//! This file contains all of the logic necessary to create a mutator for dumb
//! netlink message generation. This mutator wraps dumb byte buffers in metadata
//! for the fuzzing harness to dispatch to various netlink message handlers
//!
//! This mutator was designed to fuzz a harness discussed on the blog and is
//! meant to tease out what changes to Lucid were necessary to fuzz realistic
//! targets, for more information see the blogpost:
//! https://h0mbre.github.io/Lucid_Dreams_1/
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashSet, VecDeque, HashMap};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use super::{generate_seed, Mutator, MutatorCore};
use crate::corpus::Corpus;
use crate::LucidErr;

/// Both `lf_input` and `lf_msg` in the harness have the same metadata size
const METADATA_SIZE: usize = 8;

/// Max size of a message (total: meta + payload)
const MAX_MSG_SIZE: usize = 4096;

/// Max size of a message payload (MAX_MSG_SIZE - meta size)
const MAX_MSG_PAYLOAD_SIZE: usize = MAX_MSG_SIZE - METADATA_SIZE;

/// Max number of messages in an input
const MAX_NUM_MSGS: usize = 16;

/// % of iterations we will generate an input from scratch vs. mutate existing
const GEN_SCRATCH_RATE: usize = 1;

/// Number of valid protocol values (used as indexes in harness)
const NUM_PROTOCOLS: usize = 3;

/// Are we aligning payload lengths?
const ALIGN_ON: bool = true;

/// % of iterations where we'll align inputs
const ALIGN_RATE: usize = 99;

/// How we're aligning
const ALIGN_LEN: usize = 4;

/// How many rounds of mutation we can do in a single mutate() call
const MAX_STACK: usize = 7;

/// How many bytes in a message we can manipulate/add/delete
const BYTE_CORRUPT: usize = 32;

/// How many bits in a message we can manipulate
const BIT_CORRUPT: usize = 128;

/// How large of an input database we use to track unique inputs
const INPUT_DB_SIZE: usize = 500_000;

/// How often we reuse an input if it found new coverage
const REUSE_COUNT: usize = 10;

/// How often we switch to uniform selection to reset baseline in secs
const UNIFORM_SELECT_INTERVAL: u64 = 3600; // 1 Hour

/// How long we stay in uniform selection mode before switching it off
const UNIFORM_SELECT_DURATION: u64 = 1200; // 20 Mins

/// How much of the scores we *keep* when decaying
const DECAY_KEEP: f64 = 0.3;

/// Max size of an input, this is calculated in the harness as follows:
/*
#define LF_INPUT_HDR_SIZE (sizeof(u32) * 2)
#define LF_MSG_HDR_SIZE (sizeof(u32) * 2)
#define LF_TOTAL_MSG_PAYLOAD_SIZE (LF_MAX_MSG_SIZE * LF_MAX_MSGS)
#define LF_TOTAL_MSG_HDR_SIZE (LF_MSG_HDR_SIZE * LF_MAX_MSGS)
#define LF_MAX_INPUT_SIZE (LF_INPUT_HDR_SIZE + LF_TOTAL_MSG_PAYLOAD_SIZE + LF_TOTAL_MSG_HDR_SIZE)
*/
const MAX_INPUT_SIZE: usize = 65672;

/// List of all the different mutation strategies we implemented
const MUTATIONS: [MutationTypes; 13] = [
    // Operate on the individual message level
    MutationTypes::ByteInsert,
    MutationTypes::ByteOverwrite,
    MutationTypes::ByteDelete,
    MutationTypes::BitFlip,
    MutationTypes::PadMessage,
    MutationTypes::ProtocolChange,
    MutationTypes::UniProtocol,
    // Change the message layout in the input
    MutationTypes::DuplicateMessage,
    MutationTypes::ShuffleMessages,
    MutationTypes::SpliceMessage,
    // Smartish
    MutationTypes::PatchHeaderLen,
    MutationTypes::PatchHeaderType,
    MutationTypes::PatchHeaderFlags,
];

/// Represents some of the mutation strategies that AFL++ seems to do in "Havoc"
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MutationTypes {
    ByteInsert = 0,
    ByteOverwrite = 1,
    ByteDelete = 2,
    BitFlip = 3,
    PadMessage = 4,
    ProtocolChange = 5,
    UniProtocol = 6,
    DuplicateMessage = 7,
    ShuffleMessages = 8,
    SpliceMessage = 9,
    PatchHeaderLen = 10,
    PatchHeaderType = 11,
    PatchHeaderFlags = 12,
}

/// The overall input structure, some metadata followed by nested messages. This
/// corresponds to `lf_input` in the fuzzing harness
#[derive(Debug)]
struct NetlinkInput {
    total_len: u32,                 // Size of the entire input
    num_msgs: u32,                  // Number of nested messages
    protocols: [u32; MAX_NUM_MSGS], // Array repr of nested message protocols
    msg_lens: [u32; MAX_NUM_MSGS],  // Array repr of nested message lengths
}

impl NetlinkInput {
    // Create a new structure
    fn new() -> Self {
        NetlinkInput {
            total_len: 0,
            num_msgs: 0,
            protocols: [0u32; MAX_NUM_MSGS],
            msg_lens: [0u32; MAX_NUM_MSGS],
        }
    }

    // Helper to determine what size the struct would be if flattened
    fn expected_size(&self) -> usize {
        let mut size = METADATA_SIZE;

        // Iterate through the message length buffer and aggregate size
        for i in 0..self.num_msgs as usize {
            size += METADATA_SIZE + self.msg_lens[i] as usize;
        }

        size
    }

    // Turn this structure into flat bytes
    fn serialize(
        &mut self,
        dst: &mut Vec<u8>,
        msg_bufs: &[Vec<u8>; MAX_NUM_MSGS],
    ) -> Result<(), LucidErr> {
        // Clear the dst vector (core.input)
        dst.clear();

        // Make sure we pass sanity check for size
        let size = self.expected_size();
        if size > MAX_INPUT_SIZE {
            return Err(LucidErr::from(
                "NetlinkInput serialize expected size > MAX_INPUT_SIZE",
            ));
        }

        // Set the total length
        self.total_len = size as u32;

        // Copy over the metadata
        dst.extend_from_slice(&self.total_len.to_ne_bytes());
        dst.extend_from_slice(&self.num_msgs.to_ne_bytes());

        // Iterate over the messages and write them to the input buffer, this
        // weird unreadable iterator is from clippy, good lord
        for (i, buf) in msg_bufs.iter().enumerate().take(self.num_msgs as usize) {
            // Sanity check this message length
            let payload_len = self.msg_lens[i] as usize;
            if payload_len > MAX_MSG_PAYLOAD_SIZE {
                return Err(LucidErr::from("NetlinkInput serialize payload too large"));
            }

            if buf.len() != payload_len {
                return Err(LucidErr::from(
                    "NetlinkInput serialize payload length mismatch",
                ));
            }

            // Write contents over
            dst.extend_from_slice(&self.protocols[i].to_ne_bytes());
            dst.extend_from_slice(&self.msg_lens[i].to_ne_bytes());
            dst.extend_from_slice(&msg_bufs[i][..payload_len]);
        }

        // Success
        Ok(())
    }

    // Read flat byte buffer into a NetlinkInput
    fn deserialize(
        &mut self,
        src: &[u8],
        msg_bufs: &mut [Vec<u8>; MAX_NUM_MSGS],
    ) -> Result<(), LucidErr> {
        // Make sure we have enough room for metadata
        if src.len() < METADATA_SIZE {
            return Err(LucidErr::from(
                "NetlinkInput deserialize src buffer too small",
            ));
        }

        // Temp buffer we use for metadata members
        let mut tmp = [0u8; 4];

        // Extract metadata fields
        tmp.copy_from_slice(&src[0..4]);
        self.total_len = u32::from_ne_bytes(tmp);
        tmp.copy_from_slice(&src[4..8]);
        self.num_msgs = u32::from_ne_bytes(tmp);

        // Sanity check that we don't have a crazy amount of messages
        if self.num_msgs > MAX_NUM_MSGS as u32 {
            return Err(LucidErr::from(
                "NetlinkInput deserialize num_msgs > MAX_NUM_MSGS",
            ));
        }

        // Make sure it's a sane size input
        if (self.total_len as usize) > MAX_INPUT_SIZE {
            return Err(LucidErr::from(
                "NetlinkInput deserialize total_len exceeds max",
            ));
        }

        // Make sure we have enough data to read in
        if (self.total_len as usize) > src.len() {
            return Err(LucidErr::from("NetlinkInput deserialize invalid metadata"));
        }

        // Iterate through all the messages and deserialize them over, start
        // reading after metadata field
        let mut offset = METADATA_SIZE;
        for (i, dst_buf) in msg_bufs.iter_mut().enumerate().take(self.num_msgs as usize) {
            // Extract protocol for this message
            tmp.copy_from_slice(&src[offset..offset + 4]);
            self.protocols[i] = u32::from_ne_bytes(tmp);
            offset += 4;

            // Extract msg_len for this message
            tmp.copy_from_slice(&src[offset..offset + 4]);
            self.msg_lens[i] = u32::from_ne_bytes(tmp);
            let msg_len = self.msg_lens[i] as usize;
            offset += 4;

            // Make sure we don't have some insane value now
            if msg_len > MAX_MSG_PAYLOAD_SIZE {
                return Err(LucidErr::from(
                    "NetlinkInput deserialize message payload too big",
                ));
            }

            // Make sure we have enough remaining room to read from
            if offset + msg_len > src.len() {
                return Err(LucidErr::from("NetlinkInput deserialize invalid msg_len"));
            }

            // Clear the buf
            dst_buf.clear();

            // Copy the bytes over
            dst_buf.extend_from_slice(&src[offset..offset + msg_len]);

            // Update offset
            offset += msg_len;
        }

        // Sanity check total_len
        if (offset as u32) != self.total_len {
            return Err(LucidErr::from(
                "NetlinkInput deserialize total_len mismatch",
            ));
        }

        // Success
        Ok(())
    }
}

/// Netlink mutator structure
pub struct NetlinkMutator {
    core: MutatorCore,                      // Common stuff for all mutators
    msg_bufs: [Vec<u8>; MAX_NUM_MSGS],      // Pre-allocated message buffers
    netlink_input: NetlinkInput,            // Structured view for mutation
    scratch_msgs: [Vec<u8>; MAX_NUM_MSGS],  // Used for mutations for zero alloc
    recent_inputs: HashSet<u64>,            // Set of hashes for inputs
    recent_order: VecDeque<u64>,            // Order of the hashes inserted in DB
    reuse_remaining: usize,                 // Number of reuse attempts left
    strats_vec: Vec<MutationTypes>,         // Strats used last mutation
    total_score: usize,                     // Total score 
    last_switch: Instant,                   // When we mode switched
    uniform_mode: bool,                     // Whether or not we're in uniform
    strat_scores: HashMap<MutationTypes, usize>,    // Score database for strats
}

/// Implementation for this mutator for Mutator trait
impl Mutator for NetlinkMutator {
    /// Create new instance of structure
    fn new(seed: Option<usize>, max_size: usize) -> Self {
        // Janky but I don't use this mutator anymore and I just noticed this footgun
        assert!(max_size == MAX_INPUT_SIZE);

        // If pRNG seed not provided, make our own
        let rng = if let Some(seed_val) = seed {
            seed_val
        } else {
            generate_seed()
        };

        // Create fixed array of message bufs (heap capacity, stack metadata)
        let msg_bufs_arr: [Vec<u8>; MAX_NUM_MSGS] =
            std::array::from_fn(|_| Vec::with_capacity(MAX_MSG_PAYLOAD_SIZE));

        let scratch_msgs_arr: [Vec<u8>; MAX_NUM_MSGS] =
            std::array::from_fn(|_| Vec::with_capacity(MAX_MSG_PAYLOAD_SIZE));

        // Return instance
        NetlinkMutator {
            core: MutatorCore {
                rng,
                input: Vec::with_capacity(max_size),
                max_size,
                fields: Vec::new(),
                last_input: None,
                new_cov: false,
            },
            msg_bufs: msg_bufs_arr,
            netlink_input: NetlinkInput::new(),
            scratch_msgs: scratch_msgs_arr,
            recent_inputs: HashSet::with_capacity(INPUT_DB_SIZE),
            recent_order: VecDeque::with_capacity(INPUT_DB_SIZE),
            reuse_remaining: 0,
            strats_vec: Vec::with_capacity(MUTATIONS.len()),
            
            // Every strat gets init as 1, so just take the total of that
            total_score: MUTATIONS.len(),
            last_switch: Instant::now(),

            // Start in uniform mode
            uniform_mode: true,

            // Initialize all to 1 so that all can be selected sometimes
            strat_scores: MUTATIONS.iter().map(|&m| (m, 1)).collect(),
        }
    }

    /// Enables the default implementations
    fn core(&self) -> &MutatorCore {
        &self.core
    }

    /// Enables the default implementations
    fn core_mut(&mut self) -> &mut MutatorCore {
        &mut self.core
    }

    /// Breaks the current input into fields for Redqueen to manipulate, for
    /// this mutator, we'll want to pass the message payloads over to Redqueen.
    /// So iterate through the messages and create cloned copies of the payloads
    fn extract_redqueen_fields(&mut self) {
        // Fresh slate
        self.core.fields.clear();

        // Iterate through all of the messages we have and add them to the fields
        for i in 0..self.netlink_input.num_msgs as usize {
            // Get this message's payload length
            let msg_len = self.netlink_input.msg_lens[i] as usize;

            // Clone the payload so it becomes an owned vec for fields
            let payload = self.msg_bufs[i][..msg_len].to_vec();

            // Push it into the Redqueen fields vector
            self.core.fields.push(payload);
        }
    }

    /// Re-assembles the core's input buffer from its current field values, the
    /// fields can be different than what we sent over and we need to make
    /// sense of it at the input level
    fn reassemble_redqueen_fields(&mut self) -> Result<(), LucidErr> {
        // Fields correspond to the pre-allocated message payload buffers, so
        // first thing we have to do is copy the fields back into their respective
        // buffers
        for (i, field) in self.core.fields.iter().enumerate() {
            // Figure out where it's going
            let dst_buf = &mut self.msg_bufs[i];

            // Clear the destination buf
            dst_buf.clear();

            // Copy the potentially new field data over
            dst_buf.extend_from_slice(field);
        }

        // With fields now copied over to the msg_bufs, we can create a new
        // input with serialization
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        // Success
        Ok(())
    }

    /// Main mutation logic for this mutator
    fn mutate(&mut self, corpus: &mut Corpus) -> Result<(), LucidErr> {
        // Load the base-input for mutation
        self.load_base_input(corpus)?;

        // Score the strategies we used last time
        self.score_strats();

        // Apply mutation strategies based on mode
        if self.uniform_mode {
            self.uniform_mutations(corpus)?;
        }

        // Weighted selection
        else {
            self.weighted_mutations(corpus)?;
        }

        // Check to see if we should reset selection mode
        self.check_mode();

        Ok(())
    }
}

/// These are private (mostly) mutation methods to this mutator that we use
/// in the fn mutate() function
impl NetlinkMutator {
    // Re-use the last base-input we picked because it achieved new coverage
    fn reuse_last(&mut self, corpus: &mut Corpus) {
        // Grab the index
        let idx = self.core.last_input.unwrap();

        // Grab that input
        let chosen = corpus.get_input_by_idx(idx);

        // Copy the input over
        self.copy_input(chosen.unwrap());
    }

    // Select mutation strategies uniformly
    fn uniform_mutations(&mut self, corpus: &mut Corpus) -> Result<(), LucidErr> {
        // Clear the strats vector
        self.strats_vec.clear();

        // Determine how many rounds of mutation we're doing
        let mut rounds = self.rand_one_incl(MAX_STACK);

        // For that many rounds, pick a mutation strategy and use it
        while rounds > 0 {
            // Get strategy index
            let strat_idx = self.rand_idx(MUTATIONS.len());

            // Get strat for vector stash
            let strat = MUTATIONS[strat_idx];

            // Match on the mutation and apply it
            let success = match MUTATIONS[strat_idx] {
                MutationTypes::ByteInsert => self.byte_insert()?,
                MutationTypes::ByteOverwrite => self.byte_overwrite()?,
                MutationTypes::ByteDelete => self.byte_delete()?,
                MutationTypes::BitFlip => self.bit_flip()?,
                MutationTypes::PadMessage => self.pad_message()?,
                MutationTypes::ProtocolChange => self.protocol_change()?,
                MutationTypes::UniProtocol => self.uni_protocol()?,
                MutationTypes::DuplicateMessage => self.duplicate_message()?,
                MutationTypes::ShuffleMessages => self.shuffle_messages()?,
                MutationTypes::SpliceMessage => self.splice_message(corpus)?,
                MutationTypes::PatchHeaderLen => self.patch_nlmsghdr_len()?,
                MutationTypes::PatchHeaderType => self.patch_nlmsghdr_type()?,
                MutationTypes::PatchHeaderFlags => self.patch_nlmsghdr_flags()?,
            };

            // Failed to apply mutation, try again
            if !success {
                continue;
            }

            // Record the strat deduped, success guaranteed here
            if !self.strats_vec.contains(&strat) {
                self.strats_vec.push(strat);
            }

            // Successfully applied mutation, check if last round is done, if so
            // hash the input and make sure it's not in the DB
            rounds -= 1;
            if rounds == 0 {
                // Hash the input
                let hash = self.hash_input();

                // Check if we've seen it
                if !self.recent_inputs.contains(&hash) {
                    self.insert_recent(hash);
                }
                // We have seen this before, add another mutation round
                else {
                    rounds += 1;
                }
            }
        }

        Ok(())
    }

    // Pick mutation strategies based on historical scoring data
    fn weighted_mutations(&mut self, corpus: &mut Corpus) -> Result<(), LucidErr> {
        // Clear the strats vector
        self.strats_vec.clear();

        // Determine how many rounds of mutation we're doing
        let mut rounds = self.rand_one_incl(MAX_STACK);

        // Flatten the score database out deterministically:
        // 1 - depends on hashmap key entry order which we freeze at ::New()
        // 2 - sort_by_key is deterministic then based on map key order
        // 3 - from_fn knows the array length at compile time
        // 4 - iterates through each index and calls a callback that we 
        //     defined in the closure
        let mut sorted: [(MutationTypes, usize); MUTATIONS.len()] =
            std::array::from_fn(|i| {
                let m = MUTATIONS[i];
                let score = *self.strat_scores.get(&m).unwrap_or(&1);
                (m, score)
            });

        // Sort it in place by the score, and make it descending w Reverse
        sorted.sort_by_key(|(_, score)| std::cmp::Reverse(*score)); 

        // For that many rounds, pick a mutation strategy and use it
        while rounds > 0 {
            // Select a strategy based on weights
            let strat = self.pick_weighted_strat(&sorted);

            // Apply mutation
            let success = match strat {
                MutationTypes::ByteInsert => self.byte_insert()?,
                MutationTypes::ByteOverwrite => self.byte_overwrite()?,
                MutationTypes::ByteDelete => self.byte_delete()?,
                MutationTypes::BitFlip => self.bit_flip()?,
                MutationTypes::PadMessage => self.pad_message()?,
                MutationTypes::ProtocolChange => self.protocol_change()?,
                MutationTypes::UniProtocol => self.uni_protocol()?,
                MutationTypes::DuplicateMessage => self.duplicate_message()?,
                MutationTypes::ShuffleMessages => self.shuffle_messages()?,
                MutationTypes::SpliceMessage => self.splice_message(corpus)?,
                MutationTypes::PatchHeaderLen => self.patch_nlmsghdr_len()?,
                MutationTypes::PatchHeaderType => self.patch_nlmsghdr_type()?,
                MutationTypes::PatchHeaderFlags => self.patch_nlmsghdr_flags()?,
            };

            // Failed to apply mutation, try again
            if !success {
                continue;
            }

            // Record the strat deduped
            if !self.strats_vec.contains(&strat) {
                self.strats_vec.push(strat);
            }

            // Successfully applied mutation
            rounds -= 1;
            if rounds == 0 {
                // Hash the input
                let hash = self.hash_input();

                // Check if we've seen it before
                if !self.recent_inputs.contains(&hash) {
                    self.insert_recent(hash);
                } else {
                    // We've seen this before, add another mutation round
                    rounds += 1;
                }
            }
        }

        Ok(())
    }

    // Pick a strategy according to database scores where each score is a fraction
    // of the total_score. So we pick a number between 1 - total_score and 
    // then see what bucket that fell into and then pick that strat
    fn pick_weighted_strat(&mut self, sorted: &[(MutationTypes, usize)])
        -> MutationTypes {
        // Should always have scores as we start in uniform mode
        assert!(self.total_score > 0);
    
        // Pick a random choice within the total_score 
        let roll = self.rand_one_incl(self.total_score);
        let mut acc = 0;
    
        // Traverse in order and pick based on cumulative score
        for (strat, score) in sorted.iter() {
            acc += *score;
            if roll <= acc {
                return *strat;
            }
        }

        // I think this is unreachable?
        unreachable!();
    }

    // Load a base-input into the input buffer in core
    fn load_base_input(&mut self, corpus: &mut Corpus) -> Result<(), LucidErr> {
        // Clear the current input
        self.clear_input();

        // Short circuit if the last input got new coverage, re-use it
        if self.new_coverage() {
            // Found new coverage, reset the reuse counter
            self.reuse_remaining = REUSE_COUNT;
        }

        // We have reuse attempts remaining to reuse the last input, reuse input
        // and then decrement budget
        if self.reuse_remaining > 0 {
            self.reuse_last(corpus);
            self.reuse_remaining -= 1;
        }

        // Last input didn't lead to new coverage
        else {
            // Get the number of inputs in the corpus
            let num_inputs = corpus.num_inputs();

            // Get a generate from scratch percentage
            let gen = self.rand_perc();

            // If we don't have any inputs to choose from, create random one
            if num_inputs == 0 || gen <= GEN_SCRATCH_RATE {
                self.generate_random_input()?;
                return Ok(());
            }

            // Pick a random input from the corpus, bias towards new inputs, can
            // unwrap here because we checked above that we have > 1 inputs
            let (idx, chosen) = corpus.get_input_bias_new(self.get_rng());

            // Set this as the last used base input
            self.core.last_input = Some(idx);

            // Copy that input into the input buffer
            self.copy_input(chosen.unwrap());
        }

        // Success
        Ok(())
    }

    // Score the strategies from the last mutation 
    fn score_strats(&mut self) {
        // No new coverage, return early no one gets credit
        if !self.new_coverage() {
            return;
        }

        // Only score in uniform mode for now
        if !self.uniform_mode {
            return;
        }

        // Got new coverage, update scores
        for strat in &self.strats_vec {
            *self.strat_scores.entry(*strat).or_insert(1) += 1;
            self.total_score += 1;
        }
    }

    // Decay the scores so that we can have new baselines be effective
    fn decay_scores(&mut self) {
        // Iterate through all the scores, keep the constant defined amount
        // but make sure its always at least 1
        for score in self.strat_scores.values_mut() {
            *score = (*score as f64 * DECAY_KEEP).round() as usize;
            if *score == 0 {
                *score = 1;
            }
        }

        // Recalc the total score now
        self.total_score = self.strat_scores.values().sum();
    }

    // Check whether or not we should change modes
    fn check_mode(&mut self) {
        // Calc elapsed time
        let elapsed = self.last_switch.elapsed();

        // Get uniform mode
        let uniform = self.uniform_mode;

        // Calculate the threshold we're dealing with, could be time we've 
        // been in uniform mode or time since last uniform mode switch
        let threshold = if uniform {
            Duration::from_secs(UNIFORM_SELECT_DURATION)
        } else {
            Duration::from_secs(UNIFORM_SELECT_INTERVAL)
        };

        // Check if threshold met in uniform mode and turn it off
        if uniform && elapsed > threshold {
            self.uniform_mode = false;
            self.last_switch = Instant::now();
        }

        // Check if we need to switch to uniform mode
        else if !uniform && elapsed > threshold {
            self.uniform_mode = true;
            self.last_switch = Instant::now();

            // Decay the scores in the database
            self.decay_scores();
        }
    }

    fn generate_random_input(&mut self) -> Result<(), LucidErr> {
        // Constants for us to use for netlink message stuff
        const NLMSGHDR_SIZE: usize = 16; // Size of nlmsghdr
        const NLATTR_MAX: usize = 32; // Arbitrary limit I picked
        const NLATTRHDR_SIZE: usize = 4; // Size of nlattr
        const NLATTR_ALIGN: usize = 4; // Alignment of the payloads
        const NLATTR_PAYLOAD_MAX: usize = 128; // Arbitrary limit I picked

        // Determine how many messages we'll use, has to be at least 1?
        let num_msgs = self.rand_one_incl(MAX_NUM_MSGS);

        // For each of those messages, generate payloads and place them in
        // a message buf slot
        for i in 0..num_msgs {
            // Clear that message buffer
            self.msg_bufs[i].clear();

            // Zero out the nlmsghdr
            for _ in 0..NLMSGHDR_SIZE {
                self.msg_bufs[i].push(0);
            }

            // Generate random values for the header members
            let msg_type = self.rand() as u16;
            let flags = self.rand() as u16;
            let seq = self.rand() as u32;
            let pid = self.rand() as u32;

            // Write header fields, save length update to the very end
            self.msg_bufs[i][4..6].copy_from_slice(&msg_type.to_le_bytes());
            self.msg_bufs[i][6..8].copy_from_slice(&flags.to_le_bytes());
            self.msg_bufs[i][8..12].copy_from_slice(&seq.to_le_bytes());
            self.msg_bufs[i][12..16].copy_from_slice(&pid.to_le_bytes());

            // Track how many more bytes we have
            let mut remaining = MAX_MSG_PAYLOAD_SIZE - NLMSGHDR_SIZE;

            // Pick a number of netlink attributes to use
            let num_attrs = self.rand_one_incl(NLATTR_MAX);

            // For each nlattr attempt to create the nlattr and its payload
            for _ in 0..num_attrs {
                // Make sure we have enough for at least header
                if remaining <= NLATTRHDR_SIZE {
                    break;
                }

                // Pre-remove remaining
                remaining -= NLATTRHDR_SIZE;

                // Pick length of this nlattr payload
                let mut payload_len = self.rand_incl(NLATTR_PAYLOAD_MAX / NLATTR_ALIGN);

                // Always aligned now
                payload_len *= NLATTR_ALIGN;

                // If we don't have enough room for this payload, just quit
                if payload_len > remaining {
                    payload_len = 0;
                }

                // Put the nlattr struct together now
                let nla_len = NLATTRHDR_SIZE + payload_len;
                let nla_type = self.rand() as u16;
                self.msg_bufs[i].extend_from_slice(&nla_len.to_le_bytes());
                self.msg_bufs[i].extend_from_slice(&nla_type.to_le_bytes());

                // Fill in the random payload
                for _ in 0..payload_len {
                    let byte = self.rand_byte();
                    self.msg_bufs[i].push(byte);
                }

                // Update remaining
                remaining -= payload_len;
            }

            // Now we can go back and patch up the nlmsghdr length
            let msg_len = self.msg_bufs[i].len() as u32;
            self.msg_bufs[i][0..4].copy_from_slice(&msg_len.to_le_bytes());

            // Update length
            self.netlink_input.msg_lens[i] = msg_len;

            // Pick a protocol for this message
            self.netlink_input.protocols[i] = self.rand_idx(NUM_PROTOCOLS) as u32;
        }

        // Update num_msgs metadata field
        self.netlink_input.num_msgs = num_msgs as u32;

        // Now that everything is updated, we can serialize this input into
        // core's input buf
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        // Success
        Ok(())
    }

    /// Hash the current input in the buffer
    fn hash_input(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.core.input.hash(&mut hasher);
        hasher.finish()
    }

    /// Insert current input into our database bookkeeping
    fn insert_recent(&mut self, hash: u64) {
        if self.recent_inputs.contains(&hash) {
            return;
        }
        if self.recent_order.len() >= INPUT_DB_SIZE {
            if let Some(old) = self.recent_order.pop_front() {
                self.recent_inputs.remove(&old);
            }
        }
        self.recent_inputs.insert(hash);
        self.recent_order.push_back(hash);
    }

    /// LENGTH_CHANGE: Insert bytes into message payloads randomly
    fn byte_insert(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Get that message's length
        let mut msg_len = self.netlink_input.msg_lens[msg_idx] as usize;

        // Determine how many bytes we can insert
        let slack = MAX_MSG_PAYLOAD_SIZE - msg_len;

        // Pick the largest ceiling we can
        let ceiling = std::cmp::min(slack, BYTE_CORRUPT);

        // If ceiling is zero, bail early
        if ceiling == 0 {
            return Ok(false);
        }

        // Determine how many bytes we're going to insert now
        let insert_num = self.rand_one_incl(ceiling);

        // Optionally align this amount
        let aligned_up = self.rand_align_up(msg_len + insert_num);

        // Re-capture insert_num now that it's been potentially aligned up
        let insert_num = aligned_up - msg_len;

        // Determine whether or not this will be contiguous or random indexes
        let contig = self.rand_bool();

        // Not contiguous, insert at random indexes each time
        if !contig {
            for _ in 0..insert_num {
                // Pick random index
                let idx = self.rand_incl(msg_len);

                // Pick byte to insert
                let byte = self.rand_byte();

                // Do the insertion
                self.msg_bufs[msg_idx].insert(idx, byte);

                // Increase length
                msg_len += 1;
            }
        }
        // Contiguous, single index the entire time
        else {
            // Pick single index
            let idx = self.rand_incl(msg_len);

            // Insert bytes at that index
            for _ in 0..insert_num {
                // Pick byte
                let byte = self.rand_byte();

                // Do the insertion
                self.msg_bufs[msg_idx].insert(idx, byte);
            }

            // Increase the length
            msg_len += insert_num;
        }

        // Update metadata, serialize will fix up total_len
        self.netlink_input.msg_lens[msg_idx] = msg_len as u32;

        // Serialize back into the input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Overwrite bytes in message payloads randomly
    fn byte_overwrite(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // If zero-length just bail for now
        let msg_len = self.netlink_input.msg_lens[msg_idx] as usize;
        if msg_len == 0 {
            return Ok(false);
        }

        // Pick ceiling for number of bytes to mutate
        let ceiling = std::cmp::min(msg_len, BYTE_CORRUPT);

        // Pick number of bytes to mutate
        let num_mutate = self.rand_one_incl(ceiling);

        // For that many bytes, overwrite with random byte
        for _ in 0..num_mutate {
            // Pick mutate index, picking same one over and over is fine
            let byte_idx = self.rand_idx(msg_len);

            // Pick byte to use
            let byte = self.rand_byte();

            // Do the write
            self.msg_bufs[msg_idx][byte_idx] = byte;
        }

        // Serialize input back into buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    // LENGTH_CHANGING: Delete bytes in message payloads randomly
    fn byte_delete(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Get message length, if it's zero just bail early
        let mut msg_len = self.netlink_input.msg_lens[msg_idx] as usize;
        if msg_len == 0 || msg_len == 1 {
            return Ok(false);
        }

        // Determine how many bytes we can delete, always leave 1
        let slack = msg_len - 1;

        // Pick the largest ceiling we can
        let ceiling = std::cmp::min(slack, BYTE_CORRUPT);

        // Determine how many bytes to delete
        let del_num = self.rand_one_incl(ceiling);

        // Optionally align this amount
        let aligned_down = self.rand_align_down(msg_len - del_num);

        // Re-capture del_num now that it's been potentially aligned down. This
        // could make it such that the del num is now greater than BYTE_CORRUPT
        // but we don't really care because itll be at most BYTE_CORRUPT + ALIGN
        let del_num = msg_len - aligned_down;

        // Determine whether or not this will be contiguous or random indexes
        let contig = self.rand_bool();

        // Not contiguous, del at random indexes each time
        if !contig {
            for _ in 0..del_num {
                // Pick random index
                let idx = self.rand_idx(msg_len);

                // Do the delete
                self.msg_bufs[msg_idx].remove(idx);

                // Decrease length
                msg_len -= 1;
            }
        }
        // Contiguous, single index the entire time
        else {
            // Pick single index
            let mut idx = self.rand_idx(msg_len);

            // Make sure it won't end up out of bounds
            if idx + del_num > msg_len {
                idx = msg_len - del_num;
            }

            // Del bytes at that index
            for _ in 0..del_num {
                // Do the deletion
                self.msg_bufs[msg_idx].remove(idx);
            }

            // Decrease the length
            msg_len -= del_num;
        }

        // Update metadata, serialize will fix up total_len
        self.netlink_input.msg_lens[msg_idx] = msg_len as u32;

        // Serialize back into the input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// LENGTH_CHANGE: Pad the message out with a random amount of data
    fn pad_message(&mut self) -> Result<bool, LucidErr> {
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);
        let msg_len = self.netlink_input.msg_lens[msg_idx] as usize;

        // Can't extend, bail
        if msg_len == MAX_MSG_PAYLOAD_SIZE {
            return Ok(false);
        }

        // Choose addition length
        let mut add_len = self.rand_incl(MAX_MSG_PAYLOAD_SIZE - msg_len) + msg_len;

        // Optionally align up
        add_len = self.rand_align_up(add_len);

        // Make sure we didn't do an oopsie
        if add_len > MAX_MSG_PAYLOAD_SIZE {
            add_len = MAX_MSG_PAYLOAD_SIZE;
        }

        // Determine if same byte value or random
        let fixed = self.rand_bool();
        let mut byte = self.rand_byte();

        // Extend buffer with bytes
        while self.msg_bufs[msg_idx].len() < add_len {
            if !fixed {
                byte = self.rand_byte();
            }
            self.msg_bufs[msg_idx].push(byte);
        }
        self.netlink_input.msg_lens[msg_idx] = add_len as u32;

        // Re-serialize
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Flip bits in message payloads randomly
    fn bit_flip(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Get message length, if zero just bail
        let msg_len = self.netlink_input.msg_lens[msg_idx] as usize;
        if msg_len == 0 {
            return Ok(false);
        }

        // Ceiling for number of bits we can flip
        let ceiling = std::cmp::min(msg_len * 8, BIT_CORRUPT);

        // Pick number of bits to flip
        let num_flips = self.rand_one_incl(ceiling);

        // Perform bit flips
        for _ in 0..num_flips {
            // Pick a random byte index
            let byte_idx = self.rand_idx(msg_len);

            // Pick a random bit index in 0..7
            let bit_idx = self.rand_idx(8);

            // Flip the bit
            self.msg_bufs[msg_idx][byte_idx] ^= 1 << bit_idx;
        }

        // Serialize back into input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Change the protocol of random messages
    fn protocol_change(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Get current protocol
        let curr_protocol = self.netlink_input.protocols[msg_idx];

        // Pick a new protocol that differs
        let mut new_protocol = curr_protocol;
        while new_protocol == curr_protocol {
            new_protocol = self.rand_idx(NUM_PROTOCOLS) as u32;
        }

        // Write it back
        self.netlink_input.protocols[msg_idx] = new_protocol;

        // Re-serialize into the input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Make every message the same protocol
    fn uni_protocol(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // If we only have one message, just bail
        if self.netlink_input.num_msgs < 2 {
            return Ok(false);
        }

        // Get the protocol of the first message
        let protocol = self.netlink_input.protocols[0];

        // For all the messages, set the protocol
        for i in 0..self.netlink_input.num_msgs as usize {
            self.netlink_input.protocols[i] = protocol;
        }

        // Re-serialize into the input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    // LENGTH_CHANGING: Randomly duplicate a message in the input
    fn duplicate_message(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to copy
        let src_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Determine where we can copy it to
        let mut ceiling = self.netlink_input.num_msgs as usize;

        // If we have less than the max number of messages, make sure we can
        // also just append the new message
        if (self.netlink_input.num_msgs as usize) < MAX_NUM_MSGS {
            ceiling += 1;
        }

        // Pick a message slot to overwrite/append, no NOPs
        let mut dst_idx = self.rand_idx(ceiling);
        while dst_idx == src_idx {
            dst_idx = self.rand_idx(ceiling);
        }

        // Determine if we're appending
        let append = dst_idx == self.netlink_input.num_msgs as usize;

        // Copy source to the scratch message
        self.scratch_msgs[0].clear();
        self.scratch_msgs[0].extend_from_slice(&self.msg_bufs[src_idx]);

        // Copy the scratch to the dst
        self.msg_bufs[dst_idx].clear();
        self.msg_bufs[dst_idx].extend_from_slice(&self.scratch_msgs[0]);

        // Update the metadata
        self.netlink_input.protocols[dst_idx] = self.netlink_input.protocols[src_idx];

        // Update the lengths
        self.netlink_input.msg_lens[dst_idx] = self.netlink_input.msg_lens[src_idx];

        // If we appended, add new message count
        if append {
            self.netlink_input.num_msgs += 1;
        }

        // Re-serialize into the input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Shuffle the order of the messages
    fn shuffle_messages(&mut self) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        let num_msgs = self.netlink_input.num_msgs as usize;

        // If we only have one message or max messages, just bail
        if num_msgs == 1 || num_msgs == MAX_NUM_MSGS {
            return Ok(false);
        }

        // Where we keep the new order
        let mut new_order = [0usize; MAX_NUM_MSGS];
        for (i, slot) in new_order.iter_mut().take(num_msgs).enumerate() {
            *slot = i;
        }

        // Shuffe the indices
        for i in (1..num_msgs).rev() {
            let j = self.rand_idx(i + 1);
            new_order.swap(i, j);
        }

        // New metadata
        let mut new_protocols = [0u32; MAX_NUM_MSGS];
        let mut new_lens = [0u32; MAX_NUM_MSGS];

        // Iterate through the new order and copy all of those over
        for i in 0..num_msgs {
            // Calc src_idx
            let src_idx = new_order[i];

            // Get src and dst
            let src = &self.msg_bufs[src_idx];
            let dst = &mut self.scratch_msgs[i];

            // Clear dst
            dst.clear();

            // Copy it over
            dst.extend_from_slice(src);

            // Update metadata
            new_protocols[i] = self.netlink_input.protocols[src_idx];
            new_lens[i] = self.netlink_input.msg_lens[src_idx];
        }

        // Now place the messages back in the shuffled order
        for i in 0..num_msgs {
            let dst = &mut self.msg_bufs[i];
            dst.clear();
            dst.extend_from_slice(&self.scratch_msgs[i]);

            self.netlink_input.protocols[i] = new_protocols[i];
            self.netlink_input.msg_lens[i] = new_lens[i];
        }

        // Re-serialize into the input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// LENGTH_CHANGE: Splice a message in from another input
    fn splice_message(&mut self, corpus: &mut Corpus) -> Result<bool, LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // If we only have one input in the corpus, bail
        if corpus.num_inputs() < 2 {
            return Ok(false);
        }

        // Get the donor message
        let donor_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Save it off
        self.scratch_msgs[0].clear();
        self.scratch_msgs[0].extend_from_slice(&self.msg_bufs[donor_idx]);

        // Save metadata
        let donor_len = self.netlink_input.msg_lens[donor_idx];
        let donor_protocol = self.netlink_input.protocols[donor_idx];

        // Get a recipient input
        let (_, recipient) = corpus.get_input_bias_new(self.get_rng());
        self.copy_input(recipient.unwrap());

        // Deserialize it
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Determine where to place, make append possible
        let mut ceiling = self.netlink_input.num_msgs as usize;
        if (self.netlink_input.num_msgs as usize) < MAX_NUM_MSGS {
            ceiling += 1;
        }

        let target_idx = self.rand_idx(ceiling);

        // Place the input there
        self.msg_bufs[target_idx].clear();
        self.msg_bufs[target_idx].extend_from_slice(&self.scratch_msgs[0]);
        self.netlink_input.msg_lens[target_idx] = donor_len;
        self.netlink_input.protocols[target_idx] = donor_protocol;

        // Determine if we added a new input (append)
        if self.netlink_input.num_msgs as usize == target_idx {
            self.netlink_input.num_msgs += 1;
        }

        // Re-serialize into the input buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Patches the nlmsg_hdr->len field to be correct
    fn patch_nlmsghdr_len(&mut self) -> Result<bool, LucidErr> {
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Iterate through each message in our input
        for i in 0..self.netlink_input.num_msgs as usize {
            let len = self.netlink_input.msg_lens[i];

            // If we have at least enough bytes to hold the length, patch it
            if self.msg_bufs[i].len() >= 4 {
                self.msg_bufs[i][0..4].copy_from_slice(&len.to_ne_bytes());
            }
        }

        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Patches the nlmsg_hdr->type field to be somewhat in range
    fn patch_nlmsghdr_type(&mut self) -> Result<bool, LucidErr> {
        // Deserialize current input into structured representation
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Get number of messages
        let num_msgs = self.netlink_input.num_msgs as usize;

        // This protocol order has to match the harness for lf_protocols
        const MAX_NLMSG_TYPES: [u32; 4] = [
            123,  // NETLINK_ROUTE
            40,   // NETLINK_XFRM
            3089, // NETLINK_NETFILTER (nf_tables: (10 << 8) | 255)
            20,   // NETLINK_CRYPTO
        ];

        // Iterate through each message and if theres room, update type
        for i in 0..num_msgs {
            let proto_idx = self.netlink_input.protocols[i] as usize;

            if proto_idx < MAX_NLMSG_TYPES.len() && self.msg_bufs[i].len() >= 6 {
                // Generate a new nlmsg_type under the ceiling
                let new_type = self.rand_idx(MAX_NLMSG_TYPES[proto_idx] as usize) as u16;

                // Overwrite nlmsg_type at offset 4
                self.msg_bufs[i][4..6].copy_from_slice(&new_type.to_le_bytes());
            }
        }

        // Re-serialize back into the flat buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// NO_LENGTH: Patches the nlmsg_hdr->flags field with somewhat valid vals
    fn patch_nlmsghdr_flags(&mut self) -> Result<bool, LucidErr> {
        // Deserialize current input into structured representation
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Netlink message flag values, thanks ChagGPT, Grok, Claude
        const FLAGS: [u16; 14] = [
            0x0001, // NLM_F_REQUEST
            0x0002, // NLM_F_MULTI
            0x0004, // NLM_F_ACK
            0x0008, // NLM_F_ECHO
            0x0010, // NLM_F_ROOT
            0x0020, // NLM_F_MATCH
            0x0040, // NLM_F_ATOMIC
            0x0080, // NLM_F_CREATE
            0x0100, // NLM_F_DUMP
            0x0200, // NLM_F_DUMP_FILTERED
            0x0400, // NLM_F_APPEND
            0x0800, // NLM_F_NONREC
            0x1000, // NLM_F_BULK
            0xFFFF, // chaos combo
        ];

        // Iterate through each message and patch the flag values
        for i in 0..self.netlink_input.num_msgs as usize {
            // If we don't have the length, just continue
            if self.msg_bufs[i].len() < 8 {
                continue;
            }

            // Get the current flag value
            let mut curr = u16::from_le_bytes([self.msg_bufs[i][6], self.msg_bufs[i][7]]);

            // Randomly nuke it 50% of the time
            if self.rand_bool() {
                curr = 0;
            }

            // Roll up to 8 times
            let num_rolls = self.rand_one_incl(8);

            // For the number of rolls, do random OR'ing
            for _ in 0..num_rolls {
                curr |= FLAGS[self.rand_idx(FLAGS.len())];
            }

            // Patch that in
            self.msg_bufs[i][6..8].copy_from_slice(&curr.to_le_bytes());
        }

        // Re-serialize back into the flat buffer
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        Ok(true)
    }

    /// Generate a random value based on max, not inclusive
    fn rand_idx(&mut self, max: usize) -> usize {
        self.rand() % max
    }

    /// Generate a random byte in 0..=255
    fn rand_byte(&mut self) -> u8 {
        (self.rand() % 256) as u8
    }

    /// Generate a random usize in 0..=max (inclusive upper bound)
    fn rand_incl(&mut self, max: usize) -> usize {
        self.rand() % (max + 1)
    }

    /// Generate a random usize in 1..=max (at least 1, inclusive upper bound)
    fn rand_one_incl(&mut self, max: usize) -> usize {
        (self.rand() % max) + 1
    }

    /// Generate a random percentage
    fn rand_perc(&mut self) -> usize {
        (self.rand() % 100) + 1
    }

    /// Generate a random boolean
    fn rand_bool(&mut self) -> bool {
        self.rand() % 2 == 1
    }

    /// With probability ALIGN_RATE, round length up to nearest multiple of ALIGN_LEN.
    fn rand_align_up(&mut self, len: usize) -> usize {
        if !ALIGN_ON {
            return len;
        }

        // Random chance to still be unaligned
        let align = self.rand_perc();
        if align <= ALIGN_RATE {
            let mut aligned = (len + (ALIGN_LEN - 1)) & !(ALIGN_LEN - 1);
            if aligned > MAX_MSG_PAYLOAD_SIZE {
                aligned = MAX_MSG_PAYLOAD_SIZE;
            }
            aligned
        } else {
            len
        }
    }

    /// With probability ALIGN_RATE, round length down to nearest multiple of ALIGN_LEN.
    fn rand_align_down(&mut self, len: usize) -> usize {
        if !ALIGN_ON {
            return len;
        }

        // Random chance to still be unaligned
        let align = self.rand_perc();
        if align <= ALIGN_RATE {
            (len / ALIGN_LEN) * ALIGN_LEN
        } else {
            len
        }
    }
}
