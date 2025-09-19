//! This file contains all of the logic necessary to create a mutator for dumb
//! netlink message generation. This mutator wraps dumb byte buffers in metadata
//! for the fuzzing harness to dispatch to various netlink message handlers
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use super::{generate_seed, Mutator, MutatorCore};
use crate::corpus::Corpus;
use crate::LucidErr;

/// Both `lf_input` and `lf_msg` in the harness have the same metadata size
const METADATA_SIZE: usize = 8;

/// Max size of a message (total: meta + payload)
const MAX_MSG_SIZE: usize = 2048;

/// Max size of a message payload (MAX_MSG_SIZE - meta size)
const MAX_MSG_PAYLOAD_SIZE: usize = MAX_MSG_SIZE - METADATA_SIZE;

/// Max number of messages in an input
const MAX_NUM_MSGS: usize = 16;

/// % of iterations we will generate an input from scratch vs. mutate existing
const GEN_SCRATCH_RATE: usize = 1;

/// Number of valid protocol values (used as indexes in harness)
const NUM_PROTOCOLS: usize = 4;

/// Are we aligning payload lengths?
const ALIGN_ON: bool = true;

/// % of iterations where we'll align inputs
const ALIGN_RATE: usize = 99;

/// How we're aligning
const ALIGN_LEN: usize = 4;

/// How many rounds of mutation we can do in a single mutate() call
const MAX_STACK: usize = 4;

/// How many bytes in a message we can manipulate/add/delete
const BYTE_CORRUPT: usize = 32;

/// How many bits in a message we can manipulate
const BIT_CORRUPT: usize = 128;

/// Max size of an input, this is calculated in the harness as follows:
/*
#define LF_INPUT_HDR_SIZE (sizeof(u32) * 2)
#define LF_MSG_HDR_SIZE (sizeof(u32) * 2)
#define LF_TOTAL_MSG_PAYLOAD_SIZE (LF_MAX_MSG_SIZE * LF_MAX_MSGS)
#define LF_TOTAL_MSG_HDR_SIZE (LF_MSG_HDR_SIZE * LF_MAX_MSGS)
#define LF_MAX_INPUT_SIZE (LF_INPUT_HDR_SIZE + LF_TOTAL_MSG_PAYLOAD_SIZE + LF_TOTAL_MSG_HDR_SIZE)
*/
const MAX_INPUT_SIZE: usize = 32904;

/// List of all the different mutation strategies we implemented
const MUTATIONS: [MutationTypes; 4] = [
    MutationTypes::ByteInsert,
    MutationTypes::ByteOverwrite,
    MutationTypes::ByteDelete,
    MutationTypes::BitFlip,
    /* TODO:
    MagicByteInsert
    MagicByteOverwrite
    ProtocolChange
    MessageInsert
    MessageDelete
    */
];

/// Represents some of the mutation strategies that AFL++ seems to do in "Havoc"
#[derive(Clone, Debug)]
pub enum MutationTypes {
    ByteInsert,
    ByteOverwrite,
    ByteDelete,
    BitFlip,
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
    core: MutatorCore,                 // Common stuff for all mutators
    msg_bufs: [Vec<u8>; MAX_NUM_MSGS], // Pre-allocated message buffers
    netlink_input: NetlinkInput,       // Structured view for mutation
}

/// Implementation for this mutator for Mutator trait
impl Mutator for NetlinkMutator {
    /// Create new instance of structure
    fn new(seed: Option<usize>, max_size: usize) -> Self {
        // If pRNG seed not provided, make our own
        let rng = if let Some(seed_val) = seed {
            seed_val
        } else {
            generate_seed()
        };

        // Create fixed array of message bufs (heap capacity, stack metadata)
        let msg_bufs_arr: [Vec<u8>; MAX_NUM_MSGS] =
            std::array::from_fn(|_| Vec::with_capacity(MAX_MSG_PAYLOAD_SIZE));

        // Return instance
        NetlinkMutator {
            core: MutatorCore {
                rng,
                input: Vec::with_capacity(max_size),
                max_size,
                fields: Vec::new(),
            },
            msg_bufs: msg_bufs_arr,
            netlink_input: NetlinkInput::new(),
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

            // Just skip these?
            if msg_len == 0 {
                continue;
            }

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
    fn mutate(&mut self, corpus: &Corpus) -> Result<(), LucidErr> {
        // Clear the current input
        self.core.clear_input();

        // Get the number of inputs in the corpus
        let num_inputs = corpus.num_inputs();

        // Get a generate from scratch percentage
        let gen = self.rand_perc();

        // If we don't have any inputs to choose from, create random one
        if num_inputs == 0 || gen <= GEN_SCRATCH_RATE {
            self.generate_random_input()?;
            return Ok(());
        }

        // Pick a random input from the corpus
        let idx = self.rand_idx(num_inputs);

        // Get that input
        let chosen = corpus.get_input(idx).unwrap();

        // Copy that input into the input buffer
        self.copy_input(chosen);

        // Determine how many rounds of mutation we're doing
        let rounds = self.rand_one_incl(MAX_STACK);

        // For that many rounds, pick a mutation strategy and use it
        for _ in 0..rounds {
            // Get strategy index
            let strat_idx = self.rand_idx(MUTATIONS.len());

            // Match on the mutation and apply it
            match MUTATIONS[strat_idx] {
                MutationTypes::ByteInsert => {
                    self.byte_insert()?;
                }
                MutationTypes::ByteOverwrite => {
                    self.byte_overwrite()?;
                }
                MutationTypes::ByteDelete => {
                    self.byte_delete()?;
                }
                MutationTypes::BitFlip => {
                    self.bit_flip()?;
                }
            }
        }

        Ok(())
    }
}

/// These are private (mostly) mutation methods to this mutator that we use
/// in the fn mutate() function
impl NetlinkMutator {
    fn generate_random_input(&mut self) -> Result<(), LucidErr> {
        // Determine how many messages we'll use, has to be at least 1?
        let num_msgs = self.rand_one_incl(MAX_NUM_MSGS);

        // For each of those messages, generate payloads and place them in
        // a message buf slot
        let mut total_len = METADATA_SIZE;
        for i in 0..num_msgs {
            // Get message size
            let mut msg_len = self.rand_incl(MAX_MSG_PAYLOAD_SIZE);

            // Determine if we'll align
            if ALIGN_ON {
                let align = self.rand_perc();

                // If we're aligning, do that now
                if align <= ALIGN_RATE {
                    // Round up to next multiple of ALIGN_LEN
                    msg_len = (msg_len + (ALIGN_LEN - 1)) & !(ALIGN_LEN - 1);

                    // Make sure we didn't do an oopsie
                    if msg_len > MAX_MSG_PAYLOAD_SIZE {
                        msg_len = MAX_MSG_PAYLOAD_SIZE;
                    }
                }
            }

            // Clean slate the vector for the message
            self.msg_bufs[i].clear();

            // Place those bytes in the message
            for _ in 0..msg_len {
                let byte = self.rand_byte();
                self.msg_bufs[i].push(byte);
            }

            // Update length
            self.netlink_input.msg_lens[i] = msg_len as u32;

            // Pick a protocol for this message
            self.netlink_input.protocols[i] = self.rand_idx(NUM_PROTOCOLS) as u32;

            // Update total size
            total_len += msg_len; // Payload length
            total_len += METADATA_SIZE // Metadata length
        }

        // Update metadata fields
        self.netlink_input.total_len = total_len as u32;
        self.netlink_input.num_msgs = num_msgs as u32;

        // Now that everything is updated, we can serialize this input into
        // core's input buf
        self.netlink_input
            .serialize(&mut self.core.input, &self.msg_bufs)?;

        // Success
        Ok(())
    }

    /// LENGTH CHANGING: Insert bytes into message payloads randomly
    fn byte_insert(&mut self) -> Result<(), LucidErr> {
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
            return Ok(());
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

        Ok(())
    }

    /// NO_LENGTH: Overwrite bytes in message payloads randomly
    fn byte_overwrite(&mut self) -> Result<(), LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // If zero-length just bail for now
        let msg_len = self.netlink_input.msg_lens[msg_idx] as usize;
        if msg_len == 0 {
            return Ok(());
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

        Ok(())
    }

    // LENGTH_CHANGING: Delete bytes in message payloads randomly
    fn byte_delete(&mut self) -> Result<(), LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Get message length, if it's zero just bail early
        let mut msg_len = self.netlink_input.msg_lens[msg_idx] as usize;
        if msg_len == 0 {
            return Ok(());
        }

        // Determine how many bytes we can delete
        let slack = msg_len;

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

        Ok(())
    }

    /// NO_LENGTH: Flip bits in message payloads randomly
    fn bit_flip(&mut self) -> Result<(), LucidErr> {
        // Deserialize the core input buf into our data structure
        self.netlink_input
            .deserialize(&self.core.input, &mut self.msg_bufs)?;

        // Pick a message to mutate
        let msg_idx = self.rand_idx(self.netlink_input.num_msgs as usize);

        // Get message length, if zero just bail
        let msg_len = self.netlink_input.msg_lens[msg_idx] as usize;
        if msg_len == 0 {
            return Ok(());
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

        Ok(())
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
