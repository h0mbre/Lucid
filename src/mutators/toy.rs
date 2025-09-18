//! This file contains all of the logic necessary for a toy mutator implementation.
//! This mutator just does basic dumb mutations on a single raw byte buffer.
//!
//! This is inspired by: https://github.com/gamozolabs/basic_mutator, which in
//! turn is inspired by Hongfuzz. We don't use any of the Hongfuzz derived code
//! in here, just trying to implement our own stuff that tries to mirror what
//! AFL++ does. Eventually we'll try to just use LibAFL's mutator?
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use super::{generate_seed, Mutator, MutatorCore};
use crate::corpus::Corpus;
use crate::LucidErr;

/// Input alignment enforcement
const ALIGN: bool = true;

/// Input alignment length
const ALIGN_LEN: usize = 4;

/// Input alignment frequency
const ALIGN_RATE: usize = 95;

/// The maximum amount of mutation rounds we can apply to an input, I *think*
/// this is what AFL++ does?
const MAX_STACK: usize = 6;

/// We categorize input splicing and magic number insertion mutation strategies
/// as "longshots"; so this is an adjustable rate at which they will be applied
/// to an input. The default right now is 5% of the time.
const LONGSHOT_MUTATION_RATE: usize = 5;

/// This percentage is the rate at which we will create a new input from scratch
/// rather than pull one from the corpus to mutate
const GEN_SCRATCH_RATE: usize = 1;

/// When mutation strategies rely on mutating a number of bytes, this figure
/// provides the ceiling for how many bytes they are allowed to corrupt. Keep
/// in mind that inputs may pass through multiple rounds of mutation.
const MAX_BYTE_CORRUPTION: usize = 64;

/// When mutation strategies rely on mutating a block of memory, this figure
/// provides the ceiling for the dimensions of the block. Keep in mind that
/// inputs may pass through multiple rounds of mutation.
const MAX_BLOCK_CORRUPTION: usize = 512;

/// When mutation strategies rely on mutating bits, this figure provides the
/// ceiling for the number of bits that can be affected. Keep in mind that inputs
/// may pass through multiple rounds of mutation.
const MAX_BIT_CORRUPTION: usize = 64;

/// Hacky list of magic numbers to insert into random positions
/// in the input buffer
const MAGIC_NUMBERS: &[u64] = &[
    0,        // Hmmm
    u64::MAX, // All max values
    u32::MAX as u64,
    u16::MAX as u64,
    u8::MAX as u64,
    i64::MAX as u64,
    i32::MAX as u64,
    i16::MAX as u64,
    i8::MAX as u64,
    i64::MIN as u64, // All min values
    i32::MIN as u64,
    i16::MIN as u64,
    i8::MIN as u64,
    0b1 << 63, // Top bits set
    0b1 << 31,
    0b1 << 15,
    0b1 << 7,
    !(0b1 << 63), // All bits except top
    !(0b1 << 31) & 0xFFFFFFFF,
    !(0b1 << 15) & 0xFFFF,
    !(0b1 << 7) & 0xFF,
    2, // Po2
    4,
    8,
    16,
    32,
    64,
    128,
    256,
    512,
    1024,
    2048,
    4096,
    8192,
    16384,
];

/// A list of all the different mutation strategies
const MUTATIONS: [MutationTypes; 12] = [
    MutationTypes::ByteInsert,
    MutationTypes::ByteOverwrite,
    MutationTypes::ByteDelete,
    MutationTypes::BlockInsert,
    MutationTypes::BlockOverwrite,
    MutationTypes::BlockDelete,
    MutationTypes::BitFlip,
    MutationTypes::Grow,
    MutationTypes::Truncate,
    MutationTypes::MagicByteInsert,
    MutationTypes::MagicByteOverwrite,
    MutationTypes::Splice,
];

/// Represents some of the mutation strategies that AFL++ seems to do in "Havoc"
#[derive(Clone, Debug)]
pub enum MutationTypes {
    ByteInsert,
    ByteOverwrite,
    ByteDelete,
    BlockInsert,
    BlockOverwrite,
    BlockDelete,
    BitFlip,
    Grow,
    Truncate,
    MagicByteInsert,
    MagicByteOverwrite,
    Splice,
}

/// Toy mutator structure, everything in core is shared amongst all Mutator
/// structures while everything outside of core is unique to that mutator
/// implementation
pub struct ToyMutator {
    core: MutatorCore,
    last_mutation: Vec<MutationTypes>,
}

impl Mutator for ToyMutator {
    /// Generates a new Mutator instance with a random seed if one is not
    /// provided
    fn new(seed: Option<usize>, max_size: usize) -> Self {
        // If pRNG seed not provided, make our own
        let rng = if let Some(seed_val) = seed {
            seed_val
        } else {
            generate_seed()
        };

        ToyMutator {
            core: MutatorCore {
                rng,
                input: Vec::with_capacity(max_size),
                max_size,
                fields: Vec::new(),
            },
            last_mutation: Vec::with_capacity(MAX_STACK),
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

    /// Breaks the current input into fields for Redqueen to manipulate, since
    /// this is a dumb mutator, we just hand over the entire input buffer
    fn extract_redqueen_fields(&mut self) {
        // For a dumb mutator, just put the entire input into one field
        self.core.fields.clear();
        self.core.fields.push(self.core.get_input());
    }

    /// Reassembles fields into the input buffer, since this is a dumb mutator,
    /// we take the single field and that's our whole input
    fn reassemble_redqueen_fields(&mut self) -> Result<(), LucidErr> {
        self.core.clear_input();
        for f in &self.core.fields {
            self.core.input.extend_from_slice(f);
        }

        Ok(())
    }

    /// The main mutation function which will:
    /// 1. Clear the current input buffer
    /// 2. Randomly select an input from the corpus or generate one from scratch
    /// 3. Select the number of mutation rounds (stack)
    /// 4. Randomly select mutation strategies and apply them for n rounds
    fn mutate(&mut self, corpus: &Corpus) {
        // Clear current input
        self.core.clear_input();
        self.last_mutation.clear();

        // Get the number of inputs to choose from
        let num_inputs = corpus.num_inputs();

        // n% of the time, just generate a new input from scratch
        let gen = self.rand() % 100;

        // If we don't have any inputs to choose from, create a random one
        if num_inputs == 0 || gen < GEN_SCRATCH_RATE {
            self.generate_random_input();
            return;
        }

        // Pick an input from the corpus to use
        let idx = self.rand() % num_inputs;

        // Get the input
        let chosen = corpus.get_input(idx).unwrap();

        // Copy the input over
        self.core.input.extend_from_slice(chosen);

        // We have an input, pick a number of rounds of mutation
        let rounds = (self.rand() % MAX_STACK) + 1;

        // Apply mutations for number of rounds
        for _ in 0..rounds {
            // Determine the pool of candidates, we don't want to frequently
            // use longshot strategies
            let longshot = self.rand() % 100;

            // If we're within the longshot range, add them to the possible
            let pool = if longshot <= LONGSHOT_MUTATION_RATE {
                MUTATIONS.len()
            } else {
                MUTATIONS.len() - 3
            };

            // Pick mutation type
            let mutation_idx = self.rand() % pool;

            // Match on the mutation and apply it
            match MUTATIONS[mutation_idx] {
                MutationTypes::ByteInsert => {
                    self.byte_insert();
                    self.last_mutation.push(MutationTypes::ByteInsert);
                }
                MutationTypes::ByteOverwrite => {
                    self.byte_overwrite();
                    self.last_mutation.push(MutationTypes::ByteOverwrite);
                }
                MutationTypes::ByteDelete => {
                    self.byte_delete();
                    self.last_mutation.push(MutationTypes::ByteDelete);
                }
                MutationTypes::BlockInsert => {
                    self.block_insert();
                    self.last_mutation.push(MutationTypes::BlockInsert);
                }
                MutationTypes::BlockOverwrite => {
                    self.block_overwrite();
                    self.last_mutation.push(MutationTypes::BlockOverwrite);
                }
                MutationTypes::BlockDelete => {
                    self.block_delete();
                    self.last_mutation.push(MutationTypes::BlockDelete);
                }
                MutationTypes::BitFlip => {
                    self.bit_flip();
                    self.last_mutation.push(MutationTypes::BitFlip);
                }
                MutationTypes::Grow => {
                    self.grow();
                    self.last_mutation.push(MutationTypes::Grow);
                }
                MutationTypes::Truncate => {
                    self.truncate();
                    self.last_mutation.push(MutationTypes::Truncate);
                }
                MutationTypes::MagicByteInsert => {
                    self.magic_byte_insert();
                    self.last_mutation.push(MutationTypes::MagicByteInsert);
                }
                MutationTypes::MagicByteOverwrite => {
                    self.magic_byte_overwrite();
                    self.last_mutation.push(MutationTypes::MagicByteOverwrite);
                }
                MutationTypes::Splice => {
                    self.splice(corpus);
                    self.last_mutation.push(MutationTypes::Splice);
                }
            }
        }

        // Align the input length optionally
        if ALIGN && ALIGN_LEN > 0 && self.input_len() > ALIGN_LEN {
            let align = self.rand() % 100;
            if align < ALIGN_RATE {
                let aligned_len = self.input_len() & !(ALIGN_LEN - 1);
                self.core.input.truncate(aligned_len);
            }
        }

        // This isn't prod
        assert!(!self.core.input.is_empty());
        assert!(self.input_len() <= self.core.max_size);
    }
}

/// Implementation of all the mutation methods that are unique to this mutator
impl ToyMutator {
    /// Insert bytes into the input randomly
    fn byte_insert(&mut self) {
        // Defaults to global max, but can be hand tuned
        const MAX_INSERTS: usize = MAX_BYTE_CORRUPTION;

        // Determine the slack space we have
        let slack = self.core.max_size - self.input_len();

        // If we don't have any slack, return
        if slack == 0 {
            return;
        }

        // Determine the ceiling
        let ceiling = std::cmp::min(slack, MAX_INSERTS);

        // Pick number of bytes to insert, at least 1
        let insert_num = (self.rand() % ceiling) + 1;

        // Iterate through and apply insertions, duplicate idxs is ok
        for _ in 0..insert_num {
            // Pick an index
            let curr_idx = self.rand() % self.input_len();

            // Pick a byte to insert
            let byte = (self.rand() % 256) as u8;

            // Insert it
            self.core.input.insert(curr_idx, byte);
        }
    }

    /// Overwrite bytes in the input randomly
    fn byte_overwrite(&mut self) {
        // Defaults to global max, but can be hand tuned
        const MAX_OVERWRITES: usize = MAX_BYTE_CORRUPTION;

        // Determine how many bytes we can overwrite
        let ceiling = std::cmp::min(self.input_len(), MAX_OVERWRITES);

        // Pick a number of bytes to overwrite
        let overwrite_num = (self.rand() % ceiling) + 1;

        // Iterate through and apply overwrites
        for _ in 0..overwrite_num {
            // Pick an index
            let curr_idx = self.rand() % self.input_len();

            // Pick a byte to overwrite with
            let byte = (self.rand() % 256) as u8;

            // Overwrite it
            self.core.input[curr_idx] = byte;
        }
    }

    /// Delete bytes in the input randomly
    fn byte_delete(&mut self) {
        // Defaults to global max, but can be hand tuned
        const MAX_DELETES: usize = MAX_BYTE_CORRUPTION;

        // Determine how many bytes we can delete
        let ceiling = std::cmp::min(self.input_len() - 1, MAX_DELETES);

        // If the ceiling is 0, return
        if ceiling == 0 {
            return;
        }

        // Pick a number of bytes to delete
        let delete_num = (self.rand() % ceiling) + 1;

        // Iterate through and apply the deletes
        for _ in 0..delete_num {
            // Pick an index
            let curr_idx = self.rand() % self.input_len();

            // Remove it
            self.core.input.remove(curr_idx);
        }
    }

    /// Grabs a block from the input, and insert it randomly somewhere else
    fn block_insert(&mut self) {
        // Defaults to global max, but can be hand tuned
        const MAX_BLOCK_SIZE: usize = MAX_BLOCK_CORRUPTION;
        let mut block = [0u8; MAX_BLOCK_SIZE];

        // Determine the slack space in the input we have since we're growing
        let slack = self.core.max_size - self.input_len();

        // If we don't have any slack, return
        if slack == 0 {
            return;
        }

        // Determine a ceiling
        let mut ceiling = std::cmp::min(slack, MAX_BLOCK_SIZE);

        // If the ceiling is larger than the input, adjust it
        if ceiling > self.input_len() {
            ceiling = self.input_len();
        }

        // Determine a block size
        let block_size = (self.rand() % ceiling) + 1;

        // Determine the end range we can start from for the block
        let max_start = self.input_len() - block_size;

        // Determine where to start reading the block
        let block_start = self.rand() % (max_start + 1);

        // Copy the block into the block array
        block[..block_size]
            .copy_from_slice(&self.core.input[block_start..block_start + block_size]);

        // Determine where to insert the block
        let block_insert = self.rand() % self.input_len();

        // Use insert calls (slow, but readable and who cares?)
        for (i, &byte) in block[..block_size].iter().enumerate() {
            self.core.input.insert(block_insert + i, byte);
        }
    }

    /// Grabs a block from the input and copy it over to another location
    fn block_overwrite(&mut self) {
        // Defaults to global max, but can be hand tuned
        const MAX_BLOCK_SIZE: usize = MAX_BLOCK_CORRUPTION;
        let mut block = [0u8; MAX_BLOCK_SIZE];

        // Determine a ceiling of block size
        let ceiling = std::cmp::min(self.input_len(), MAX_BLOCK_SIZE);

        // Pick a block size
        let block_size = (self.rand() % ceiling) + 1;

        // Determine the end range we can start from for the block reading, but
        // also this is the block writing start as well
        let max_start = self.input_len() - block_size;

        // Determine where to start reading the block
        let block_start = self.rand() % (max_start + 1);

        // Copy the block into the block array
        block[..block_size]
            .copy_from_slice(&self.core.input[block_start..block_start + block_size]);

        // Determine where to start overwriting
        let overwrite_start = self.rand() % (max_start + 1);

        // Overwrite those bytes
        self.core.input[overwrite_start..overwrite_start + block_size]
            .copy_from_slice(&block[..block_size]);
    }

    /// Removes a random block from the input buffer
    fn block_delete(&mut self) {
        // Defaults to global max, but can be hand tuned
        const MAX_BLOCK_SIZE: usize = MAX_BLOCK_CORRUPTION;

        // Determine how much we can delete
        let ceiling = std::cmp::min(self.input_len() - 1, MAX_BLOCK_SIZE);

        // If we have a ceiling of 0, just return
        if ceiling == 0 {
            return;
        }

        // Pick a block size for deletion
        let block_size = (self.rand() % ceiling) + 1;

        // Determine the end range to start deleting from
        let max_start = self.input_len() - block_size;

        // Pick a place to start deleting from
        let block_start = self.rand() % (max_start + 1);

        // Delete that block
        self.core.input.drain(block_start..block_start + block_size);
    }

    /// Generates a random input from scratch, not likely to be a great strategy
    fn generate_random_input(&mut self) {
        // Pick a size for the input
        let input_size = (self.rand() % self.core.max_size) + 1;

        // Re-size the input vector
        self.core.input.resize(input_size, 0);

        // Fill in the data randomly
        for i in 0..input_size {
            self.core.input[i] = (self.rand() % 256) as u8;
        }
    }

    /// Randomly flips bits in the input buffer
    fn bit_flip(&mut self) {
        // Determine the number of bits in the input
        let num_bits = self.input_len() * 8;

        // Determine the ceiling of what we can flip
        let ceiling = std::cmp::min(num_bits, MAX_BIT_CORRUPTION);

        // Determine the number of bits to flip (at least 1)
        let num_flips = (self.rand() % ceiling) + 1;

        // Go through and flip bits
        for _ in 0..num_flips {
            // Choose a random bit to flip
            let bit_position = self.rand() % num_bits;

            // Calculate which byte this bit is in
            let byte_index = bit_position / 8;

            // Calculate which bit within the byte to flip
            let bit_index = bit_position % 8;

            // Flip the bit
            self.core.input[byte_index] ^= 1 << bit_index;
        }
    }

    /// Inserts a random byte block into the input buffer
    fn grow(&mut self) {
        // Determine maximum size to grow
        let slack = self.core.max_size - self.input_len();
        if slack == 0 {
            return;
        }

        // Pick size of block
        let size = (self.rand() % slack) + 1;

        // Pick an index to add to
        let idx = self.rand() % self.input_len();

        // Pick byte to place in there
        let byte = (self.rand() % 256) as u8;

        // Insert there
        for _ in 0..size {
            self.core.input.insert(idx, byte);
        }
    }

    /// Truncates the input a random amount of bytes but always leaves at least
    /// one byte
    fn truncate(&mut self) {
        // Determine how much we can shrink
        let slack = self.input_len() - 1;
        if slack == 0 {
            return;
        }

        // Pick an index to truncate at, can't be zero
        let idx = (self.rand() % slack) + 1;

        // Truncate
        self.core.input.truncate(idx);
    }

    /// Inserts magic bytes into the input buffer after optionally mutating
    /// the bytes
    fn magic_byte_insert(&mut self) {
        // Defaults to global max, but can be hand tuned
        const MAX_INSERTS: usize = MAX_BYTE_CORRUPTION;

        // Determine the slack space we have
        let slack = self.core.max_size - self.input_len();

        // If we don't have any slack space, return
        if slack == 0 {
            return;
        }

        // Determine the ceiling
        let ceiling = std::cmp::min(slack, MAX_INSERTS);

        // Pick number of bytes to insert, at least 1
        let insert_num = (self.rand() % ceiling) + 1;

        // Divide that by 8 to determine how many u64s will fit
        let num_u64 = insert_num / 8;

        // Insert up to num_u64 u64 values, likely much smaller
        for _ in 0..num_u64 {
            // Pick an index to insert at
            let idx = self.rand() % self.input_len();

            // Pick a magic value
            let magic = MAGIC_NUMBERS[self.rand() % MAGIC_NUMBERS.len()];

            // Convert to vector of bytes
            let magic_bytes = magic.to_ne_bytes().to_vec();

            // Insert magic bytes
            for (i, &byte) in magic_bytes.iter().enumerate() {
                self.core.input.insert(idx + i, byte);
            }
        }
    }

    /// Overwrites randomly selected input buffer data with magic bytes that are
    /// optionally mutated
    fn magic_byte_overwrite(&mut self) {
        // If the input isn't at least 8 bytes, just NOP
        if self.input_len() < 8 {
            return;
        }

        // Defaults to global max, but can be hand tuned
        const MAX_OVERWRITES: usize = MAX_BYTE_CORRUPTION;

        // Determine how many bytes we can overwrite
        let ceiling = std::cmp::min(self.input_len(), MAX_OVERWRITES);

        // Pick a number of bytes to overwrite
        let overwrite_num = (self.rand() % ceiling) + 1;

        // Divide that number by 8 to determine how many u64s will fit
        let num_u64 = overwrite_num / 8;

        // Make sure we don't go out of bounds
        let max_overwrite = self.input_len() - 8;

        // Overwrite up to num_u64 u64 values
        for _ in 0..num_u64 {
            // Pick an index to overwrite at
            let idx = self.rand() % (max_overwrite + 1);

            // Pick a magic value
            let magic = MAGIC_NUMBERS[self.rand() % MAGIC_NUMBERS.len()];

            // Convert to vector of bytes
            let magic_bytes = magic.to_ne_bytes().to_vec();

            // Overwrite with magic bytes
            for (i, &byte) in magic_bytes.iter().enumerate() {
                self.core.input[idx + i] = byte;
            }
        }
    }

    /// Splices two inputs together if possible, this strategy depends on
    /// having access to the corpus in order to select a 2nd input
    fn splice(&mut self, corpus: &Corpus) {
        // Take a block of the current input
        let old_block_start = self.rand() % self.input_len();

        // Pick a length for the block
        let old_block_len = self.rand() % (self.input_len() - old_block_start) + 1;

        // Pick a new input index
        let new_idx = self.rand() % corpus.num_inputs();

        // Get reference to new input
        let Some(new_input) = corpus.get_input(new_idx) else {
            return; // No inputs in corpus?
        };

        // Determine the slack space left
        let slack = self.core.max_size - old_block_len;

        // If there's no slack, we can return early
        if slack == 0 {
            return;
        }

        // Pick a place in the new input to read a block from
        let new_block_start = self.rand() % new_input.len();

        // Pick a length ceiling of the new block, guaranteed to be at least 1
        let new_ceiling = std::cmp::min(new_input.len() - new_block_start, slack);

        // Pick a length
        let new_block_len = (self.rand() % new_ceiling) + 1;

        // Determine total length we'll have
        let total_len = old_block_len + new_block_len;

        // Adjust input buffer if necessary
        if total_len > self.input_len() {
            self.core.input.resize(total_len, 0);
        }

        // Copy with memmove because of overlap potential
        self.core
            .input
            .copy_within(old_block_start..old_block_start + old_block_len, 0);

        // Then, copy the new block right after the old block
        let new_block = &new_input[new_block_start..new_block_start + new_block_len];
        self.core.input[old_block_len..total_len].copy_from_slice(new_block);

        // Adjust input buffer length if necessary
        if total_len < self.input_len() {
            self.core.input.truncate(total_len);
        }
    }
}
