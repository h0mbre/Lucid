//! This file contains the logic implementing the Mutator traits and the core
//! data structure for all mutator implementations (MutatorCore). This allows
//! for the creation of mutators in the /mutators folder and adding them to
//! the factory function `create_mutator`. See toy.rs for more details on
//! mutator implementation.
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::corpus::Corpus;
use crate::err::LucidErr;

pub mod toy;
use toy::ToyMutator;

/// Generates a random seed for the mutator by executing rdtsc() and then
/// hashing the result
fn generate_seed() -> usize {
    let mut hasher = DefaultHasher::new();

    let rdtsc = unsafe { core::arch::x86_64::_rdtsc() };
    rdtsc.hash(&mut hasher);

    // Combine all sources of entropy
    hasher.finish() as usize
}

/// Shared state for all mutators, each implementation embeds this
#[derive(Clone, Default)]
pub(crate) struct MutatorCore {
    pub rng: usize,           // Random generator seed/state
    pub input: Vec<u8>,       // Current input buffer (empty by default)
    pub max_size: usize,      // Maximum input size
    pub fields: Vec<Vec<u8>>, // RedQueen fields
}

/// Trait that all mutators share
/// All default methods have their implementations here so that they don't have
/// to be implemented per-mutator implementation, while non-default methods are
/// required but will be implemented on a per-mutator basis as they will be
/// unique
pub trait Mutator {
    /// Construct a new mutator with max input size.
    fn new(seed: Option<usize>, max_size: usize) -> Self
    where
        Self: Sized;

    /// Get access to core
    fn core(&self) -> &MutatorCore;

    /// Get mutable access to core
    fn core_mut(&mut self) -> &mut MutatorCore;

    /// Default: Return a random usize.
    #[inline]
    fn rand(&mut self) -> usize {
        // Save off current value
        let curr = self.core().rng;

        // Mutate current state with xorshift for next call
        let rng = &mut self.core_mut().rng;
        *rng ^= *rng << 13;
        *rng ^= *rng >> 17;
        *rng ^= *rng << 43;

        // Return saved off value
        curr
    }

    /// Default: Reseed RNG.
    fn reseed(&mut self) -> usize {
        self.core_mut().rng = generate_seed();
        self.core().rng
    }

    /// Default: Return the number of fields currently decomposed
    fn num_redqueen_fields(&self) -> usize {
        self.core().fields.len()
    }

    /// Default: Getter for Redqueen fields
    fn get_redqueen_field(&self, idx: usize) -> Result<Vec<u8>, LucidErr> {
        self.core()
            .fields
            .get(idx)
            .cloned()
            .ok_or_else(|| LucidErr::from("Invalid Redqueen field index"))
    }

    /// Default: Setter for Redqueen fields
    fn set_redqueen_field(&mut self, idx: usize, field: Vec<u8>) -> Result<(), LucidErr> {
        if idx < self.core().fields.len() {
            self.core_mut().fields[idx] = field;
            Ok(())
        } else {
            Err(LucidErr::from("Invalid Redqueen field index"))
        }
    }

    /// Default: Clears the current mutator input buffer and copies a passed in
    /// slice into the input buffer
    fn copy_input(&mut self, slice: &[u8]) {
        self.core_mut().copy_input(slice);
    }

    /// Default: Get a read-only reference to current input buffer
    fn get_input_ref(&self) -> &Vec<u8> {
        self.core().get_input_ref()
    }

    /// Default: Get owned copy of current input buffer
    fn get_input(&self) -> Vec<u8> {
        self.core().get_input()
    }

    /// Default: Returns input length
    fn input_len(&self) -> usize {
        self.core().input_len()
    }

    /// Default: Returns input as a pointer
    fn input_ptr(&self) -> *const u8 {
        self.core().input_ptr()
    }

    /// Default: Return rng
    fn get_rng(&self) -> usize {
        self.core().get_rng()
    }

    /// Default: Return max_size
    fn get_max_size(&self) -> usize {
        self.core().get_max_size()
    }

    /// Custom: Perform one round of mutation on input.
    fn mutate(&mut self, corpus: &Corpus);

    /// Custom: Split input into RedQueen fields.
    fn extract_redqueen_fields(&mut self);

    /// Custom: Reassemble input from RedQueen fields.
    fn reassemble_redqueen_fields(&mut self);
}

impl MutatorCore {
    // Clears the current mutator input buffer and copies a passed in slice
    /// into the input buffer
    fn copy_input(&mut self, slice: &[u8]) {
        // Clear the current input
        self.input.clear();

        // Copy the passed in buffer
        self.input.extend_from_slice(slice);
    }

    /// Get a read-only reference to current input buffer
    fn get_input_ref(&self) -> &Vec<u8> {
        &self.input
    }

    /// Get owned copy of current input buffer
    fn get_input(&self) -> Vec<u8> {
        self.input.clone()
    }

    /// Returns input length
    fn input_len(&self) -> usize {
        self.input.len()
    }

    /// Returns input as a pointer
    fn input_ptr(&self) -> *const u8 {
        self.input.as_ptr()
    }

    /// Read-only accessor for rng
    fn get_rng(&self) -> usize {
        self.rng
    }

    /// Read-only accessor for max_size
    fn get_max_size(&self) -> usize {
        self.max_size
    }
}

/// Simple factory to create mutators by name (extend as needed).
pub fn create_mutator(
    name: &str,
    seed: Option<usize>,
    max_size: usize,
) -> Result<Box<dyn Mutator>, LucidErr> {
    match name {
        "toy" => Ok(Box::new(ToyMutator::new(seed, max_size))),
        // Add others: "basic" => Box::new(BasicMutator::new(max_size)),
        _ => Err(LucidErr::from(&format!("Unrecognized mutator '{}'", name))),
    }
}
