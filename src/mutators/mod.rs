//! This file contains the logic implementing the Mutator traits and the core
//! data structure for all mutator implementations (MutatorCore). This allows
//! for the creation of mutators in the /mutators folder and adding them to
//! the factory function `create_mutator`. See toy.rs for more details on
//! mutator implementation.
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use crate::corpus::Corpus;
use crate::err::LucidErr;

pub mod toy;
use toy::ToyMutator;

/// Shared state for all mutators, each implementation embeds this
#[derive(Clone, Default)]
struct MutatorCore {
    rng: usize,           // Random generator seed/state
    input: Vec<u8>,       // Current input buffer (empty by default)
    max_size: usize,      // Maximum input size
    fields: Vec<Vec<u8>>, // RedQueen fields
}

/// Trait all mutators must implement
pub trait Mutator {
    /// Construct a new mutator with max input size.
    fn new(seed: Option<usize>, max_size: usize) -> Self
    where
        Self: Sized;

    /// Return a random usize.
    fn rand(&mut self) -> usize;

    /// Reseed RNG.
    fn reseed(&mut self) -> usize;

    /// Split input into RedQueen fields.
    fn extract_redqueen_fields(&mut self);

    /// Reassemble input from RedQueen fields.
    fn reassemble_redqueen_fields(&mut self);

    /// Number of RedQueen fields.
    fn num_redqueen_fields(&self) -> usize;

    /// Get a RedQueen field by index.
    fn get_redqueen_field(&self, idx: usize) -> Result<Vec<u8>, LucidErr>;

    /// Replace a RedQueen field by index.
    fn set_redqueen_field(&mut self, idx: usize, field: Vec<u8>) -> Result<(), LucidErr>;

    /// Copy into input buffer (enforces max_size).
    fn copy_input(&mut self, new_input: &[u8]);

    /// Perform one round of mutation on input.
    fn mutate(&mut self, corpus: &Corpus);

    /// Get a read-only reference to current input buffer
    fn get_input_ref(&self) -> &Vec<u8>;

    /// Get owned copy of current input buffer
    fn get_input(&self) -> Vec<u8>;

    /// Get the size of the current input length
    fn input_len(&self) -> usize;

    /// Get ptr to current input
    fn input_ptr(&self) -> *const u8;

    /// Read-only accessor for rng
    fn get_rng(&self) -> usize;

    /// Read-only accessor for max_size
    fn get_max_size(&self) -> usize;
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
