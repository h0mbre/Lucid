//! This file contains all of the datastructures and logic necessary to create
//! and manage a corpus of inputs for fuzzing
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use std::collections::HashSet;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::time::Instant;

use crate::config::Config;
use crate::err::LucidErr;
use crate::{finding, finding_warn, prompt_warn};

/// The amount of inputs we can sample from disk from other fuzzers
const SAMPLE_CORPUS_SIZE: usize = 1000;

/// % of time we choose a newer input over an older input
const NEW_BIAS_RATE: usize = 75;

/// Holds all of the information and statistics we need in order to manage a
/// database of inputs, timeouts, and crashes.
#[derive(Clone)]
pub struct Corpus {
    pub inputs_dir: String,      // Where inputs are written to on disk
    pub crash_dir: String,       // Where crashes are written to on disk
    pub stats_dir: String,       // Where statistics are written to on disk
    pub inputs: Vec<Vec<u8>>,    // In memory input database
    input_hashes: HashSet<u64>,  // Database of unique input hashes
    output_limit: usize,         // The limit in megabytes of what we can save
    pub id: usize,               // Inherited from the LucidContext
    last_sync: Instant,          // The last time we synced from disk to memory
    sync_interval: u64,          // How often we sync the in-memory corpus with the disk
    pub corpus_size: usize,      // The number of bytes in the corpus
    sample_inputs: Vec<Vec<u8>>, // Input data base sampled from other fuzzers
    sample_hashes: HashSet<u64>, // Database of unique sample input hashes
    prng: usize,                 // pRNG state
}

impl Corpus {
    /// Create a new Corpus based on configuration data
    pub fn new(config: &Config) -> Result<Self, LucidErr> {
        let mut inputs = Vec::new();
        let mut corpus_size = 0;
        let prng = 0;
        let sample_inputs = Vec::new();
        let sample_hashes = HashSet::new();

        // Try to read inputs in from the seeds_dir if we have one
        if config.seeds_dir.is_some() {
            let seeds_dir = config.seeds_dir.as_ref().unwrap().clone();

            // Read the directory
            let Ok(entries) = std::fs::read_dir(seeds_dir) else {
                return Err(LucidErr::from("Unable to read entries from seeds dir"));
            };

            // For each entry, get a path
            for entry in entries {
                if entry.is_ok() {
                    let path = entry.unwrap().path();

                    // Make sure its a regular file
                    if path.is_file() {
                        let file = File::open(&path);
                        if file.is_err() {
                            continue;
                        }

                        // Store contents
                        let mut file_buf = Vec::new();
                        let result = file.unwrap().read_to_end(&mut file_buf);
                        if result.is_err() {
                            continue;
                        }

                        // Store the input
                        corpus_size += file_buf.len();
                        inputs.push(file_buf);
                    }
                }
            }
        }

        // Formulate dir names
        let inputs_dir = format!("{}/inputs", config.output_dir);
        let crash_dir = format!("{}/crashes", config.output_dir);
        let stats_dir = format!("{}/stats", config.output_dir);

        // Try to create directories for inputs, crashes (including timeouts),
        // and statistics
        if std::path::Path::new(&inputs_dir).exists() {
            prompt_warn!("Inputs directory '{}' already exists!", inputs_dir);
        } else {
            match std::fs::create_dir_all(&inputs_dir) {
                Ok(_) => (),
                Err(e) => {
                    return Err(LucidErr::from(&format!(
                        "Unable to create inputs directory '{}', error: {}",
                        inputs_dir, e
                    )));
                }
            }
        }

        if std::path::Path::new(&crash_dir).exists() {
            prompt_warn!("Crash directory '{}' already exists!", crash_dir);
        } else {
            match std::fs::create_dir_all(&crash_dir) {
                Ok(_) => (),
                Err(e) => {
                    return Err(LucidErr::from(&format!(
                        "Unable to create crash directory '{}', error: {}",
                        crash_dir, e
                    )));
                }
            }
        }

        if std::path::Path::new(&stats_dir).exists() {
            prompt_warn!("Stats directory '{}' already exists!", stats_dir);
        } else {
            match std::fs::create_dir_all(&stats_dir) {
                Ok(_) => (),
                Err(e) => {
                    return Err(LucidErr::from(&format!(
                        "Unable to create stat directory '{}', error: {}",
                        stats_dir, e
                    )));
                }
            }
        }

        // Delete any files in stat dir
        let stat_files = std::fs::read_dir(&stats_dir)
            .map_err(|e| LucidErr::from(&format!("Failed to read stats directory: {}", e)))?;

        for file in stat_files {
            let file = file
                .map_err(|e| LucidErr::from(&format!("Failed to read directory entry: {}", e)))?;
            let path = file.path();
            if path.is_file() {
                std::fs::remove_file(path)
                    .map_err(|e| LucidErr::from(&format!("Failed to delete file: {}", e)))?;
            }
        }

        // Truncate inputs if necessary
        let max = config.input_max_size;
        for input in inputs.iter_mut() {
            if input.len() > max {
                prompt_warn!(
                    "Input truncated from {} bytes to {} bytes",
                    input.len(),
                    max
                );
                input.truncate(max);
            }
        }

        // Count this now as our last sync
        let last_sync = Instant::now();

        Ok(Corpus {
            inputs_dir,
            crash_dir,
            stats_dir,
            inputs,
            input_hashes: HashSet::new(),
            output_limit: config.output_limit,
            id: 0,
            last_sync,
            sync_interval: config.sync_interval as u64,
            corpus_size,
            sample_inputs,
            sample_hashes,
            prng,
        })
    }

    /// Return the number of inputs currently in the corpus in memory
    pub fn num_inputs(&self) -> usize {
        self.inputs.len() + self.sample_inputs.len()
    }

    /// Get an input by index
    pub fn get_input_by_idx(&self, idx: usize) -> Option<&[u8]> {
        // Validate index
        if idx >= self.inputs.len() + self.sample_inputs.len() {
            return None;
        }

        // Grab from normal corpus
        if idx < self.inputs.len() {
            return Some(&self.inputs[idx]);
        }

        // Return from sample inputs
        Some(&self.sample_inputs[idx - self.inputs.len()])
    }

    /// Gets an input from the corpus with pseudo uniform distribution
    pub fn get_input_uniform(&mut self, prng: usize) -> Option<&[u8]> {
        // Seed our random
        self.prng = prng;

        // Determine ceiling index
        let ceiling = self.inputs.len() + self.sample_inputs.len();
        if ceiling == 0 {
            return None;
        }

        // Pick a random index across both pools
        let idx = self.rand() % ceiling;

        // If it's in the normal corpus, return that
        if idx < self.inputs.len() {
            return Some(&self.inputs[idx]);
        }

        // Otherwise, adjust and return from the sample pool
        Some(&self.sample_inputs[idx - self.inputs.len()])
    }

    /// Gets an input but biases selection towards newer inputs (towards end)
    pub fn get_input_bias_new(&mut self, prng: usize) -> Option<&[u8]> {
        // Seed our random
        self.prng = prng;

        // Determine ceiling index
        let ceiling = self.inputs.len() + self.sample_inputs.len();

        // If we don't have at least two inputs, just return uniform
        if ceiling < 2 {
            return self.get_input_uniform(prng);
        }

        // Split corpus into halves
        let old = 0..(ceiling / 2);
        let new = (ceiling / 2)..ceiling;

        // Determine what pool to pick from
        let pool = if self.rand() % 100 > NEW_BIAS_RATE {
            old
        } else {
            new
        };

        // Pick an index into that pool
        let idx = pool.start + (self.rand() % pool.len());

        // Return that by index
        self.get_input_by_idx(idx)
    }

    /// Save an input to the corpus
    /// - Hash the input so we can focus on saving only unique inputs
    /// - Attempt to write the input to disk, but fail and warn the user if
    /// we have already reached our findings limit
    ///
    /// It's important to note that if we fail to write the input to disk because
    /// of the findings limit, then we also don't save the input to memory
    pub fn save_input(&mut self, input: &Vec<u8>) -> u64 {
        // Create a hash for the input data
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        let hash = hasher.finish();

        // Create the file path for the new input
        let file_path = std::path::Path::new(&self.inputs_dir).join(format!("{:016X}.input", hash));
        if file_path.exists() {
            finding_warn!(self.id, "Skipping input save, {:016X} already exists", hash);
        }

        // Make sure we have enough space
        if input.len() > self.output_limit {
            finding_warn!(self.id, "Unable to save new input, output_limit exhausted!");
            return hash;
        }

        // Attempt to save the input to disk
        match std::fs::write(file_path, input) {
            Ok(_) => {
                self.output_limit -= input.len();
                // Copy the input bytes over in memory only if successfully saved to disk
                self.inputs.push(input.clone());
                self.corpus_size += input.len();

                // Add the hash to the database
                self.input_hashes.insert(hash);
            }
            Err(e) => {
                finding_warn!(self.id, "Unable to save new input to disk, error: {}", e);
            }
        }

        hash
    }

    /// Save a crash
    /// - Hash the crash so we don't duplicate crashes on disk
    /// - Attempt to write the crash to disk, but fail and warn the user if
    /// we have already reached our findings limit
    pub fn save_crash(&mut self, input: &Vec<u8>, filetype: &str) -> u64 {
        // Create a hash for the input data
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        let hash = hasher.finish();

        // Create the file path for the new input
        let file_path =
            std::path::Path::new(&self.crash_dir).join(format!("{:016X}.{}", hash, filetype));
        if file_path.exists() {
            finding_warn!(
                self.id,
                "Skipping {} input save, {:016X} already exists",
                filetype,
                hash
            );
            return hash;
        }

        // Make sure we have enough space
        if input.len() > self.output_limit {
            finding_warn!(
                self.id,
                "Unable to save {} input, output_limit exhausted!",
                filetype
            );
            return hash;
        }

        // Attempt to save the input to disk
        match std::fs::write(&file_path, input) {
            Ok(_) => {
                self.output_limit -= input.len();
                // Copy the input bytes over in memory only if successfully saved to disk
                finding!(
                    self.id,
                    "Saved {} input '{:016X}' ({} bytes)",
                    filetype,
                    hash,
                    input.len()
                );
            }
            Err(e) => {
                finding_warn!(
                    self.id,
                    "Unable to save {} input to disk, error: {}",
                    filetype,
                    e
                );
            }
        }

        hash
    }

    /// Part of the corpus-syncing process, take the file name from the on-disk
    /// corpus file and extract the hash portion, example filename:
    /// 8B5BB66137A8AA15.input
    fn extract_hash_from_filename(&self, path: &std::path::Path) -> Option<u64> {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| u64::from_str_radix(stem, 16).ok())
    }

    /// Shouldn't be necessary, but check to make sure it's a somewhat sane
    /// file before we try ingesting it during the corpus-syncing process
    fn is_valid_input_file(&self, path: &std::path::Path) -> bool {
        path.is_file() && path.extension().map_or(false, |ext| ext == "input")
    }

    /// Thin wrapper around reading the corpus directory entries during the
    /// corpus-syncing process
    fn read_input_directory(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.inputs_dir)
    }

    /// Copied from mutator core implementation, meh
    #[inline]
    fn rand(&mut self) -> usize {
        // Save off current value
        let curr = self.prng;

        // Mutate current state with xorshift for next call
        let rng = &mut self.prng;
        *rng ^= *rng << 13;
        *rng ^= *rng >> 17;
        *rng ^= *rng << 43;

        // Return saved off value
        curr
    }

    /// During the corpus-syncing process, scan the corpus directory for new
    /// inputs that we can potentially sample from and ingest them randomly if
    /// there is more than the sample max
    fn sample_inputs_from_disk(&mut self) {
        // Get a list of all the entries in the shared corpus directory
        let entries = match self.read_input_directory() {
            Ok(entries) => entries,
            Err(e) => {
                finding_warn!(self.id, "Failed to read inputs directory: {}", e);
                return;
            }
        };

        // Iterate through all the entries and see which ones we don't have, if
        // we don't have them, they become a candidate to be sampled
        let mut candidates = Vec::new();
        for entry in entries {
            // Skip failed entry results with warning
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    finding_warn!(self.id, "Failed to read directory entry: {}", e);
                    continue;
                }
            };

            // Extract the path
            let path = entry.path();

            // Make sure it's somewhat valid looking
            if !self.is_valid_input_file(&path) {
                continue;
            }

            // Get the hash for file
            if let Some(hash) = self.extract_hash_from_filename(&path) {
                // If this is something we already have, continue
                if self.input_hashes.contains(&hash) {
                    continue;
                }

                // Add this to the candidate pool
                candidates.push((hash, path));
            }
        }

        // Determine what selection mode we're in, if we have more candidates
        // than the max sample amount, we'll have to randomly select them
        if candidates.len() > SAMPLE_CORPUS_SIZE {
            // Randomly pick an input from the candidate pool
            while self.sample_inputs.len() < SAMPLE_CORPUS_SIZE && !candidates.is_empty() {
                // Get idx
                let pick_idx = self.rand() % candidates.len();

                // Remove this candidate from the pool
                let (hash, path) = candidates.swap_remove(pick_idx);

                // If we already have this hash, skip, this should never happen!
                if !self.sample_hashes.insert(hash) {
                    finding_warn!(self.id, "Chosen candidate was in sample DB already");
                    continue;
                }

                // Try to read the data now into the sample input database
                match std::fs::read(&path) {
                    Ok(content) => self.sample_inputs.push(content),
                    Err(e) => {
                        finding_warn!(self.id, "Failed to read input file {:016X}: {}", hash, e)
                    }
                }
            }
        }
        // We have enough room to take all candidates in sample
        else {
            for (hash, path) in candidates {
                if !self.sample_hashes.insert(hash) {
                    continue;
                }

                match std::fs::read(&path) {
                    Ok(content) => self.sample_inputs.push(content),
                    Err(e) => {
                        finding_warn!(self.id, "Failed to read input file {:016X}: {}", hash, e)
                    }
                }
            }
        }
    }

    /// All fuzzers independently save their discovered inputs to the corpus
    /// directory for inputs. Each fuzzer will then have less inputs in their
    /// in-memory corpus than what exists on disk. Every sync_interval, the
    /// fuzzers will all scan the corpus directory for new inputs to potentially
    /// sample. Every sync they will clear out their sample queue and hashset
    pub fn sync(&mut self, prng: usize) {
        // Check to see if we've reached re-sync time
        if self.last_sync.elapsed().as_secs() < self.sync_interval {
            return;
        }

        // Set the prng
        self.prng = prng;

        // Clear the samples
        self.sample_inputs.clear();
        self.sample_hashes.clear();

        // Read all of the filenames in the corpus directory and add them
        // to the corpus if we don't have the hash in the database, files have
        // this format: `8B5BB66137A8AA15.input`
        self.sample_inputs_from_disk();
        self.last_sync = Instant::now();

        finding!(
            self.id,
            "Sampled {} inputs from disk",
            self.sample_inputs.len()
        );
    }
}
