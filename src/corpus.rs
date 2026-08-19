//! This file contains all of the datastructures and logic necessary to create
//! and manage a corpus of inputs for fuzzing
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2026 h0mbre

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::err::LucidErr;
use crate::{finding, finding_warn, prompt_warn};

/// The amount of inputs we can sample from disk from other fuzzers
const SAMPLE_CORPUS_SIZE: usize = 1000;

/// Hit-count descendants may occupy at most 5% of the permanent corpus.
const HITCOUNT_DESCENDANT_RATIO: f64 = 0.05;

/// The maximum number of hit-count inputs generated without a parent.
const GENERATED_HITCOUNT_SIZE: usize = 64;

/// Size of each PC in an input coverage sidecar.
const PC_SIZE: usize = std::mem::size_of::<u64>();

/// Why an input is being admitted to the corpus.
pub enum CorpusSaveReason {
    /// Seeds and inputs retained for new edges or semantic feedback.
    Permanent,
    /// An input retained only because it increased an edge hit-count bucket.
    Hitcount {
        /// Flat corpus index of the input used as the mutation base.
        parent: Option<usize>,
    },
}

/// Holds all of the information and statistics we need in order to manage a
/// database of inputs, timeouts, and crashes.
#[derive(Clone)]
pub struct Corpus {
    pub inputs_dir: String,     // Where inputs are written to on disk
    pub crash_dir: String,      // Where crashes are written to on disk
    pub stats_dir: String,      // Where statistics are written to on disk
    pub inputs: Vec<Vec<u8>>,   // Permanent in-memory input database
    input_hashes: HashSet<u64>, // Database of unique permanent input hashes
    output_limit: usize,        // The limit in megabytes of what we can save
    pub id: usize,              // Inherited from the LucidContext
    next_sync: Instant,         // The next time we should sync from disk to memory
    sync_interval: u64,         // How often we sync the in-memory corpus with the disk
    pub corpus_size: usize,     // Permanent and hit-count corpus bytes

    // Inputs sampled from other fuzzers are replaced on every corpus sync.
    sample_inputs: [Option<Vec<u8>>; SAMPLE_CORPUS_SIZE],
    sample_len: usize,
    sample_hashes: HashSet<u64>,

    // Hit-count-only inputs are local FIFO pools. Descendants have a selected
    // corpus parent; generated inputs were created without a parent.
    descendant_hitcounts: VecDeque<Vec<u8>>,
    generated_hitcounts: VecDeque<Vec<u8>>,
    prng: usize, // pRNG state
}

impl Corpus {
    /// Create a new Corpus based on configuration data
    pub fn new(config: &Config) -> Result<Self, LucidErr> {
        let mut inputs = Vec::new();
        let mut corpus_size = 0;
        let prng = 0;
        let sample_inputs = std::array::from_fn(|_| None);
        let sample_len = 0;
        let sample_hashes = HashSet::new();
        let descendant_hitcounts = VecDeque::new();
        let generated_hitcounts = VecDeque::new();

        // Try to read inputs in from the seeds_dir if we have one
        if let Some(seeds_dir) = config.seeds_dir.as_ref() {
            // Read the directory
            let Ok(entries) = std::fs::read_dir(seeds_dir) else {
                return Err(LucidErr::from("Unable to read entries from seeds dir"));
            };

            // Flatten will unwrap all Ok() entries for us and skip Err()
            for ok_entry in entries.flatten() {
                // Extract the path from the dir entry
                let path = ok_entry.path();

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

        // Seed inputs are already permanent corpus members. Remember their
        // hashes so rediscovering an unchanged seed cannot add it a second time.
        let input_hashes = inputs.iter().map(|input| Self::hash_input(input)).collect();

        // Use the full interval until the worker initializes its post-fork,
        // independently jittered sync schedule.
        let next_sync = Instant::now() + Duration::from_secs(config.sync_interval as u64);

        Ok(Corpus {
            inputs_dir,
            crash_dir,
            stats_dir,
            inputs,
            input_hashes,
            output_limit: config.output_limit,
            id: 0,
            next_sync,
            sync_interval: config.sync_interval as u64,
            corpus_size,
            sample_inputs,
            sample_len,
            sample_hashes,
            descendant_hitcounts,
            generated_hitcounts,
            prng,
        })
    }

    /// Initialize this worker's corpus-sync schedule from its post-fork PRNG
    /// seed. Only the first deadline is jittered; subsequent syncs retain the
    /// configured fixed interval.
    pub fn initialize_sync_schedule(&mut self, prng: usize) -> u64 {
        self.prng = prng;

        let initial_delay = if self.sync_interval == 0 {
            0
        } else {
            self.rand() as u64 % self.sync_interval
        };

        self.next_sync = Instant::now() + Duration::from_secs(initial_delay);
        initial_delay
    }

    /// Return the number of inputs currently in the corpus in memory
    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
            + self.sample_len
            + self.descendant_hitcounts.len()
            + self.generated_hitcounts.len()
    }

    /// Return the number of permanent inputs owned by this fuzzer.
    pub fn num_permanent_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Return the number of inputs currently sampled from other fuzzers.
    pub fn num_sampled_inputs(&self) -> usize {
        self.sample_len
    }

    /// Return the number of hit-count inputs descended from a corpus parent.
    pub fn num_descendant_hitcounts(&self) -> usize {
        self.descendant_hitcounts.len()
    }

    /// Return the number of hit-count inputs generated without a parent.
    pub fn num_generated_hitcounts(&self) -> usize {
        self.generated_hitcounts.len()
    }

    /// Get an input by index
    pub fn get_input_by_idx(&self, idx: usize) -> Option<&[u8]> {
        // Validate index
        if idx >= self.num_inputs() {
            return None;
        }

        // Grab from normal corpus
        if idx < self.inputs.len() {
            return Some(&self.inputs[idx]);
        }

        // Grab from sampled permanent inputs
        let mut pool_idx = idx - self.inputs.len();
        if pool_idx < self.sample_len {
            return self.sample_inputs[pool_idx].as_deref();
        }

        // Grab from hit-count descendants.
        pool_idx -= self.sample_len;
        if pool_idx < self.descendant_hitcounts.len() {
            return self.descendant_hitcounts.get(pool_idx).map(Vec::as_slice);
        }

        // Return from hit-count inputs generated without a parent.
        pool_idx -= self.descendant_hitcounts.len();
        self.generated_hitcounts.get(pool_idx).map(Vec::as_slice)
    }

    /// Gets an input from the corpus with pseudo uniform distribution
    pub fn get_input_uniform(&mut self, prng: usize) -> (usize, Option<&[u8]>) {
        // Seed our random
        self.prng = prng;

        // Determine ceiling index
        let ceiling = self.num_inputs();
        if ceiling == 0 {
            return (0, None);
        }

        // Treat all four pools as one logical corpus. Every individual input
        // therefore has the same chance of being selected.
        let idx = self.rand() % ceiling;

        // Return the selected input from the flattened corpus
        (idx, self.get_input_by_idx(idx))
    }

    /// Save an input to the corpus
    /// - Hash the input so we can focus on saving only unique inputs
    /// - Attempt to write the input to disk, but fail and warn the user if
    ///   we have already reached our findings limit
    ///
    /// It's important to note that if we fail to write the input to disk because
    /// of the findings limit, then we also don't save the input to memory
    pub fn save_input(&mut self, input: &Vec<u8>, reason: CorpusSaveReason) -> u64 {
        let hash = Self::hash_input(input);

        // Hit-count-only inputs stay local and never touch disk. Whether the
        // mutator selected a parent determines which bounded FIFO owns them.
        match reason {
            CorpusSaveReason::Hitcount { parent: Some(_) } => {
                self.save_descendant_hitcount(input);
                return hash;
            }
            CorpusSaveReason::Hitcount { parent: None } => {
                self.save_generated_hitcount(input);
                return hash;
            }
            CorpusSaveReason::Permanent => {}
        }

        // A worker can rediscover one of its seeds or one of its own findings.
        // Neither case should consume disk budget or create another corpus row.
        if self.input_hashes.contains(&hash) {
            return hash;
        }

        // Create the file path for the new input
        let file_path = std::path::Path::new(&self.inputs_dir).join(format!("{:016X}.input", hash));
        if file_path.exists() {
            return hash;
        }

        // Make sure we have enough space
        if input.len() > self.output_limit {
            finding_warn!(self.id, "Unable to save new input, output_limit exhausted!");
            return hash;
        }

        // Create the file exclusively. Multiple fuzzers share this directory,
        // so another worker can publish the same input after the check above.
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
        {
            Ok(file) => file,
            Err(e) => {
                // Another worker winning the create race is normal.
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    finding_warn!(self.id, "Unable to save new input to disk, error: {}", e);
                }
                return hash;
            }
        };

        if let Err(e) = file.write_all(input) {
            // This worker created the file, so it also owns cleanup if the
            // write failed before the input could be published.
            let _ = std::fs::remove_file(&file_path);
            finding_warn!(self.id, "Unable to save new input to disk, error: {}", e);
            return hash;
        }

        self.output_limit -= input.len();
        self.inputs.push(input.clone());
        self.corpus_size += input.len();
        self.input_hashes.insert(hash);

        hash
    }

    /// Hash an input using the corpus file-name hash.
    fn hash_input(input: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        hasher.finish()
    }

    /// Add a hit-count input descended from a selected corpus parent.
    fn save_descendant_hitcount(&mut self, input: &[u8]) {
        self.descendant_hitcounts.push_back(input.to_vec());
        self.corpus_size += input.len();

        // Permanent inputs are the only unbounded local pool. The descendant
        // allowance grows by one entry for every twenty permanent inputs.
        let limit = (self.inputs.len() as f64 * HITCOUNT_DESCENDANT_RATIO) as usize;
        while self.descendant_hitcounts.len() > limit {
            if let Some(removed) = self.descendant_hitcounts.pop_front() {
                self.corpus_size -= removed.len();
            }
        }
    }

    /// Add a hit-count input produced without selecting a corpus parent.
    fn save_generated_hitcount(&mut self, input: &[u8]) {
        self.generated_hitcounts.push_back(input.to_vec());
        self.corpus_size += input.len();

        while self.generated_hitcounts.len() > GENERATED_HITCOUNT_SIZE {
            if let Some(removed) = self.generated_hitcounts.pop_front() {
                self.corpus_size -= removed.len();
            }
        }
    }

    /// Save the PCs this input newly discovered beside the input itself.
    pub fn save_input_pcs(&mut self, hash: u64, pcs: &[u64]) {
        // Inputs that only gained a hit-count bucket remain local to this fuzzer
        if pcs.is_empty() {
            return;
        }

        // Never publish a sidecar unless the matching input was saved first
        let input_path =
            std::path::Path::new(&self.inputs_dir).join(format!("{:016X}.input", hash));
        if !input_path.exists() {
            return;
        }

        // Another fuzzer may have already published this exact input
        let pcs_path = std::path::Path::new(&self.inputs_dir).join(format!("{:016X}.pcs", hash));
        if pcs_path.exists() {
            return;
        }

        // Serialize the sorted PC set using the same little-endian u64 format
        // used by the campaign edge-PC databases
        let mut bytes = Vec::with_capacity(std::mem::size_of_val(pcs));
        for pc in pcs {
            bytes.extend_from_slice(&pc.to_le_bytes());
        }

        // Sidecars count against the same on-disk findings limit as inputs
        if bytes.len() > self.output_limit {
            finding_warn!(
                self.id,
                "Unable to save input PC sidecar, output_limit exhausted!"
            );
            return;
        }

        // Publish with rename so syncing fuzzers never observe a partial PC set
        let tmp_path = std::path::Path::new(&self.inputs_dir)
            .join(format!("{:016X}.pcs.{}.tmp", hash, self.id));
        let result = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .and_then(|mut file| file.write_all(&bytes))
            .and_then(|_| std::fs::rename(&tmp_path, &pcs_path));

        match result {
            Ok(_) => self.output_limit -= bytes.len(),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                finding_warn!(
                    self.id,
                    "Unable to save input PC sidecar {:016X}, error: {}",
                    hash,
                    e
                );
            }
        }
    }

    /// Save a crash
    /// - Hash the crash so we don't duplicate crashes on disk
    /// - Attempt to write the crash to disk, but fail and warn the user if
    ///   we have already reached our findings limit
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
    /// 8B5BB66137A8AA15.pcs
    fn extract_hash_from_filename(&self, path: &std::path::Path) -> Option<u64> {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| u64::from_str_radix(stem, 16).ok())
    }

    /// Shouldn't be necessary, but check to make sure it's a somewhat sane
    /// file before we try ingesting it during the corpus-syncing process
    fn is_valid_pc_file(&self, path: &std::path::Path) -> bool {
        path.is_file() && path.extension().is_some_and(|ext| ext == "pcs")
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
    fn sample_inputs_from_disk(&mut self, seen_pcs: &HashSet<u64>) {
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
            if !self.is_valid_pc_file(&path) {
                continue;
            }

            // Get the hash for file
            if let Some(hash) = self.extract_hash_from_filename(&path) {
                // If this is something we already have, continue
                if self.input_hashes.contains(&hash) {
                    continue;
                }

                // Decode this input's newly discovered PCs and skip it when this
                // fuzzer has already observed every one of them
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) if bytes.len() % PC_SIZE == 0 => bytes,
                    Ok(_) => {
                        finding_warn!(self.id, "Ignoring malformed PC sidecar {:016X}", hash);
                        continue;
                    }
                    Err(e) => {
                        finding_warn!(
                            self.id,
                            "Failed to read input PC sidecar {:016X}: {}",
                            hash,
                            e
                        );
                        continue;
                    }
                };
                let has_unseen_pc = bytes.chunks_exact(PC_SIZE).any(|bytes| {
                    let pc = u64::from_le_bytes(bytes.try_into().unwrap());
                    !seen_pcs.contains(&pc)
                });
                if !has_unseen_pc {
                    continue;
                }

                // The sidecar is the publication marker, so derive and verify
                // the matching input path only after its PCs pass the filter
                let input_path =
                    std::path::Path::new(&self.inputs_dir).join(format!("{:016X}.input", hash));
                if !input_path.is_file() {
                    finding_warn!(self.id, "PC sidecar {:016X} has no input", hash);
                    continue;
                }

                // Add this to the candidate pool
                candidates.push((hash, input_path));
            }
        }

        // Determine what selection mode we're in, if we have more candidates
        // than the max sample amount, we'll have to randomly select them
        if candidates.len() > SAMPLE_CORPUS_SIZE {
            // Randomly pick an input from the candidate pool
            while self.sample_len < SAMPLE_CORPUS_SIZE && !candidates.is_empty() {
                // Get idx
                let pick_idx = self.rand() % candidates.len();

                // Remove this candidate from the pool
                let (hash, path) = candidates.swap_remove(pick_idx);

                // If we already have this hash, skip, this should never happen!
                if !self.sample_hashes.insert(hash) {
                    finding_warn!(self.id, "Chosen candidate was in sample DB already");
                    continue;
                }

                self.load_sample_input(hash, &path);
            }
        }
        // We have enough room to take all candidates in sample
        else {
            for (hash, path) in candidates {
                if !self.sample_hashes.insert(hash) {
                    continue;
                }

                self.load_sample_input(hash, &path);
            }
        }
    }

    /// Load one sampled input into the next free slot in the fixed sample pool.
    fn load_sample_input(&mut self, hash: u64, path: &std::path::Path) {
        if self.sample_len == SAMPLE_CORPUS_SIZE {
            return;
        }

        match std::fs::read(path) {
            Ok(content) => {
                self.sample_inputs[self.sample_len] = Some(content);
                self.sample_len += 1;
            }
            Err(e) => {
                finding_warn!(self.id, "Failed to read input file {:016X}: {}", hash, e);
            }
        }
    }

    /// All fuzzers independently save their discovered inputs to the corpus
    /// directory for inputs. Each fuzzer will then have less inputs in their
    /// in-memory corpus than what exists on disk. Every sync_interval, the
    /// fuzzers will all scan the corpus directory for new inputs to potentially
    /// sample. Every sync they will clear out their sample queue and hashset
    pub fn sync(&mut self, prng: usize, seen_pcs: &HashSet<u64>) {
        // Check to see if we've reached re-sync time
        let now = Instant::now();
        if now < self.next_sync {
            return;
        }

        // Keep the configured period after the independently jittered first
        // sync. Anchor it to this check rather than the duration of the scan.
        self.next_sync = now + Duration::from_secs(self.sync_interval);

        // Set the prng
        self.prng = prng;

        // Clear the occupied portion of the fixed sample pool.
        for idx in 0..self.sample_len {
            self.sample_inputs[idx] = None;
        }
        self.sample_len = 0;
        self.sample_hashes.clear();

        // Scan PC sidecars and sample only inputs that carry a PC this fuzzer
        // has not observed, files have this format: `8B5BB66137A8AA15.pcs`
        self.sample_inputs_from_disk(seen_pcs);

        finding!(self.id, "Sampled {} inputs from disk", self.sample_len);
    }
}
