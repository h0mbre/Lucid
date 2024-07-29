//! This file contains all of the datastructures and logic necessary to create
//! and manage a corpus of inputs for fuzzing

use std::collections::HashSet;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::time::Instant;

use crate::config::Config;
use crate::err::LucidErr;
use crate::misc::MEG;
use crate::{finding, finding_warn, prompt_warn};

/// Holds all of the information and statistics we need in order to manage a
/// database of inputs, timeouts, and crashes.
#[derive(Clone)]
pub struct Corpus {
    pub inputs_dir: String,     // Where inputs are written to on disk
    pub crash_dir: String,      // Where crashes are written to on disk
    pub stats_dir: String,      // Where statistics are written to on disk
    pub inputs: Vec<Vec<u8>>,   // In memory input database
    input_hashes: HashSet<u64>, // Database of unique input hashes
    findings_limit: usize,      // The limit in megabytes of what we can save
    pub id: usize,              // Inherited from the LucidContext
    last_sync: Instant,         // The last time we synced from disk to memory
    sync_interval: u64,         // How often we sync the in-memory corpus with the disk
    pub corpus_size: usize,     // The number of bytes in the corpus
}

impl Corpus {
    /// Create a new Corpus based on configuration data
    pub fn new(config: &Config) -> Result<Self, LucidErr> {
        let mut inputs = Vec::new();
        let mut corpus_size = 0;

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
            findings_limit: config.findings_limit,
            id: 0,
            last_sync,
            sync_interval: config.sync_interval as u64,
            corpus_size,
        })
    }

    /// Return the number of inputs currently in the corpus in memory
    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Retrieves a reference to an input in the corpus or None if the corpus is
    /// empty
    pub fn get_input(&self, idx: usize) -> Option<&[u8]> {
        if idx < self.inputs.len() {
            return Some(&self.inputs[idx]);
        }

        None
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
        if input.len() > self.findings_limit {
            finding_warn!(
                self.id,
                "Unable to save new input, findings_limit exhausted!"
            );
            return hash;
        }

        // Attempt to save the input to disk
        match std::fs::write(file_path, input) {
            Ok(_) => {
                self.findings_limit -= input.len();
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
        if input.len() > self.findings_limit {
            finding_warn!(
                self.id,
                "Unable to save {} input, findings_limit exhausted!",
                filetype
            );
            return hash;
        }

        // Attempt to save the input to disk
        match std::fs::write(&file_path, input) {
            Ok(_) => {
                self.findings_limit -= input.len();
                // Copy the input bytes over in memory only if successfully saved to disk
                finding!(
                    self.id,
                    "Saved {} input: {:016X} ({} bytes)",
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

    /// Part of the corpus-syncing process, we add a new input that we found
    /// during the sync to the in-memory corpus and update our hash set accordingly
    fn add_new_input(&mut self, hash: u64, content: Vec<u8>) {
        self.inputs.push(content.clone());
        self.corpus_size += content.len();
        self.input_hashes.insert(hash);

        finding!(
            self.id,
            "Corpus sync netted new input {:016X} (Corpus: {} inputs, {:.2}MB)",
            hash,
            self.inputs.len(),
            self.corpus_size as f64 / MEG as f64
        )
    }

    /// Part of the corpus-syncing process, attempt to read the content of a
    /// file in the corpus
    fn process_input_file(&mut self, hash: u64, path: &std::path::Path) {
        if self.input_hashes.contains(&hash) {
            return;
        }

        match std::fs::read(path) {
            Ok(content) => self.add_new_input(hash, content),
            Err(e) => finding_warn!(self.id, "Failed to read input file {:016X}: {}", hash, e),
        }
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

    /// Process a single directory entry during the corpus-syncing process
    fn process_directory_entry(&mut self, entry: std::io::Result<std::fs::DirEntry>) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                finding_warn!(self.id, "Failed to read directory entry: {}", e);
                return;
            }
        };

        let path = entry.path();
        if !self.is_valid_input_file(&path) {
            return;
        }

        if let Some(hash) = self.extract_hash_from_filename(&path) {
            self.process_input_file(hash, &path);
        }
    }

    /// Thin wrapper around reading the corpus directory entries during the
    /// corpus-syncing process
    fn read_input_directory(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.inputs_dir)
    }

    /// During the corpus-syncing process, scan the corpus directory for new
    /// inputs that we don't have in our in-memory corpus that the other fuzzers
    /// have found and saved, then ingest them into our in-memory corpus
    fn sync_inputs_from_disk(&mut self) {
        let entries = match self.read_input_directory() {
            Ok(entries) => entries,
            Err(e) => {
                finding_warn!(self.id, "Failed to read inputs directory: {}", e);
                return;
            }
        };

        for entry in entries {
            self.process_directory_entry(entry);
        }
    }

    /// All fuzzers independently save their discovered inputs to the corpus
    /// directory for inputs. Each fuzzer will then have less inputs in their
    /// in-memory corpus than what exists on disk. Every sync_interval, the
    /// fuzzers will all scan the corpus directory for new inputs that they
    /// don't have in their in-memory corpus and ingest them
    pub fn sync(&mut self) {
        // Check to see if we've reached re-sync time
        if self.last_sync.elapsed().as_secs() < self.sync_interval {
            return;
        }

        finding!(self.id, "Syncing corpus...");

        // Read all of the filenames in the corpus directory and add them
        // to the corpus if we don't have the hash in the database, files have
        // this format: `8B5BB66137A8AA15.input`
        self.sync_inputs_from_disk();
        self.last_sync = Instant::now();
    }
}
