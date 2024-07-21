//! This file contains all of the datastructures and logic necessary to create
//! and manage a corpus of inputs for fuzzing

use std::collections::HashSet;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::time::Instant;

use crate::config::Config;
use crate::err::LucidErr;
use crate::{finding, finding_warn, prompt, prompt_warn};

// The default maximum amount of findings we can use in disk space
const DEFAULT_FINDINGS_MAX: usize = 1_000_000_000;
const MEG: usize = 1_000_000;

#[derive(Clone)]
pub struct Corpus {
    pub inputs_dir: String,
    pub crash_dir: String,
    pub stats_dir: String,
    pub inputs: Vec<Vec<u8>>,
    input_hashes: HashSet<u64>,
    findings_limit: usize,
    pub id: usize,
    last_sync: Instant,
    sync_interval: u64,
    corpus_size: usize,
}

impl Corpus {
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

        // Try to create directories
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

        // Check to see if there was a limit specified
        let findings_limit = if config.findings_limit.is_some() {
            let limit = config.findings_limit.unwrap().wrapping_mul(MEG);
            prompt!("Findings limit set to {}MB", limit / MEG);
            limit
        } else {
            prompt_warn!(
                "No findings limit specified, defaulting to {}MB",
                DEFAULT_FINDINGS_MAX / MEG
            );
            DEFAULT_FINDINGS_MAX
        };

        // Count this now as our last sync
        let last_sync = Instant::now();

        Ok(Corpus {
            inputs_dir,
            crash_dir,
            stats_dir,
            inputs,
            input_hashes: HashSet::new(),
            findings_limit,
            id: 0,
            last_sync,
            sync_interval: config.sync_interval as u64,
            corpus_size,
        })
    }

    // Used by mutator to get an index to pick an input to use
    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    // Used by mutator to get an input
    pub fn get_input(&self, idx: usize) -> Option<&[u8]> {
        if idx < self.inputs.len() {
            return Some(&self.inputs[idx]);
        }

        None
    }

    // Used to save a new input
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
                finding!(
                    self.id,
                    "Saved new input: {:016X} (Corpus: {} inputs, {:.2}MB)",
                    hash,
                    self.inputs.len(),
                    self.corpus_size as f64 / MEG as f64,
                );

                // Add the hash to the database
                self.input_hashes.insert(hash);
            }
            Err(e) => {
                finding_warn!(self.id, "Unable to save new input to disk, error: {}", e);
            }
        }

        hash
    }

    // Used to save a crashing input
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

    // Add a synced file to the corpus
    fn add_new_input(&mut self, hash: u64, content: Vec<u8>) {
        self.inputs.push(content.clone());
        self.corpus_size += content.len();
        self.input_hashes.insert(hash);

        finding!(
            self.id,
            "Corpus sync netted new input {:016X} (Corpus: {} inputs, {:.2}MB)",
            hash,
            self.inputs.len(),
            self.corpus_size as f64 / MEG as f64)
    }

    // Process a single input file to retrieve its contents
    fn process_input_file(&mut self, hash: u64, path: &std::path::Path) {
        if self.input_hashes.contains(&hash) {
            return;
        }

        match std::fs::read(path) {
            Ok(content) => self.add_new_input(hash, content),
            Err(e) => finding_warn!(self.id, "Failed to read input file {:016X}: {}", hash, e),
        }
    }

    // Helper to retrieve a file hash from the input file name itself, cool!
    fn extract_hash_from_filename(&self, path: &std::path::Path) -> Option<u64> {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| u64::from_str_radix(stem, 16).ok())
    }

    // Helper to determine if file in inputs dir is from us and valid
    fn is_valid_input_file(&self, path: &std::path::Path) -> bool {
        path.is_file() && path.extension().map_or(false, |ext| ext == "input")
    }

    // Process a single directory entry, make sure its a valid path/file, extract
    // the hash for the file from the file name and then send it off for
    // further processing
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

    // Tiny helper to read a directory for entries
    fn read_input_directory(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.inputs_dir)
    }

    // Get the entries from the inputs dir and send each one off for processing
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

    // Sync with the corpus on disk if it's time
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
