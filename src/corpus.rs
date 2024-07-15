/// This file contains all of the datastructures and logic necessary to create
/// and manage a corpus of inputs for fuzzing
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;

use crate::config::Config;
use crate::err::LucidErr;
use crate::{prompt, prompt_warn};

// The default maximum amount of findings we can use in disk space
const DEFAULT_FINDINGS_MAX: usize = 1_000_000_000;
const MEG: usize = 1_000_000;

#[derive(Clone)]
pub struct Corpus {
    pub inputs_dir: String,
    pub crash_dir: String,
    pub inputs: Vec<Vec<u8>>,
    findings_limit: usize,
}

impl Corpus {
    pub fn new(config: &Config) -> Result<Self, LucidErr> {
        let mut inputs = Vec::new();

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
                        inputs.push(file_buf);
                    }
                }
            }
        }

        // Formulate dir names
        let inputs_dir = format!("{}/inputs", config.output_dir);
        let crash_dir = format!("{}/crashes", config.output_dir);

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

        Ok(Corpus {
            inputs_dir,
            crash_dir,
            inputs,
            findings_limit,
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

        // Make sure we have enough space
        if input.len() > self.findings_limit {
            prompt_warn!("Unable to save new input, findings_limit exhausted!");
            return hash;
        }

        // Attempt to save the input to disk
        match std::fs::write(file_path, input) {
            Ok(_) => {
                self.findings_limit -= input.len();
                // Copy the input bytes over in memory only if successfully saved to disk
                self.inputs.push(input.clone());
                prompt!("Saved new input: {:016X} ({} bytes)", hash, input.len());
            }
            Err(e) => {
                prompt_warn!("Unable to save new input to disk, error: {}", e);
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
            prompt_warn!(
                "Skipping {} input save, {:016X} already exists",
                filetype,
                hash
            );
            return hash;
        }

        // Make sure we have enough space
        if input.len() > self.findings_limit {
            prompt_warn!(
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
                prompt!(
                    "Saved {} input: {:016X} ({} bytes)",
                    filetype,
                    hash,
                    input.len()
                );
            }
            Err(e) => {
                prompt_warn!("Unable to save {} input to disk, error: {}", filetype, e);
            }
        }

        hash
    }
}
