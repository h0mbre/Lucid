//! Full PC tracing for inputs that discover new edge coverage.
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2026 h0mbre

use crate::context::LucidContext;
use crate::err::LucidErr;
use crate::mega_panic;
use std::collections::HashSet;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Must match the capacity of the static buffer in patched Bochs.
const PC_BATCH_CAPACITY: usize = 1 << 16;
/// Size of each PC record in the on-disk coverage databases.
const PC_SIZE: u64 = std::mem::size_of::<u64>() as u64;

/// Per-process trace collection and manager-side campaign consolidation.
pub struct TraceCov {
    trace_dir: PathBuf,           // Directory that holds all PC databases
    worker_id: usize,             // ID for this fuzzer process
    worker_count: usize,          // Total number of fuzzer processes
    current_trace: HashSet<u64>,  // PCs reported during the current replay
    worker_seen: HashSet<u64>,    // PCs already saved by this fuzzer
    global_seen: HashSet<u64>,    // PCs already saved in the global database
    worker_offsets: Vec<u64>,     // Last processed file offset for each fuzzer
}

impl TraceCov {
    pub fn new(output_dir: &str, worker_count: usize) -> Result<Self, LucidErr> {
        // Create the directory that holds the per-fuzzer and global databases
        let trace_dir = Path::new(output_dir).join("coverage");
        create_dir_all(&trace_dir).map_err(|e| {
            LucidErr::from(&format!(
                "Unable to create coverage trace directory '{}': {}",
                trace_dir.display(),
                e
            ))
        })?;

        // Initialize this process as fuzzer zero until its ID is updated
        let mut trace_cov = Self {
            trace_dir,
            worker_id: 0,
            worker_count,
            current_trace: HashSet::new(),
            worker_seen: HashSet::new(),
            global_seen: HashSet::new(),
            worker_offsets: vec![0; worker_count],
        };

        // Reload any coverage databases that already exist in the output folder
        trace_cov.global_seen = Self::read_pc_file(&trace_cov.global_path())?;
        trace_cov.worker_seen = Self::read_pc_file(&trace_cov.worker_path(0))?;
        Ok(trace_cov)
    }

    /// Select the per-worker artifact after a fuzzer child has been forked.
    pub fn update_id(&mut self, id: usize) -> Result<(), LucidErr> {
        // Select this fuzzer's database and reload all of its existing PCs
        self.worker_id = id;
        self.worker_seen = Self::read_pc_file(&self.worker_path(id))?;
        Ok(())
    }

    /// Discard data from a previous trace before replaying an interesting input.
    pub fn begin_trace(&mut self) {
        self.current_trace.clear();
    }

    /// Receive one bounded batch from Bochs and deduplicate it in memory.
    fn report_batch(&mut self, pcs: &[u64]) {
        self.current_trace.extend(pcs.iter().copied());
    }

    /// Append PCs newly observed by this worker to its raw little-endian blob.
    pub fn finish_trace(&mut self) -> Result<usize, LucidErr> {
        // Keep only PCs that have not already been saved by this fuzzer
        let mut new_pcs: Vec<u64> = self
            .current_trace
            .drain()
            .filter(|pc| self.worker_seen.insert(*pc))
            .collect();

        // Sort the PCs for stable output and append them to the database
        new_pcs.sort_unstable();
        Self::append_pcs(&self.worker_path(self.worker_id), &new_pcs)?;
        Ok(new_pcs.len())
    }

    /// Merge each worker's append-only blob into the manager-owned global blob.
    pub fn consolidate(&mut self) -> Result<usize, LucidErr> {
        // Collect PCs that have not already been saved in the global database
        let mut new_global = Vec::new();

        // Check the unread portion of every fuzzer's coverage database
        for id in 0..self.worker_count {
            let path = self.worker_path(id);

            // A missing database simply means this fuzzer has not found an edge
            let mut file = match File::open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(Self::file_error("open", &path, error)),
            };

            // Limit reads to complete u64 records that have not been seen yet
            let file_len = file
                .metadata()
                .map_err(|e| Self::file_error("inspect", &path, e))?
                .len();
            let complete_len = file_len - (file_len % PC_SIZE);
            let offset = self.worker_offsets[id].min(complete_len);
            if offset == complete_len {
                continue;
            }

            // Read the newly appended records and advance this fuzzer's offset
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| Self::file_error("seek", &path, e))?;
            let mut bytes = vec![0; (complete_len - offset) as usize];
            file.read_exact(&mut bytes)
                .map_err(|e| Self::file_error("read", &path, e))?;
            self.worker_offsets[id] = complete_len;

            // Decode and deduplicate the new PCs against the global database
            for bytes in bytes.chunks_exact(std::mem::size_of::<u64>()) {
                let pc = u64::from_le_bytes(bytes.try_into().unwrap());
                if self.global_seen.insert(pc) {
                    new_global.push(pc);
                }
            }
        }

        // Append the newly discovered PCs to the global coverage database
        Self::append_pcs(&self.global_path(), &new_global)?;
        Ok(new_global.len())
    }

    /// Get the path to a fuzzer's individual PC database.
    fn worker_path(&self, id: usize) -> PathBuf {
        self.trace_dir.join(format!("fuzzer-{}.coverage", id))
    }

    /// Get the path to the consolidated global PC database.
    fn global_path(&self) -> PathBuf {
        self.trace_dir.join("global.coverage")
    }

    /// Read an existing PC database into a deduplicated in-memory set.
    fn read_pc_file(path: &Path) -> Result<HashSet<u64>, LucidErr> {
        // Open the database if it exists, otherwise begin with an empty set
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(HashSet::new());
            }
            Err(error) => return Err(Self::file_error("open", path, error)),
        };

        // Reject truncated databases instead of silently discarding bytes
        let len = file
            .metadata()
            .map_err(|e| Self::file_error("inspect", path, e))?
            .len();
        if len % PC_SIZE != 0 {
            return Err(LucidErr::from(&format!(
                "Coverage trace file '{}' has a partial u64",
                path.display()
            )));
        }

        // Read and decode every little-endian u64 PC into a deduplicated set
        let mut bytes = Vec::with_capacity(len as usize);
        file.read_to_end(&mut bytes)
            .map_err(|e| Self::file_error("read", path, e))?;
        Ok(bytes
            .chunks_exact(std::mem::size_of::<u64>())
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .collect())
    }

    /// Append a batch of PCs to an on-disk coverage database.
    fn append_pcs(path: &Path, pcs: &[u64]) -> Result<(), LucidErr> {
        // Avoid opening the database when there is nothing new to append
        if pcs.is_empty() {
            return Ok(());
        }

        // Reserve the exact byte size of the PC slice to avoid reallocating while serializing
        let mut bytes = Vec::with_capacity(std::mem::size_of_val(pcs));

        // Serialize every PC as an explicitly little-endian u64
        for pc in pcs {
            bytes.extend_from_slice(&pc.to_le_bytes());
        }

        // Append the entire batch without rewriting the existing database
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(&bytes))
            .map_err(|e| Self::file_error("append to", path, e))
    }

    /// Format an I/O error with the affected coverage database path.
    fn file_error(operation: &str, path: &Path, error: std::io::Error) -> LucidErr {
        LucidErr::from(&format!(
            "Unable to {} coverage trace file '{}': {}",
            operation,
            path.display(),
            error
        ))
    }
}

/// Called by patched Bochs whenever its static PC batch is full or flushed.
pub extern "C" fn lucid_report_pcs(
    contextp: *mut LucidContext,
    pcs: *const u64,
    count: usize,
) {
    // Validate every value received across the Bochs callback boundary
    if !LucidContext::is_valid(contextp)
        || pcs.is_null()
        || count == 0
        || count > PC_BATCH_CAPACITY
    {
        mega_panic!("Invalid PC trace report\n");
    }

    // Convert the Bochs buffer to a slice and add it to the current trace
    let context = LucidContext::from_ptr_mut(contextp);
    let pcs = unsafe { std::slice::from_raw_parts(pcs, count) };
    context.trace_cov.report_batch(pcs);
}
