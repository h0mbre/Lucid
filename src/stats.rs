//! This file contains all of the code for keeping stats for the current session
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use chrono::Local;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::err::LucidErr;
use crate::misc::MEG;

/// Helper function to format a group of stats for printing to the terminal
fn format_group(title: &str, stats: &[(String, String)]) -> String {
    let stats_str = stats
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join(" | ");
    format!("\x1b[1;32m{}:\x1b[0m {}", title, stats_str)
}

/// What kind of mode are fuzzing in determines how stats are processed and
/// collected
#[derive(Clone, Default)]
enum ReportMode {
    #[default]
    Single,
    Multi,
}

/// Represents statistics from the Snapshot structure that we're interested in
/// keeping track of, we want to know about the dirty page metrics since these
/// will vary wildly amongst targets and we might eventually optionally want to
/// set a threshold for dirty pages when we switch strategies
#[derive(Clone, Copy)]
pub struct SnapshotStats {
    pub dirty_pages: usize,
    pub memcpys: usize,
}

/// Represents the stastistics from the Corpus structure that we're interested in
/// keeping track of
#[derive(Clone, Copy)]
pub struct CorpusStats {
    pub entries: usize,
    pub size: usize,
    pub max_input: usize,
}

/// Represents the statistics that fuzzers need to serialize to disk if fuzzing
/// is multi-process. The report number is written first and last as a cheap
/// file lock so the reader knows that if those are mismatched to re-read
#[derive(Clone, Copy, Default, Debug)]
#[repr(C, packed)]
struct SerialStats {
    report: usize, // Has to be the first member
    iters: usize,
    crashes: usize,
    timeouts: usize,
    edges: usize,
    total_time: u64,
    reset_time: u64,
    mutator_time: u64,
    target_time: u64,
    coverage_time: u64,
    redqueen_time: u64,
    dirty_pages: usize,
    memcpys: usize,
    corpus_entries: usize,
    corpus_size: usize,
    report_checksum: usize, // Has to be the last member
}

impl SerialStats {
    /// Creates a serialized statistics structure from an existing Stats structure
    pub fn from_stats(stats: &Stats) -> Self {
        // Calculate total time
        let total_time = if let Some(start) = stats.session_start {
            start.elapsed().as_millis() as u64
        } else {
            0
        };

        SerialStats {
            report: stats.report,
            iters: stats.session_iters,
            crashes: stats.crashes,
            timeouts: stats.timeouts,
            edges: stats.edges,
            total_time,
            reset_time: stats.batch_reset.as_millis() as u64,
            mutator_time: stats.batch_mutator.as_millis() as u64,
            target_time: stats.batch_target.as_millis() as u64,
            coverage_time: stats.batch_coverage.as_millis() as u64,
            redqueen_time: stats.batch_redqueen.as_millis() as u64,
            dirty_pages: stats.dirty_pages,
            memcpys: stats.memcpys,
            corpus_entries: stats.corpus_entries,
            corpus_size: stats.corpus_size,
            report_checksum: stats.report,
        }
    }

    /// Creates a diff between an old SerialStats structure and the current
    /// structure, this is used to simulate the concept of a "batch" that exists
    /// when fuzzing single-process
    pub fn diff(&self, old: SerialStats) -> Self {
        SerialStats {
            report: self.report,
            iters: self.iters - old.iters,
            crashes: self.crashes,
            timeouts: self.timeouts,
            edges: self.edges,
            total_time: self.total_time - old.total_time,
            reset_time: self.reset_time - old.reset_time,
            mutator_time: self.mutator_time - old.mutator_time,
            target_time: self.target_time - old.target_time,
            coverage_time: self.coverage_time - old.coverage_time,
            redqueen_time: self.redqueen_time - old.redqueen_time,
            dirty_pages: self.dirty_pages,
            memcpys: self.memcpys,
            corpus_entries: self.corpus_entries,
            corpus_size: self.corpus_size,
            report_checksum: self.report,
        }
    }
}

/// A data structure for statistics that have already been formatted and can
/// be displayed (printed to terminal)
struct FormattedStats {
    uptime: String,
    fuzzers: usize,
    iters: String,
    iters_per_sec: f64,
    iters_per_sec_fuzzer: f64,
    crashes: usize,
    timeouts: usize,
    edges: usize,
    last_find: String,
    map_coverage: f64,
    cpu_target: f64,
    cpu_reset: f64,
    cpu_mutator: f64,
    cpu_coverage: f64,
    cpu_redqueen: f64,
    cpu_misc: f64,
    dirty_pages: usize,
    dirty_percent: f64,
    memcpys: usize,
    corpus_entries: usize,
    corpus_size: f64,
    max_input: usize,
}

/// Statistics that help end-users make sense of the current fuzzing setup
#[derive(Clone, Default)]
pub struct Stats {
    // Stats for the entire campaign so far
    report: usize,                  // Current report number
    pub start_str: String,          // String repr of date start
    pub session_iters: usize,       // Total fuzzcases
    session_start: Option<Instant>, // Start time
    last_find: Option<Instant>,     // Last new coverage find
    last_find_iters: usize,         // Iters since last new coverage find
    pub crashes: usize,             // Number of crashes
    pub timeouts: usize,            // Number of timeouts
    pub fuzzers: usize,             // Number of fuzzers
    report_mode: ReportMode,        // Type of reporting to do as fuzzer
    pub id: usize,                  // Fuzzer id
    pub stat_file: Option<String>,  // Path to stat file if we need one

    // Snapshot related metrics
    pub dirty_pages: usize,    // Number of dirty pages we're restoring
    dirty_block_length: usize, // Length of the dirty page range
    pub memcpys: usize,        // Number of memcpys we're doing for resets

    // Corpus related metrics
    corpus_entries: usize, // Number of inputs
    corpus_size: usize,    // Size of all the inputs in bytes
    max_input: usize,      // The configuration for max input allowed

    // Stats for local batch reporting
    batch_iters: usize,           // Batch fuzzcases
    batch_start: Option<Instant>, // Batch start
    pub batch_reset: Duration,    // Batch time spent in reset
    pub batch_mutator: Duration,  // Batch time spent in mutator
    pub batch_target: Duration,   // Batch time spent in target
    pub batch_coverage: Duration, // Batch time spent in coverage
    pub batch_redqueen: Duration, // Batch time spent in redqueen
    pub oldest_batch: Duration,   // Oldest batch duration in multi-process

    pub edges: usize,        // Number of edges we've hit
    map_size: usize,         // Size of coverage map
    pub stat_interval: u128, // How often we report stats in millis

    // For the multi-process stat reporter
    multi_batch_stats: Vec<SerialStats>,
}

impl Stats {
    /// Creates a new Stats structure based on the provided Config
    pub fn new(config: &Config, dirty_block_length: usize, input_max_size: usize) -> Self {
        // Determine mode
        let report_mode = match config.num_fuzzers {
            1 => ReportMode::Single,
            _ => ReportMode::Multi,
        };

        Stats {
            stat_interval: config.stat_interval,
            fuzzers: config.num_fuzzers,
            report_mode,
            id: 0,
            dirty_block_length,
            max_input: input_max_size,
            ..Default::default()
        }
    }

    /// Returns the duration since the last new coverage was found.
    /// If no coverage has ever been found, returns None.
    fn since_last_find(&self) -> Option<Duration> {
        self.last_find.map(|t| t.elapsed())
    }

    /// Helper: returns true if we've been starved for coverage longer than `threshold`.
    pub fn starved_for(&self, threshold: Duration) -> bool {
        match self.since_last_find() {
            Some(dur) => dur >= threshold,
            None => false,
        }
    }

    /// Converts a Stats structure to a FormattedStats structure so that the
    /// statistics can be printed to the terminal
    fn generate_formatted_stats(&self) -> FormattedStats {
        // Format the Global values
        let total_elapsed = self.session_start.unwrap().elapsed();
        let total_seconds = total_elapsed.as_secs();
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;

        let lf_elapsed = self.last_find.unwrap().elapsed().as_secs();
        let lf_hours = lf_elapsed / 3600;
        let lf_minutes = (lf_elapsed % 3600) / 60;
        let lf_secs = lf_elapsed % 60;

        // Format the last find iters
        let lf_iters = match self.last_find_iters {
            0..=999 => format!("{}", self.last_find_iters),
            1_000..=999_999 => format!("{:.2}K", self.last_find_iters as f64 / 1_000.0),
            _ => format!("{:.3}M", self.last_find_iters as f64 / 1_000_000.0),
        };

        // For single process
        let batch_elapsed = self.batch_start.unwrap().elapsed();
        let batch_millis = batch_elapsed.as_millis() as f64;
        let batch_seconds = batch_millis / 1000.0;

        // For multi-process
        let oldest_millis = self.oldest_batch.as_millis() as f64;
        let oldest_seconds = oldest_millis / 1000.0;

        // Iters/s is based on report mode
        let iters_sec = if matches!(self.report_mode, ReportMode::Single) {
            self.batch_iters as f64 / batch_seconds
        } else {
            self.batch_iters as f64 / oldest_seconds
        };

        // Calculate Iters/s per fuzzer
        let iters_sec_fuzzer = iters_sec / self.fuzzers as f64;

        // Generate the dynamic iters/s string value to print
        let iters_str = match self.session_iters {
            0..=999 => format!("{}", self.session_iters),
            1_000..=999_999 => format!("{:.2}K", self.session_iters as f64 / 1_000.0),
            _ => format!("{:.3}M", self.session_iters as f64 / 1_000_000.0),
        };

        // Generate the batch's CPU time spent where values
        let cpu_target = (self.batch_target.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_reset = (self.batch_reset.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_mutator = (self.batch_mutator.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_coverage = (self.batch_coverage.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_redqueen = (self.batch_redqueen.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_misc = 100.0 - (cpu_target + cpu_reset + cpu_mutator + cpu_coverage + cpu_redqueen);

        // Calculate snapshot dirty page metrics
        let dirty_pages = self.dirty_pages;
        let dirty_percent = (self.dirty_pages as f64 / self.dirty_block_length as f64) * 100.0;
        let memcpys = self.memcpys;

        // Calculate corpus metrics
        let corpus_size = self.corpus_size as f64 / MEG as f64;

        // Create FormattedStats structure for printing
        FormattedStats {
            uptime: format!("{}d {}h {}m {}s", days, hours, minutes, seconds),
            fuzzers: self.fuzzers,
            iters: iters_str,
            iters_per_sec: iters_sec,
            iters_per_sec_fuzzer: iters_sec_fuzzer,
            crashes: self.crashes,
            timeouts: self.timeouts,
            edges: self.edges,
            last_find: format!(
                "{}h {}m {}s, {} iters",
                lf_hours, lf_minutes, lf_secs, lf_iters
            ),
            map_coverage: (self.edges as f64 / self.map_size as f64) * 100.0,
            cpu_target,
            cpu_reset,
            cpu_mutator,
            cpu_coverage,
            cpu_redqueen,
            cpu_misc,
            dirty_pages,
            dirty_percent,
            memcpys,
            corpus_entries: self.corpus_entries,
            corpus_size,
            max_input: self.max_input,
        }
    }

    /// Prints stats to the terminal
    pub fn print_stats(&self) {
        // Format the stats into a FormattedStats struct for easy printing
        let formatted_stats = self.generate_formatted_stats();

        // Print banner
        println!(
            "\n\x1b[1;35m[lucid stats (start time: {})]\x1b[0m",
            self.start_str
        );

        // Highlight crashes and timeouts as red/yellow respectively
        fn colorize_number(label: &str, value: usize) -> String {
            match label {
                "crashes" if value > 0 => format!("\x1b[1;31m{}\x1b[0m", value),
                "timeouts" if value > 0 => format!("\x1b[1;33m{}\x1b[0m", value),
                _ => value.to_string(),
            }
        }

        // Print all the global statistics
        let globals = [
            ("uptime".to_string(), formatted_stats.uptime),
            ("fuzzers".to_string(), formatted_stats.fuzzers.to_string()),
            (
                "crashes".to_string(),
                colorize_number("crashes", formatted_stats.crashes),
            ),
            (
                "timeouts".to_string(),
                colorize_number("timeouts", formatted_stats.timeouts),
            ),
        ];
        println!("{}", format_group("globals", &globals));

        // Print all the perf stuff
        let perf = [
            ("iters".to_string(), formatted_stats.iters),
            (
                "iters/s".to_string(),
                format!("{:.2}", formatted_stats.iters_per_sec),
            ),
            (
                "iters/s/f".to_string(),
                format!("{:.2}", formatted_stats.iters_per_sec_fuzzer),
            ),
        ];
        println!("{}", format_group("perf", &perf));

        // Print where we're spending our CPU time
        let cpu = [
            (
                "target".to_string(),
                format!("{:.1}%", formatted_stats.cpu_target),
            ),
            (
                "reset".to_string(),
                format!("{:.1}%", formatted_stats.cpu_reset),
            ),
            (
                "mutator".to_string(),
                format!("{:.1}%", formatted_stats.cpu_mutator),
            ),
            (
                "coverage".to_string(),
                format!("{:.1}%", formatted_stats.cpu_coverage),
            ),
            (
                "redqueen".to_string(),
                format!("{:.1}%", formatted_stats.cpu_redqueen),
            ),
            (
                "misc".to_string(),
                format!("{:.1}%", formatted_stats.cpu_misc),
            ),
        ];
        println!("{}", format_group("cpu", &cpu));

        // Print coverage metrics
        let coverage = [
            ("edges".to_string(), formatted_stats.edges.to_string()),
            ("last find".to_string(), formatted_stats.last_find),
            (
                "map".to_string(),
                format!("{:.2}%", formatted_stats.map_coverage),
            ),
        ];
        println!("{}", format_group("coverage", &coverage));

        // Print the dirty memory snapshot metrics
        let snapshot = [
            (
                "dirty pages".to_string(),
                format!("{}", formatted_stats.dirty_pages),
            ),
            (
                "dirty / total".to_string(),
                format!("{:.5}%", formatted_stats.dirty_percent),
            ),
            (
                "reset memcpys".to_string(),
                format!("{}", formatted_stats.memcpys),
            ),
        ];
        println!("{}", format_group("snapshot", &snapshot));

        // Print the corpus metrics
        let corpus = [
            (
                "inputs".to_string(),
                format!("{}", formatted_stats.corpus_entries),
            ),
            (
                "corpus size (MB)".to_string(),
                format!("{:.3}", formatted_stats.corpus_size),
            ),
            (
                "max input".to_string(),
                format!("0x{:X}", formatted_stats.max_input),
            ),
        ];
        println!("{}", format_group("corpus", &corpus));
    }

    /// Initializes global stat values such as the start time of the fuzzing
    /// campaign
    #[inline]
    pub fn start_session(
        &mut self,
        map_size: usize,
        dirty_block_length: usize,
        input_max_size: usize,
    ) {
        self.start_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.session_start = Some(Instant::now());
        self.batch_start = Some(Instant::now());
        self.last_find = Some(Instant::now());
        self.last_find_iters = 0;
        self.map_size = map_size;
        self.dirty_block_length = dirty_block_length;
        self.max_input = input_max_size;
    }

    /// Update stats after a single fuzzcase
    #[inline]
    pub fn update(&mut self, snapshot: SnapshotStats, corpus: CorpusStats) {
        // We just completed a single fuzzcase
        self.session_iters += 1;
        self.batch_iters += 1;
        self.last_find_iters += 1;

        // Update the snapshot statistics
        self.dirty_pages = snapshot.dirty_pages;
        self.memcpys = snapshot.memcpys;

        // Update the corpus statistics
        self.corpus_entries = corpus.entries;
        self.corpus_size = corpus.size;
        self.max_input = corpus.max_input;
    }

    /// Check to see if enough time has elapsed to print the current batch of
    /// statistics when fuzzing in single-process mode
    fn report_ready_single(&self) -> bool {
        if let Some(batch_start) = self.batch_start {
            batch_start.elapsed().as_millis() > self.stat_interval
        } else {
            false
        }
    }

    /// Check to see if enough time has elapsed to print the current batch
    /// of statistics when fuzzing in multi-process mode
    fn report_ready_multi(&mut self) -> bool {
        if let Some(batch_start) = self.batch_start {
            if batch_start.elapsed().as_millis() > self.stat_interval {
                self.batch_start = Some(Instant::now());

                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Check to see if it's time to report statistics for the current batch
    pub fn report_ready(&mut self) -> bool {
        if matches!(self.report_mode, ReportMode::Single) {
            self.report_ready_single()
        } else {
            self.report_ready_multi()
        }
    }

    /// Update stats when new coverage has been detected
    pub fn new_coverage(&mut self, edges: usize) {
        self.edges = edges;
        self.last_find = Some(Instant::now());
        self.last_find_iters = 0;
    }

    /// Report stats in single-process fuzzing
    fn report_single(&mut self) -> Result<(), LucidErr> {
        // Print our stats
        self.print_stats();

        // Reset batch
        self.batch_iters = 0;
        self.batch_start = Some(Instant::now());
        self.batch_reset = Duration::new(0, 0);
        self.batch_mutator = Duration::new(0, 0);
        self.batch_target = Duration::new(0, 0);
        self.batch_coverage = Duration::new(0, 0);
        self.batch_redqueen = Duration::new(0, 0);

        Ok(())
    }

    /// Report stats in multi-process fuzzing. Each fuzzer has its own file
    /// in the output directory where it serializes its statistics to disk and
    /// the main stat reporting thread will synthesize all of the statistics
    /// for each fuzzer into a single report
    pub fn report_multi(&self) -> Result<(), LucidErr> {
        // Make sure we have a stat file
        let stat_file = self
            .stat_file
            .as_ref()
            .ok_or_else(|| LucidErr::from("Stat file path not set"))?;

        // Create a serializable struct
        let serial_stats = SerialStats::from_stats(self);

        // Open the file for writing
        let mut file = File::create(stat_file).map_err(|e| LucidErr::from(&e.to_string()))?;

        // Write the entire struct at once
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&serial_stats as *const SerialStats) as *const u8,
                std::mem::size_of::<SerialStats>(),
            )
        };

        // Write the bytes
        file.write_all(bytes)
            .map_err(|e| LucidErr::from(&e.to_string()))?;

        // Ensure all data is written to disk
        file.sync_all()
            .map_err(|e| LucidErr::from(&e.to_string()))?;

        Ok(())
    }

    /// Display stats
    pub fn report(&mut self) -> Result<(), LucidErr> {
        // Annotate report number
        self.report += 1;

        // Determine what type of stat reporting we're doing
        if matches!(self.report_mode, ReportMode::Single) {
            self.report_single()
        } else {
            self.report_multi()
        }
    }

    /// Used by main stat reporting process in multi-process fuzzing mode to
    /// read the SerialStats for a specific fuzzer from its stat file
    fn read_stat_file(&self, output_dir: &str, id: usize) -> Result<SerialStats, LucidErr> {
        // Create stat file
        let stat_file = format!("{}/stats/fuzzer-{}.stats", output_dir, id);

        // Open file
        let mut file = File::open(stat_file).map_err(|e| LucidErr::from(&e.to_string()))?;

        // Buffer to hold the contents of the struct
        let mut buffer = [0u8; std::mem::size_of::<SerialStats>()];

        // We read in a loop because the stat struct is led by, and ended by
        // the report number, we make sure those match and we didn't race before
        // we know we have a good file read
        loop {
            // We may read more than once, so this is necessary
            file.seek(SeekFrom::Start(0))
                .map_err(|e| LucidErr::from(&e.to_string()))?;

            // Read the bytes
            file.read_exact(&mut buffer)
                .map_err(|e| LucidErr::from(&e.to_string()))?;

            // Cast the bytes to a SerialStats struct
            let stats = unsafe { *(buffer.as_ptr() as *const SerialStats) };

            // Make sure the report numbers match
            if stats.report == stats.report_checksum {
                return Ok(stats);
            }
        }
    }

    /// Initializes the containers for stats structures that are used by the
    /// main stat reporting process during multi-process fuzzing
    fn init_multi_stats(
        &mut self,
        map_size: usize,
        dirty_block_length: usize,
        max_input_size: usize,
    ) {
        self.multi_batch_stats = vec![SerialStats::default(); self.fuzzers];

        self.start_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.session_start = None;
        self.batch_start = None;
        self.last_find = Some(Instant::now());
        self.last_find_iters = 0;
        self.map_size = map_size;
        self.dirty_block_length = dirty_block_length;
        self.max_input = max_input_size;
    }

    /// Diffs two SerializedStats structures to create a 'batch' for statistics
    /// reporting when in multi-process mode
    fn create_batch(&mut self, idx: usize, new: SerialStats) -> SerialStats {
        // Grab the old stats
        let old = self.multi_batch_stats[idx];

        // Diff the two and return them
        new.diff(old)
    }

    /// Formats and synthesizes all of the statistics gathered from each
    /// individual fuzzer's stat file to print the statistics
    pub fn report_global(
        &mut self,
        output_dir: &str,
        map_size: usize,
        dirty_block_length: usize,
        input_max_size: usize,
    ) {
        // If the vector is empty, populate it by starting campaign stats
        if self.multi_batch_stats.is_empty() {
            self.init_multi_stats(map_size, dirty_block_length, input_max_size);
        }

        // Totals and absolutes
        let mut max_total_time = 0;
        let mut session_iters = 0;
        let mut crashes = 0;
        let mut timeouts = 0;
        let mut edges = 0;
        let mut dirty_pages = 0;
        let mut memcpys = 0;
        let mut corpus_entries = 0;
        let mut corpus_size = 0;

        // Batch stats
        let mut batch_total_time = Duration::new(0, 0);
        let mut batch_iters = 0;
        let mut batch_reset = Duration::new(0, 0);
        let mut batch_mutator = Duration::new(0, 0);
        let mut batch_target = Duration::new(0, 0);
        let mut batch_coverage = Duration::new(0, 0);
        let mut batch_redqueen = Duration::new(0, 0);
        let mut oldest_batch = 0;

        for i in 0..self.fuzzers {
            let Ok(stats) = self.read_stat_file(output_dir, i) else {
                continue;
            };

            // First, update all total-type and absolute statisics
            max_total_time = max_total_time.max(stats.total_time);
            session_iters += stats.iters;
            crashes += stats.crashes;
            timeouts += stats.timeouts;
            edges = edges.max(stats.edges);
            dirty_pages = dirty_pages.max(stats.dirty_pages);
            memcpys = memcpys.max(stats.memcpys);
            corpus_entries += stats.corpus_entries;
            corpus_size += stats.corpus_size;

            // Create a batch for this fuzzer
            let batch = self.create_batch(i, stats);

            // Create batch figures
            oldest_batch = oldest_batch.max(batch.total_time);
            batch_total_time += Duration::from_millis(batch.total_time);
            batch_iters += batch.iters;
            batch_reset += Duration::from_millis(batch.reset_time);
            batch_mutator += Duration::from_millis(batch.mutator_time);
            batch_target += Duration::from_millis(batch.target_time);
            batch_coverage += Duration::from_millis(batch.coverage_time);
            batch_redqueen += Duration::from_millis(batch.redqueen_time);

            // Save these stats to compare against next time
            self.multi_batch_stats[i] = stats;
        }

        // Simulate a campaign start time if we don't have one yet
        if self.session_start.is_none() {
            self.session_start = Some(Instant::now() - Duration::from_millis(max_total_time));
        }

        // Update our total/absolute stats
        self.session_iters = session_iters;
        self.crashes = crashes;
        self.timeouts = timeouts;

        // New edge record, reset last find
        if edges > self.edges {
            self.edges = edges;
            self.last_find = Some(Instant::now());
            self.last_find_iters = 0;
        }
        // No new edge record, add the batch iters to since last
        else {
            self.last_find_iters += batch_iters;
        }

        self.dirty_pages = dirty_pages;
        self.memcpys = memcpys;
        self.corpus_entries = corpus_entries;
        self.corpus_size = corpus_size;

        // Update our batch stats
        self.batch_start = Some(Instant::now() - batch_total_time);
        self.batch_iters = batch_iters;
        self.batch_reset = batch_reset;
        self.batch_mutator = batch_mutator;
        self.batch_target = batch_target;
        self.batch_coverage = batch_coverage;
        self.batch_redqueen = batch_redqueen;
        self.oldest_batch = Duration::from_millis(oldest_batch);

        // Print the stats
        self.print_stats();

        // Reset batch stats for the next iteration
        self.batch_iters = 0;
        self.batch_start = None;
        self.batch_reset = Duration::new(0, 0);
        self.batch_mutator = Duration::new(0, 0);
        self.batch_target = Duration::new(0, 0);
        self.batch_coverage = Duration::new(0, 0);
        self.batch_redqueen = Duration::new(0, 0);
        self.oldest_batch = Duration::new(0, 0);
    }
}
