//! This file contains all of the code for keeping stats for the current session

use chrono::Local;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::err::LucidErr;
use crate::prompt_warn;

// Default batch time for stat reporting in milliseconds
const DEFAULT_BATCH_TIME: u128 = 2_000; // Print stats every 2 seconds

// Helper function to format a group of stats
fn format_group(title: &str, stats: &[(String, String)]) -> String {
    let stats_str = stats
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join(" | ");
    format!("\x1b[1;32m{}:\x1b[0m {}", title, stats_str)
}

// What kind of mode are fuzzing in
#[derive(Clone)]
enum ReportMode {
    Single,
    Multi,
}

impl Default for ReportMode {
    fn default() -> Self {
        ReportMode::Single
    }
}

// Stats that we serialize to disk in multi-process mode
#[derive(Clone, Copy, Default, Debug)]
#[repr(C, packed)]
struct SerialStats {
    report: usize,
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
    report_checksum: usize,
}

impl SerialStats {
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
            report_checksum: stats.report,
        }
    }

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
            report_checksum: self.report,
        }
    }
}

// Formatted stats for printing
struct FormattedStats {
    uptime: String,
    fuzzers: usize,
    iters: String,
    iters_per_sec: f64,
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
}

#[derive(Clone, Default)]
pub struct Stats {
    // Stats for the entire campaign so far
    report: usize,                  // Current report number
    pub start_str: String,          // String repr of date start
    pub session_iters: usize,       // Total fuzzcases
    session_start: Option<Instant>, // Start time
    last_find: Option<Instant>,     // Last new coverage find
    pub crashes: usize,             // Number of crashes
    pub timeouts: usize,            // Number of timeouts
    pub fuzzers: usize,             // Number of fuzzers
    report_mode: ReportMode,        // Type of reporting to do as fuzzer
    pub id: usize,                  // Fuzzer id
    pub stat_file: Option<String>,  // Path to stat file if we need one

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
    pub fn new(config: &Config) -> Self {
        // Update the members that depend on the config
        let stat_interval = match config.stat_interval {
            None => {
                prompt_warn!(
                    "No stat interval provided, defaulting to {} secs",
                    DEFAULT_BATCH_TIME / 1_000
                );
                DEFAULT_BATCH_TIME
            }
            Some(interval) => (interval.wrapping_mul(1_000)) as u128,
        };

        // Determine mode bruh
        let report_mode = match config.num_fuzzers {
            1 => ReportMode::Single,
            _ => ReportMode::Multi,
        };

        Stats {
            stat_interval,
            fuzzers: config.num_fuzzers,
            report_mode,
            id: 0,
            ..Default::default()
        }
    }

    fn generate_formatted_stats(&self) -> FormattedStats {
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

        let iters_str = match self.session_iters {
            0..=999 => format!("{}", self.session_iters),
            1_000..=999_999 => format!("{:.2}K", self.session_iters as f64 / 1_000.0),
            _ => format!("{:.3}M", self.session_iters as f64 / 1_000_000.0),
        };

        let cpu_target = (self.batch_target.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_reset = (self.batch_reset.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_mutator = (self.batch_mutator.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_coverage = (self.batch_coverage.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_redqueen = (self.batch_redqueen.as_millis() as f64 / batch_millis) * 100.0;
        let cpu_misc = 100.0 - (cpu_target + cpu_reset + cpu_mutator + cpu_coverage + cpu_redqueen);

        FormattedStats {
            uptime: format!("{}d {}h {}m {}s", days, hours, minutes, seconds),
            fuzzers: self.fuzzers,
            iters: iters_str,
            iters_per_sec: iters_sec,
            crashes: self.crashes,
            timeouts: self.timeouts,
            edges: self.edges,
            last_find: format!("{}h {}m {}s", lf_hours, lf_minutes, lf_secs),
            map_coverage: (self.edges as f64 / self.map_size as f64) * 100.0,
            cpu_target,
            cpu_reset,
            cpu_mutator,
            cpu_coverage,
            cpu_redqueen,
            cpu_misc,
        }
    }

    pub fn print_stats(&self) {
        let formatted_stats = self.generate_formatted_stats();

        println!(
            "\n\x1b[1;35m[lucid stats (start time: {})]\x1b[0m",
            self.start_str
        );

        let globals = [
            ("uptime".to_string(), formatted_stats.uptime),
            ("fuzzers".to_string(), formatted_stats.fuzzers.to_string()),
            ("iters".to_string(), formatted_stats.iters),
            (
                "iters/s".to_string(),
                format!("{:.2}", formatted_stats.iters_per_sec),
            ),
            ("crashes".to_string(), formatted_stats.crashes.to_string()),
            ("timeouts".to_string(), formatted_stats.timeouts.to_string()),
        ];
        println!("{}", format_group("globals", &globals));

        let coverage = [
            ("edges".to_string(), formatted_stats.edges.to_string()),
            ("last find".to_string(), formatted_stats.last_find),
            (
                "map".to_string(),
                format!("{:.2}%", formatted_stats.map_coverage),
            ),
        ];
        println!("{}", format_group("coverage", &coverage));

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
    }

    // Start the timers
    #[inline]
    pub fn start_session(&mut self, map_size: usize) {
        self.start_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.session_start = Some(Instant::now());
        self.batch_start = Some(Instant::now());
        self.last_find = Some(Instant::now());
        self.map_size = map_size;
    }

    // Update 1 fuzzcase
    #[inline]
    pub fn update(&mut self) {
        self.session_iters += 1;
        self.batch_iters += 1;
    }

    fn report_ready_single(&self) -> bool {
        if let Some(batch_start) = self.batch_start {
            batch_start.elapsed().as_millis() > self.stat_interval
        } else {
            false
        }
    }

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

    // Check if time to report
    pub fn report_ready(&mut self) -> bool {
        if matches!(self.report_mode, ReportMode::Single) {
            self.report_ready_single()
        } else {
            self.report_ready_multi()
        }
    }

    pub fn new_coverage(&mut self, edges: usize) {
        self.edges = edges;
        self.last_find = Some(Instant::now());
    }

    // How a single-process fuzzer reports
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

    // Report the stats
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

    // Read a serial stats file for a specific fuzzer id
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

    // Initialize the vector to hold all of the fuzzer stats
    fn init_multi_stats(&mut self, map_size: usize) {
        self.multi_batch_stats = vec![SerialStats::default(); self.fuzzers];

        self.start_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.session_start = None;
        self.batch_start = None;
        self.last_find = Some(Instant::now());
        self.map_size = map_size;
    }

    // Diff two stat structs to create batch statistics
    fn create_batch(&mut self, idx: usize, new: SerialStats) -> SerialStats {
        // Grab the old stats
        let old = self.multi_batch_stats[idx];

        // Diff the two and return them
        new.diff(old)
    }

    // Report global stats
    pub fn report_global(&mut self, output_dir: &str, map_size: usize) {
        // If the vector is empty, populate it by starting campaign stats
        if self.multi_batch_stats.is_empty() {
            self.init_multi_stats(map_size);
        }

        // Totals and absolutes
        let mut max_total_time = 0;
        let mut session_iters = 0;
        let mut crashes = 0;
        let mut timeouts = 0;
        let mut edges = 0;

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
        if edges > self.edges {
            self.edges = edges;
            self.last_find = Some(Instant::now());
        }

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
