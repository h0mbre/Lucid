/// This file contains all of the code for keeping stats for the current session

use std::time::{Instant, Duration};
use chrono::Local;

// Default batch time for stat reporting in milliseconds
const BATCH_TIME: u128 = 1_000;  // Print stats every second

// Helper function to format a group of stats
fn format_group(title: &str, stats: &[(String, String)]) -> String {
    let stats_str = stats.iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join(" | ");
    format!("\x1b[1;32m{}:\x1b[0m {}", title, stats_str)
}

#[derive(Clone, Default)]
pub struct Stats {
    // Stats for the entire campaign so far
    pub start_str: String,                      // String repr of date start
    pub session_iters: usize,                   // Total fuzzcases
    session_start: Option<Instant>,             // Start time
    last_find: Option<Instant>,                 // Last new coverage find
    crashes: usize,                             // Number of crashes

    // Stats for local batch reporting
    batch_iters: usize,                         // Batch fuzzcases
    batch_start: Option<Instant>,               // Batch start 
    pub batch_restore: Duration,                // Batch time spent in restore
    pub batch_mutator: Duration,                // Batch time spent in mutator
    pub batch_target: Duration,                 // Batch time spent in target
    pub batch_coverage: Duration,               // Batch time spent in coverage
    pub batch_redqueen: Duration,               // Batch time spent in redqueen

    pub edges: usize,                           // Number of edges we've hit
    map_size: usize,                            // Size of coverage map
}

impl Stats {
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
    pub fn update(&mut self, crash: i32) {
        self.session_iters += 1;
        self.batch_iters += 1;

        if crash == 1{
            self.crashes += 1;
        }
    }

    // Check if time to report
    #[inline]
    pub fn report_ready(&self) -> bool {
        if let Some(batch_start) = self.batch_start {
            batch_start.elapsed().as_millis() > BATCH_TIME
        } else {
            false
        }
    }

    pub fn new_coverage(&mut self, edges: usize) {
        self.edges = edges;
        self.last_find = Some(Instant::now());
    } 

    // Report the stats
    pub fn report(&mut self) {
        // Safety reasons
        if self.session_start.is_none() {
            return;
        }

        // Calculate total uptime
        let total_elapsed = self.session_start.unwrap().elapsed();
        let total_seconds = total_elapsed.as_secs();
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;

        // Calculate last find
        let lf_elapsed = self.last_find.unwrap().elapsed().as_secs();
        let lf_hours = lf_elapsed / 3600;
        let lf_minutes = (lf_elapsed % 3600) / 60;
        let lf_secs = lf_elapsed % 60;

        // Calculate batch iters/sec
        let batch_elapsed = self.batch_start.unwrap().elapsed();
        let batch_millis = batch_elapsed.as_millis();
        let batch_seconds = batch_millis as f64 / 1000.0;
        let iters_sec = self.batch_iters as f64 / batch_seconds;

        // Calculate total iters unit
        let iters_str = match self.session_iters {
            0..=999 => format!("{}", self.session_iters),
            1_000..=999_999 => 
                format!("{:.2}K", self.session_iters as f64 / 1_000.0),
            _ => format!("{:.3}M", self.session_iters as f64 / 1_000_000.0),
        };

        // Calculate batch proportions
        let restore_per = if batch_millis > 0 {
            (self.batch_restore.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let mutator_per = if batch_millis > 0 {
            (self.batch_mutator.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let target_per = if batch_millis > 0 {
            (self.batch_target.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let coverage_per = if batch_millis > 0 {
            (self.batch_coverage.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let rq_per = if batch_millis > 0 {
            (self.batch_redqueen.as_millis() as f64 / batch_millis as f64)
            * 100.0
        } else {
            0.0
        };

        let misc_per = if batch_millis > 0 {
            100.0 - restore_per - mutator_per - target_per
                - coverage_per - rq_per
        } else {
            0.0
        };

        // Print banner
        println!("\n\x1b[1;35m[lucid stats (start time: {})]\x1b[0m",
            self.start_str.clone());

        // Format and print globals
        let globals = [
            ("uptime".to_string(), format!("{}d {}h {}m {}s",
                days, hours, minutes, seconds)),
            ("iters".to_string(), iters_str),
            ("iters/s".to_string(), format!("{:.2}", iters_sec)),
            ("crashes".to_string(), format!("{}", self.crashes)),
        ];
        println!("{}", format_group("globals", &globals));
    
        // Format and print coverage
        let coverage = [
            ("edges".to_string(), format!("{}", self.edges)),
            ("last find".to_string(), format!("{}h {}m {}s",
                lf_hours, lf_minutes, lf_secs)),
            ("map".to_string(), format!("{:.2}%",
                (self.edges as f64 / self.map_size as f64) * 100.0)),
        ];
        println!("{}", format_group("coverage", &coverage));

        // Format and print CPU stats
        let cpu = [
            ("target".to_string(), format!("{:.1}%", target_per)),
            ("reset".to_string(), format!("{:.1}%", restore_per)),
            ("mutator".to_string(), format!("{:.1}%", mutator_per)),
            ("coverage".to_string(), format!("{:.1}%", coverage_per)),
            ("redqueen".to_string(), format!("{:.1}%", rq_per)),
            ("misc".to_string(), format!("{:.1}%", misc_per)),
        ];
        println!("{}", format_group("cpu", &cpu));

        // Reset batch
        self.batch_iters = 0;
        self.batch_start = Some(Instant::now());
        self.batch_restore = Duration::new(0, 0);
        self.batch_mutator = Duration::new(0, 0);
        self.batch_target = Duration::new(0, 0);
        self.batch_coverage = Duration::new(0, 0);
        self.batch_redqueen = Duration::new(0, 0);
    }
}