/// This file contains all of the code for keeping stats for the current session

use std::time::{Instant, Duration};

// Default batch size for stat reporting
const BATCH_SIZE: usize = 500;

fn print_top_title(title: &str, line_len: usize) {
    // Determine padding
    let padding = line_len - title.len() - 2;
    
    // Format string
    let line = format!("┌\x1b[1;32m{}\x1b[0m{}┐",
        title,
        "─".repeat(padding));

    println!("{line}");
}

fn print_mid_title(title: &str, line_len: usize) {
    // Determine padding
    let padding = line_len - title.len() - 2;
    
    // Format string
    let line = format!("├\x1b[1;32m{}\x1b[0m{}┤",
        title,
        "─".repeat(padding));

    println!("{line}");
}

fn print_entry<T: std::fmt::Display>(key: &str, val: T, line_len: usize) {
    // Format key value
    let key_val_str = format!("{} : {}", key, val);

    // Calculate padding
    let padding = line_len - key_val_str.len() - 2;

    // Format final line
    let line = format!("│{}{}│",
        key_val_str,
        " ".repeat(padding));

    println!("{line}");
}

fn close_stats(line_len: usize) {
    let padding = line_len - 2;
    let line = format!("└{}┘", "─".repeat(padding));
    println!("{line}");
}

#[derive(Clone, Default)]
pub struct Stats {
    // Stats for the entire campaign so far
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

    pub edges: usize,                           // Number of edges we've hit
    map_size: usize,                            // Size of coverage map
}

impl Stats {
    // Start the timers
    #[inline]
    pub fn start_session(&mut self, map_size: usize) {
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
        self.batch_iters % BATCH_SIZE == 0
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
                format!("{:.1}K", self.session_iters as f64 / 1_000.0),
            _ => format!("{:.1}M", self.session_iters as f64 / 1_000_000.0),
        };

        // Calculate batch proportions
        let restore_percent = if batch_millis > 0 {
            (self.batch_restore.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let mutator_percent = if batch_millis > 0 {
            (self.batch_mutator.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let target_percent = if batch_millis > 0 {
            (self.batch_target.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let coverage_percent = if batch_millis > 0 {
            (self.batch_coverage.as_millis() as f64 / batch_millis as f64)
                * 100.0
        } else {
            0.0
        };

        let misc_percent = if batch_millis > 0 {
            100.0 - restore_percent - mutator_percent - target_percent
                - coverage_percent
        } else {
            0.0
        };

        // Line length
        let line_length = 70;

        // Clear terminal
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        
        // Print the title bar
        let title = "lucid stats";
        let padding = line_length - title.len(); 
        println!("{}\x1b[1;35m{}\x1b[0m{}",
            " ".repeat(padding / 2), title, " ".repeat(padding / 2));
        
        // Print Globals
        print_top_title("globals", line_length);
        print_entry("uptime", format!("{days}d {hours}h {minutes}m {seconds}s"),
            line_length);
        print_entry("iters", iters_str, line_length);
        print_entry("iters/s", format!("{iters_sec:.2}"), line_length);
        print_entry("crashes", self.crashes, line_length);

        // Print Coverage
        print_mid_title("coverage", line_length);
        print_entry("edges", self.edges, line_length);
        print_entry("last find", format!("{lf_hours}h {lf_minutes}m {lf_secs}s",
            ), line_length);
        print_entry("map", format!("{:.2}%",
            (self.edges as f64 / self.map_size as f64) * 100.0), line_length);

        // Print CPU stats
        print_mid_title("cpu", line_length);
        print_entry("target", format!("{target_percent:.1}%"), line_length);
        print_entry("reset", format!("{restore_percent:.1}%"), line_length);
        print_entry("mutator", format!("{mutator_percent:.1}%"), line_length);
        print_entry("coverage", format!("{coverage_percent:.1}%"), line_length);
        print_entry("misc", format!("{misc_percent:.1}%"), line_length);

        // Close the stat box
        close_stats(line_length);

        // Reset batch
        self.batch_iters = 0;
        self.batch_start = Some(Instant::now());
        self.batch_restore = Duration::new(0, 0);
        self.batch_mutator = Duration::new(0, 0);
        self.batch_target = Duration::new(0, 0);
        self.batch_coverage = Duration::new(0, 0);
    }
}