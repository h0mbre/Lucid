//! This file contains the `main` program logic which right now parses a Bochs
//! image, loads that image into memory, and starts executing it
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2026 h0mbre

mod config;
mod context;
mod corpus;
mod coverage;
mod edge_pc;
mod elf;
mod err;
mod files;
mod ijon;
mod loader;
mod misc;
mod mmu;
mod mutators;
mod redqueen;
mod snapshot;
mod stats;
mod syscall;

use config::parse_args;
use context::{dry_run, fuzz_loop, start_bochs, LucidContext};
use corpus::Corpus;
use err::LucidErr;
use loader::load_bochs;
use misc::{handle_wait_result, non_block_waitpid, pin_core};

/// Main function steps:
/// 1. Parses configuration
/// 2. Creates a corpus
/// 3. Loads Bochs into memory
/// 4. Creates a LucidContext object which is how the entire fuzzer works
/// 5. Runs Bochs up to the snapshot instruction
/// 6. Creates a snapshot
/// 7. Registers fuzzing input dimensions so we can insert fuzzcases
/// 8. Dry-runs all seed inputs to normalize code-coverage
/// 9. Launches fuzzer(s)
fn main() {
    // Parse arguments and retrieve config
    prompt!("Parsing config options...");
    let config = parse_args().unwrap_or_else(|error| {
        fatal!(error);
    });
    prompt!("Configuration complete");

    // Read Corpus into memory
    prompt!("Creating corpus...");
    let corpus = Corpus::new(&config).unwrap_or_else(|error| {
        fatal!(error);
    });
    prompt!("Corpus created with {} seed inputs", corpus.inputs.len());

    // Load Bochs into our process space
    prompt!(
        "Loading Bochs with Bochs image path: '{}'...",
        config.bochs_image
    );
    let bochs = load_bochs(&config).unwrap_or_else(|error| {
        fatal!(error);
    });

    // Display all of the loading information
    prompt!(
        "Bochs loaded @ 0x{:X} - 0x{:X}",
        bochs.image_base,
        bochs.image_base + bochs.image_length
    );
    prompt!(
        "Bochs stack @ 0x{:X} - 0x{:X}",
        bochs.stack_base,
        bochs.stack_base + bochs.stack_length
    );
    prompt!("Bochs entry @ 0x{:X}", bochs.entry);
    prompt!("Bochs RSP @ 0x{:X}", bochs.rsp);

    // Create a new execution context
    prompt!("Creating Bochs execution context...");
    let mut lucid_context = Box::new(LucidContext::new(bochs, &config, corpus).unwrap_or_else(
        |error| {
            fatal!(error);
        },
    ));

    prompt!(
        "LucidContext @ 0x{:X}",
        &*lucid_context as *const LucidContext as usize
    );

    // Display known snapshot dimensions
    prompt!(
        "Snapshot memory @ 0x{:X} - 0x{:X}",
        lucid_context.snapshot.base,
        lucid_context.snapshot.base + lucid_context.snapshot.length
    );

    // Update user with MMU details
    prompt!(
        "MMU Brk Pool @ 0x{:X} - 0x{:X}",
        lucid_context.mmu.brk_base,
        lucid_context.mmu.brk_base + lucid_context.mmu.brk_size
    );

    prompt!(
        "MMU Mmap Pool @ 0x{:X} - 0x{:X}",
        lucid_context.mmu.mmap_base,
        lucid_context.mmu.mmap_base + lucid_context.mmu.mmap_size
    );

    prompt!("Lucid xsave area @ 0x{:X}", lucid_context.lucid_save_area);
    prompt!("Bochs xsave area @ 0x{:X}", lucid_context.bochs_save_area);

    prompt!("Scratch RSP @ 0x{:X}", lucid_context.scratch_rsp);

    // Update user with Mutator details
    prompt!(
        "Mutator seeded with 0x{:X}",
        lucid_context.mutator.get_rng()
    );
    prompt!(
        "Mutator max input size: 0x{:X}",
        lucid_context.mutator.get_max_size()
    );

    // Start executing Bochs
    prompt!("Running Bochs up to snapshot...");
    start_bochs(&mut lucid_context);

    // Check to see if any faults occurred during Bochs execution
    if let Some(err) = lucid_context.err.as_ref() {
        fatal!(err);
    }

    // Bochs translates the guest's registered physical ranges immediately
    // before it asks Lucid to take the snapshot, make sure that happened
    if lucid_context.input_spans.is_empty() {
        fatal!(LucidErr::from(
            "Bochs did not register the guest fuzzing input"
        ));
    }

    // Display input dimensions
    prompt!("Input layout spans: {}", lucid_context.input_spans.len());
    prompt!(
        "Input buffer capacity: 0x{:X}",
        lucid_context.input_capacity
    );

    // Dry-run if we have seeds and aren't skipping
    if config.dryrun && lucid_context.corpus.num_inputs() > 0 {
        prompt!("Dry-running seeds to initialize coverage map...");
        dry_run(&mut lucid_context).unwrap_or_else(|error| {
            fatal!(error);
        });

        // Check how many edges we found
        prompt!(
            "Seeds found {} edge(s)",
            lucid_context.coverage.get_edge_count()
        );
    }

    // Sleep to allow configuration to display
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Pin ourselves to core 0
    pin_core(0);

    // Single-process arch
    if lucid_context.is_single_process() {
        // Now we can fuzz
        prompt!("Starting fuzzer...");
        fuzz_loop(&mut lucid_context, None).unwrap_or_else(|error| {
            fatal!(error);
        });
    }
    // Multi-process arch:
    // - The original process becomes a simple stat reporter and waits to reap
    //      dead spawned children
    // - This means we'll share a CPU with fuzzer-id 0 which is fine since the
    //      original process is mostly not scheduled just reading stats and
    //      printing
    else {
        // Track children pids
        let mut child_pids = Vec::new();

        // Fork fuzzers off
        prompt!("Starting fuzzers...");
        for i in 0..lucid_context.config.num_fuzzers {
            let fork_result = unsafe { libc::fork() };

            if fork_result == -1 {
                fatal!(LucidErr::from("Fork failed to spawn fuzzer"));
            }

            // Child
            if fork_result == 0 {
                // Turn off verbosity if enabled, we don't want to muddle the
                // terminal with Bochs prints
                lucid_context.verbose = false;

                // Pin ourselves to core
                pin_core(i);

                // Start fuzzing!
                fuzz_loop(&mut lucid_context, Some(i)).unwrap_or_else(|error| {
                    fatal!(error);
                });

                // Not reachable
                unreachable!();
            }
            // Parent
            else {
                // Store pid
                child_pids.push(fork_result);
            }
        }

        // Parent is done forking, in a loop, print stats
        loop {
            // Sleep for the stat reporting interval + 2 seconds
            std::thread::sleep(std::time::Duration::from_millis(
                lucid_context.stats.stat_interval as u64 + 2_000,
            ));

            // Print statistics
            lucid_context.stats.report_global(
                &lucid_context.config.output_dir,
                lucid_context.coverage.curr_map.len(),
                lucid_context.snapshot.dirty_block_length,
                lucid_context.config.input_max_size,
            );

            // Roll-up the PCs for every fuzzer into the global database
            lucid_context
                .edge_pc
                .consolidate()
                .unwrap_or_else(|error| fatal!(error));

            // Try to reap any dead fuzzers and exit
            let mut child_exit = false;
            for pid in child_pids.iter() {
                let mut status: libc::c_int = 0;
                let wait_result = non_block_waitpid(*pid, &mut status);
                if handle_wait_result(wait_result, &status).is_err() {
                    child_exit = true;
                    break;
                }
            }

            // If we had a child exit, shut everything down
            if child_exit {
                prompt_warn!("Shutting down child process fuzzers...");
                for pid in child_pids.iter() {
                    // Send killing signal
                    unsafe {
                        libc::kill(*pid, 9);
                    }

                    // Status we don't check or care about
                    let mut status: libc::c_int = 0;
                    unsafe {
                        libc::waitpid(*pid, &mut status, 0);
                    }
                }

                fatal!(LucidErr::from("Exiting due to early child exit"));
            }
        }
    }
}
