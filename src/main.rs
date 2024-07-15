/// This file contains the `main` program logic which right now parses a Bochs
/// image, loads that image into memory, and starts executing it
mod config;
mod context;
mod corpus;
mod coverage;
mod elf;
mod err;
mod files;
mod loader;
mod misc;
mod mmu;
mod mutator;
mod redqueen;
mod snapshot;
mod stats;
mod syscall;

use config::parse_args;
use context::{dry_run, fuzz_loop, register_input, start_bochs, LucidContext};
use corpus::Corpus;
use loader::load_bochs;

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
    let bochs = load_bochs(&config.bochs_image).unwrap_or_else(|error| {
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
    prompt!("Mutator seeded with 0x{:X}", lucid_context.mutator.rng);
    prompt!(
        "Mutator max input size: 0x{:X}",
        lucid_context.mutator.max_size
    );

    // Start executing Bochs
    prompt!("Running Bochs up to snapshot...");
    start_bochs(&mut lucid_context);

    // Check to see if any faults occurred during Bochs execution
    if lucid_context.err.is_some() {
        fatal!(lucid_context.err.unwrap());
    }

    // Register input dimensions
    prompt!("Registering fuzzing input dimensions...");
    register_input(&mut lucid_context, config.input_signature).unwrap_or_else(|error| {
        fatal!(error);
    });

    // Display input dimensions
    prompt!("Input size address @ 0x{:X}", lucid_context.input_size_addr);
    prompt!(
        "Input buffer address @ 0x{:X}",
        lucid_context.input_buf_addr
    );

    // Try to reach into the Bochs memory and pull out these values for
    // confirmation
    let input_size = unsafe { *(lucid_context.input_size_addr as *const usize) };

    let display_len = std::cmp::min(input_size, 8);

    let input_buf: &[u8] = unsafe {
        std::slice::from_raw_parts(lucid_context.input_buf_addr as *const u8, display_len)
    };

    prompt!("Input size in snapshot: 0x{:X}", input_size);
    prompt!("Input buffer in snapshot: {:X?}...", input_buf);

    // Dry-run if we have seeds and aren't skipping
    if !config.skip_dryrun && lucid_context.corpus.num_inputs() > 0 {
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

    /* FORK */

    // Now we can fuzz
    prompt!("Starting fuzzer...");
    fuzz_loop(&mut lucid_context).unwrap_or_else(|error| {
        fatal!(error);
    });

    // Campaign over
    prompt!("Campaign suspended");
}
