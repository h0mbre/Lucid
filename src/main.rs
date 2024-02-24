/// This file contains the `main` program logic which right now parses a Bochs
/// image, loads that image into memory, and starts executing it

mod err;
mod elf;
mod loader;
mod context;
mod misc;
mod syscall;

use loader::load_bochs;
use context::{start_bochs, LucidContext, Fault};
use err::LucidErr;

// Just create a fatal LucidErr if no image is provided
fn fatal_image() {
    fatal!(LucidErr::from("--bochs-image <image path> is required"));
}

// Parse the CLI args for the `--bochs-path` value
fn get_bochs_image() -> String {
    // Retrieve the Bochs image with some simple arg parsing for now
    let args: Vec<String> = std::env::args().collect();

    // Check to see if we have a "--bochs-image" argument (required)
    if args.len() < 3 || !args.contains(&"--bochs-image".to_string()) { 
        fatal_image();
    }

    // Search for path value in the most readable dumb way as possible
    let mut path = None;
    for (i, arg) in args.iter().enumerate() {
        if arg == "--bochs-image" {
            if i >= args.len() - 1 {
                fatal_image();
            }

            path = Some(args[i + 1].clone());
            break;
        }
    }
    if path.is_none() { fatal_image(); }
    path.unwrap()
}

fn main() {
    // Retrieve the Bochs image with some simple arg parsing for now
    let path = get_bochs_image();
    prompt!("Bochs image: {}", path);

    // Load Bochs into our process space
    prompt!("Loading Bochs...");
    let bochs = load_bochs(path).unwrap_or_else(|error| {
        fatal!(error);
    });
    prompt!("Bochs mapping: 0x{:X} - 0x{:X}",
        bochs.addr, bochs.addr + bochs.size);
    prompt!("Bochs mapping size: 0x{:X}", bochs.size);
    prompt!("Bochs stack: 0x{:X}", bochs.rsp);
    prompt!("Bochs entry: 0x{:X}", bochs.entry);

    // Create a new execution context
    prompt!("Creating Bochs execution context...");
    let mut lucid_context = Box::new(LucidContext::new(bochs.entry, bochs.rsp)
        .unwrap_or_else(|error| { fatal!(error); }));

    // Start executing Bochs
    prompt!("Starting Bochs...");
    start_bochs(&mut lucid_context);

    // Check to see if any faults occurred during Bochs execution
    if !matches!(lucid_context.fault, Fault::Success) {
        fatal!(LucidErr::from_fault(lucid_context.fault));
    }
}