/// This file contains the `main` program logic which right now parses a Bochs
/// image, loads that image into memory, and starts executing it

mod err;
mod elf;
mod loader;
mod context;
mod misc;
mod syscall;
mod mmu;
mod files;

use loader::load_bochs;
use context::{start_bochs, LucidContext, Fault};
use err::LucidErr;
use misc::get_arg_val;

fn main() {
    // Retrieve the Bochs image with some simple arg parsing for now
    let Some(path) = get_arg_val("--bochs-image") else {
        fatal!(LucidErr::from("
            No '--bochs-image' argument "));
    };
    prompt!("Bochs image path: '{}'", path);

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

    // Update user with context address
    prompt!("LucidContext: 0x{:X}",
        &*lucid_context as *const LucidContext as usize);

    // Update user with MMU details
    prompt!("MMU Break Pool: 0x{:X} - 0x{:X}",
        lucid_context.mmu.brk_base,
        lucid_context.mmu.brk_base + lucid_context.mmu.brk_size);
    
    prompt!("MMU Mmap Pool: 0x{:X} - 0x{:X}",
        lucid_context.mmu.mmap_base,
        lucid_context.mmu.mmap_base + lucid_context.mmu.mmap_size);

    // Start executing Bochs
    prompt!("Starting Bochs...");
    start_bochs(&mut lucid_context);

    // Check to see if any faults occurred during Bochs execution
    if !matches!(lucid_context.fault, Fault::Success) {
        fatal!(LucidErr::from_fault(lucid_context.fault));
    }
}