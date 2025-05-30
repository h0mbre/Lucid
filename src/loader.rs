//! This file contains all of the logic necessary to load a parsed static pie
//! ELF into memory as well as set up a program stack
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use std::fs::read;

use crate::config::Config;
use crate::elf::{parse_elf, Elf, ELF_HDR_SIZE, PRG_HDR_SIZE};
use crate::err::LucidErr;
use crate::misc::PAGE_SIZE;

/// Address we want to load Bochs at
const LOAD_TARGET: usize = 0x10000;

/// A megabtye of memory in powers of 2
const MEGABYTE: usize = 1_048_576;

/// Size of the actual Read/Write stack allocation
const STACK_ALLOC_SIZE: usize = MEGABYTE;

/// Size of a void *, this should always just be 8 for now, no planned support
/// for anything else
const POINTER_SIZE: usize = 8;

/// Size of a u64, this should always be 8. Just doing this to differentiate
/// from a pointer, but same purpose
const U64_SIZE: usize = 8;

/// The max size our stack data can be, has to be a multiple of a page size
const STACK_DATA_MAX: usize = 0x1000;

/// This represent all of the data we need about Bochs' ELF image and stack to
/// load and jump to for execution
#[derive(Clone)]
pub struct Bochs {
    pub image_base: usize,   // The address of the ELF in memory
    pub image_length: usize, // Length of the ELF image in memory
    pub stack_base: usize,   // Address of Bochs' stack
    pub stack_length: usize, // Length of Bochs' stack
    pub write_base: usize,   // Where contiguous writable memory starts
    pub write_length: usize, // Length of contiguous writable memory
    pub entry: usize,        // Address of ELF entry point
    pub rsp: usize,          // The stack pointer we should use for execution
}

/// Map all of the memory we need to hold the ELF image of Bochs but also Bochs'
/// stack in one contiguous block. We have to map this as writable so we can
/// write to it, but we'll go back and mprotect certain page ranges later.
fn initial_mmap(size: usize) -> Result<usize, LucidErr> {
    // Call `mmap` and make sure it succeeds
    let result = unsafe {
        libc::mmap(
            LOAD_TARGET as *mut libc::c_void, // Alignment? It works?
            size,
            libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
            -1,
            0,
        )
    };

    if result == libc::MAP_FAILED {
        return Err(LucidErr::from("Failed to `mmap` memory for Bochs"));
    }

    Ok(result as usize)
}

/// Iterate through all the loadable segments and adjust their memory backing
/// according to their permissions and load the binary data
fn load_segments(addr: usize, elf: &Elf) -> Result<(usize, usize), LucidErr> {
    // Extract relevant data from loadable segments
    let mut load_segments = Vec::new();
    for ph in elf.program_headers.iter() {
        if ph.is_load() {
            load_segments.push((
                ph.flags,           // segment.0
                ph.vaddr as usize,  // segment.1
                ph.memsz as usize,  // segment.2
                ph.offset as usize, // segment.3
                ph.filesz as usize, // segment.4
            ));
        }
    }

    // Iterate through the loadable segments and change their perms and then
    // copy the data over. For our snapshotting logic to work, all writable
    // segments must be contiguous
    let mut write_start = 0;
    let mut write_end = 0;
    for (flags, vaddr, memsz, offset, filesz) in load_segments.iter() {
        // Copy the binary data over, the destination is where in our process
        // memory we're copying the binary data to. The source is where we copy
        // from, this is going to be an offset into the binary data in the file,
        // len is going to be how much binary data is in the file, that's filesz
        let dst = (addr + vaddr) as *mut u8;
        let src = (elf.data[*offset..*offset + filesz]).as_ptr();
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, *filesz);
        }

        // Calculate the `mprotect` address by adding the mmap address plus the
        // virtual address offset, we also mask off the last 0x1000 bytes so
        // that we are always page-aligned as required by `mprotect`
        let mprotect_addr = ((addr + vaddr) & !(PAGE_SIZE - 1)) as *mut libc::c_void;

        // Get the length
        let mut mprotect_len = *memsz;

        // Adjust the length to round up to nearest page if necessary
        if mprotect_len % PAGE_SIZE != 0 {
            let remainder = mprotect_len % PAGE_SIZE;
            let round_amt = PAGE_SIZE - remainder;
            mprotect_len += round_amt;
        }

        // Get the protection
        let mut mprotect_prot = 0 as libc::c_int;
        if flags & 0x1 == 0x1 {
            mprotect_prot |= libc::PROT_EXEC;
        }
        if flags & 0x2 == 0x2 {
            mprotect_prot |= libc::PROT_WRITE;
        }
        if flags & 0x4 == 0x4 {
            mprotect_prot |= libc::PROT_READ;
        }

        // Call `mprotect` to change the mapping perms
        let result = unsafe { libc::mprotect(mprotect_addr, mprotect_len, mprotect_prot) };
        if result < 0 {
            return Err(LucidErr::from("Failed to `mprotect` memory for Bochs"));
        }

        // Do we have a writable segment?
        if mprotect_prot & libc::PROT_WRITE != 0 {
            // If we haven't encountered a writable segment, start tracking
            if write_start == 0 {
                write_start = mprotect_addr as usize;
            }
            // Update write end
            write_end = mprotect_addr as usize + mprotect_len;
        }
        // We don't have a writable segment, make sure we haven't had one yet
        else if write_start != 0 {
            return Err(LucidErr::from("Non-contiguous writable segments"));
        }
    }

    Ok((write_start, write_end))
}

/// Pushes a u64 onto the stack in little-endian order
fn push_u64(stack: &mut Vec<u8>, value: u64) {
    let bytes = value.to_le_bytes();
    for &byte in bytes.iter().rev() {
        stack.insert(0, byte);
    }
}

/// Pushes a NULL terminated string onto the "stack" and pads the string with
/// NULL bytes until we achieve 8-byte alignment
fn push_string(stack: &mut Vec<u8>, string: String) {
    // Convert the string to bytes and append it to the stack
    let mut bytes = string.as_bytes().to_vec();

    // Add a NULL terminator
    bytes.push(0x0);

    // We're adding bytes in reverse because we're adding to index 0 always,
    // we want to pad these strings so that they remain 8-byte aligned so that
    // the stack is easier to reason about
    if bytes.len() % U64_SIZE > 0 {
        let pad = U64_SIZE - (bytes.len() % U64_SIZE);
        bytes.resize(bytes.len() + pad, 0x0);
    }

    for &byte in bytes.iter().rev() {
        stack.insert(0, byte);
    }
}

/// Create the actual content/data that we'll place onto the stack that we
/// provide to Bochs when we jump to it to start executing
///
/// The stack layout should look like this when we're done, thanks to
/// https://articles.manugarg.com/aboutelfauxiliaryvectors for reference and
/// @netspooky for their help
///
/// ==== LOWER ====
/// RSP     -> argc
/// argv[0] -> pointer
/// argv[1] -> pointer
/// ..
/// argv[n] -> NULL
///
/// envp[0] -> pointer
/// envp[1] -> pointer
/// ..
/// envp[n] -> NULL
///
/// auxv[0] -> pointer
/// auxv[1] -> pointer
/// ..
/// auxv[n] -> AT_NULL vector
///
/// padding
///
/// argv strings
/// envvar strings
/// end marker (NULL)
/// ==== HIGHER ====
fn create_stack_data(
    base: usize,
    stack_addr: usize,
    elf: &Elf,
    args: Vec<String>,
) -> Result<Vec<u8>, LucidErr> {
    // Create a vector to hold all of our stack data
    let mut stack_data = Vec::new();

    // Add the "end-marker" NULL, we're skipping adding any envvar strings for
    // now
    push_u64(&mut stack_data, 0u64);

    // Store the length of the strings including padding
    let mut arg_lens = Vec::new();

    // For each argument, push a string onto the stack and store its offset
    // location
    for arg in args.iter() {
        let old_len = stack_data.len();
        push_string(&mut stack_data, arg.to_string());

        // Calculate arg length and store it
        let arg_len = stack_data.len() - old_len;
        arg_lens.push(arg_len);
    }

    // Add some padding
    push_u64(&mut stack_data, 0u64);

    // Next we need to set up the auxiliary vectors, terminate the vector with
    // the AT_NULL key which is 0, with a value of 0
    push_u64(&mut stack_data, 0u64);
    push_u64(&mut stack_data, 0u64);

    // Add the AT_ENTRY key which is 9, along with the value from the Elf header
    // for the program's entry point. We need to calculate
    push_u64(&mut stack_data, elf.elf_header.entry + base as u64);
    push_u64(&mut stack_data, 9u64);

    // Add the AT_PHDR key which is 3, along with the address of the program
    // headers which is just ELF_HDR_SIZE away from the base
    push_u64(&mut stack_data, (base + ELF_HDR_SIZE) as u64);
    push_u64(&mut stack_data, 3u64);

    // Add the AT_PHENT key which is 4, along with the program header entry size
    push_u64(&mut stack_data, PRG_HDR_SIZE as u64);
    push_u64(&mut stack_data, 4u64);

    // Add the AT_PHNUM key which is 5, along with the number of program headers
    push_u64(&mut stack_data, elf.program_headers.len() as u64);
    push_u64(&mut stack_data, 5u64);

    // Add AT_RANDOM key which is 25, this is where the start routines will
    // expect 16 bytes of random data as a seed to generate stack canaries, we
    // can just use the entry again since we don't care about security
    push_u64(&mut stack_data, elf.elf_header.entry + base as u64);
    push_u64(&mut stack_data, 25u64);

    // Since we skipped ennvars for now, envp[0] is going to be NULL
    push_u64(&mut stack_data, 0u64);

    // argv[n] is a NULL
    push_u64(&mut stack_data, 0u64);

    // At this point, we have all the information we need to calculate the total
    // length of the stack. We're missing the argv pointers and finally argc
    let mut stack_length = stack_data.len();

    // Add argv pointers
    stack_length += args.len() * POINTER_SIZE;

    // Add argc
    stack_length += std::mem::size_of::<u64>();

    // Now with the argv[] string data we've collected, and the final stack size
    // calculated, we can correctly calculate the pointers to the arguments. We
    // pushed the argument strings onto the stack such that the highest memory
    // string location is argv[n] and we work our way up to argv[0]. We're
    // going to use a moving offset that traverses from the bottom of the stack
    // (HIGHER MEMORY ADDR) towards the top of the stack (LOWER MEMORY ADDR).
    // We'll use the offset and the collected argument lengths to calculate the
    // address of the strings in absolute terms and push those pointers onto the
    // stack
    let mut curr_offset = stack_length;

    // Right now our offset is at the bottom of the stack, for the first
    // argument calculation, we have to accomdate the "end-marker" that we added
    // to the stack at the beginning. So we need to move the offset up the size
    // of the end-marker so that it will point to the end of the first string
    curr_offset -= U64_SIZE;

    // Now for each argument, we just have to account for the length of each
    // string
    for arg_len in arg_lens.iter() {
        // Seek to the beginning of the string
        curr_offset -= arg_len;

        // Calculate the absolute address
        let absolute_addr = (stack_addr + curr_offset) as u64;

        // Push the absolute address onto the stack
        push_u64(&mut stack_data, absolute_addr);
    }

    // Finally, add argc
    let argc = args.len() as u64;
    push_u64(&mut stack_data, argc);

    // If we have too much stack data, we have to bail at this point
    if stack_data.len() > STACK_DATA_MAX {
        return Err(LucidErr::from(
            "Failed to Load Bochs, stack_data > STACK_DATA_MAX",
        ));
    }

    Ok(stack_data)
}

/// Loads Bochs ELF image into memory so that we can execute it. Ensures that
/// all writable memory is contiguous and comes at the end of the ELF with
/// regards to headers. We will also create and prepare a stack here. This
/// returns all of the necessary information to jump to Bochs and start
/// executing
pub fn load_bochs(config: &Config) -> Result<Bochs, LucidErr> {
    // Get the bochs image
    let bochs_image = &config.bochs_image;

    // Read the executable file into memory
    let data = read(bochs_image)
        .map_err(|_| LucidErr::from("Unable to read binary data from Bochs binary"))?;

    // Parse ELF
    let elf = parse_elf(&data)?;

    // Make sure there are no interpreter program headers for -static-pie check
    for ph in elf.program_headers.iter() {
        if ph.is_interp() {
            return Err(LucidErr::from("Invalid ELF, not -static-pie"));
        }
    }

    // Calculate the size of the ELF image that we need to load into memory
    let mut image_size: usize = 0;
    for ph in elf.program_headers.iter() {
        // We have a loadable program header
        if ph.is_load() {
            // If this is our first loadable header, make sure vaddr is 0 for
            // a -static-pie sanity check
            if image_size == 0 && ph.vaddr != 0 {
                return Err(LucidErr::from("Invalid ELF, not -static-pie"));
            }

            // Calculate the end address
            let end_addr = (ph.vaddr + ph.memsz) as usize;
            if image_size < end_addr {
                image_size = end_addr;
            }
        }
    }

    // Round the image size up to a page
    if image_size % PAGE_SIZE > 0 {
        image_size += PAGE_SIZE - (image_size % PAGE_SIZE);
    }

    // Calculate a total size
    let total_size = image_size + STACK_ALLOC_SIZE;

    // Get an initial `mmap()` of the range
    let mapping = initial_mmap(total_size)?;

    // Load the segments with their permissions and their binary data
    let (write_base, write_end) = load_segments(mapping, &elf)?;

    // Calc the writable memory length, the length of the writable memory
    // in the process image + the size of the stack
    let write_length = (write_end - write_base) + STACK_ALLOC_SIZE;

    // Calculate the stack base
    let stack_addr = mapping + image_size;

    // Calculate the stack pointer, give the stack as much slack space as we can
    let rsp = stack_addr + STACK_ALLOC_SIZE - STACK_DATA_MAX;

    // Create stack data
    let args = config.bochs_args.clone();
    let stack_data = create_stack_data(mapping, rsp, &elf, args)?;

    // Copy the stack data over to the stack
    let len = stack_data.len() as libc::size_t;
    let dst = rsp as *mut u8;
    let src = stack_data.as_ptr();
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, len);
    }

    // Change the memory protections of the stack to be readable as well
    let mprotect_prot = libc::PROT_READ | libc::PROT_WRITE;
    let result = unsafe {
        libc::mprotect(
            stack_addr as *mut libc::c_void,
            STACK_ALLOC_SIZE,
            mprotect_prot,
        )
    };
    if result < 0 {
        return Err(LucidErr::from("Failed to mprotect stack"));
    }

    // Calculate the entry address for Bochs ELF
    let entry = mapping + elf.elf_header.entry as usize;

    // Return Bochs
    Ok(Bochs {
        image_base: mapping,
        image_length: image_size,
        stack_base: stack_addr,
        stack_length: STACK_ALLOC_SIZE,
        write_base,
        write_length,
        entry,
        rsp,
    })
}
