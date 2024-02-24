/// This file contains all of the logic necessary to load a parsed static pie 
/// ELF into memory as well as set up a program stack

use std::fs::read;
use crate::err::LucidErr;
use crate::elf::{parse_elf, Elf, ELF_HDR_SIZE, PRG_HDR_SIZE};

// Address we want to load Bochs at
const LOAD_TARGET: usize = 0x10000;

// Duh
const PAGE_SIZE: usize = 0x1000;

// How many pages we place before and after Read/Write Stack memory
const NUM_GUARD_PAGES: usize = 2;

// Size of the guard page buffer in bytes
const GUARD_SIZE: usize = NUM_GUARD_PAGES * PAGE_SIZE;

// Size of the actual Read/Write stack allocation
const STACK_ALLOC_SIZE: usize = 0x100000;

// Size of a void *, this should always just be 8 for now, no planned support
// for anything else
const POINTER_SIZE: usize = std::mem::size_of::<*const u8>();

// Size of a u64, this should always be 8. Just doing this to differentiate
// from a pointer, but same purpose
const U64_SIZE: usize = std::mem::size_of::<u64>();

// The max size our stack data can be, has to be a multiple of a page size
const STACK_DATA_MAX: usize = 0x1000;

// This is what we return to `main`, this is the information required to 
// jump to Bochs and start execution
pub struct Bochs {
    pub entry: usize,
    pub rsp: usize,
    pub addr: usize,
    pub size: usize,
}

// Call `mmap` to map memory into our process to hold all of the loadable 
// program header contents in a contiguous range. Right now the perms will be
// generic across the entire range as PROT_WRITE,
// later we'll go back and `mprotect` them appropriately
fn initial_mmap(size: usize) -> Result<usize, LucidErr> {
    // We don't want to specify a fixed address
    let addr = LOAD_TARGET as *mut libc::c_void;

    // Length is straight forward
    let length = size as libc::size_t;

    // Set the protections for now to writable
    let prot = libc::PROT_WRITE;

    // Set the flags, this is anonymous memory
    let flags = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

    // We don't have a file to map, so this is -1
    let fd = -1 as libc::c_int;

    // We don't specify an offset 
    let offset = 0 as libc::off_t;

    // Call `mmap` and make sure it succeeds
    let result = unsafe {
        libc::mmap(
            addr,
            length,
            prot,
            flags,
            fd,
            offset
        )
    };

    if result == libc::MAP_FAILED {
        return Err(LucidErr::from("Failed to `mmap` memory for Bochs"));
    }

    Ok(result as usize)
}

// Iterate through all the loadable segments and adjust their memory backing
// according to their permissions and load the binary data
pub fn load_segments(addr: usize, elf: &Elf) -> Result<(), LucidErr> {
    // Extract relevant data from loadable segments
    let mut load_segments = Vec::new();
    for ph in elf.program_headers.iter() {
        if ph.is_load() {
            load_segments.push((
                ph.flags,               // segment.0
                ph.vaddr    as usize,   // segment.1
                ph.memsz    as usize,   // segment.2
                ph.offset   as usize,   // segment.3
                ph.filesz   as usize,   // segment.4
            ));
        }
    }

    // Iterate through the loadable segments and change their perms and then 
    // copy the data over
    for segment in load_segments.iter() {
        // Copy the binary data over, the destination is where in our process
        // memory we're copying the binary data to. The source is where we copy
        // from, this is going to be an offset into the binary data in the file,
        // len is going to be how much binary data is in the file, that's filesz 
        // This is going to be unsafe no matter what
        let len = segment.4;
        let dst = (addr + segment.1) as *mut u8;
        let src = (elf.data[segment.3..segment.3 + len]).as_ptr();

        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, len);
        }

        // Calculate the `mprotect` address by adding the mmap address plus the
        // virtual address offset, we also mask off the last 0x1000 bytes so 
        // that we are always page-aligned as required by `mprotect`
        let mprotect_addr = ((addr + segment.1) & !(PAGE_SIZE - 1))
            as *mut libc::c_void;

        // Get the length
        let mprotect_len = segment.2 as libc::size_t;

        // Get the protection
        let mut mprotect_prot = 0 as libc::c_int;
        if segment.0 & 0x1 == 0x1 { mprotect_prot |= libc::PROT_EXEC; }
        if segment.0 & 0x2 == 0x2 { mprotect_prot |= libc::PROT_WRITE; }
        if segment.0 & 0x4 == 0x4 { mprotect_prot |= libc::PROT_READ; }

        // Call `mprotect` to change the mapping perms
        let result = unsafe {
            libc::mprotect(
                mprotect_addr,
                mprotect_len,
                mprotect_prot
            )
        };

        if result < 0 {
            return Err(LucidErr::from("Failed to `mprotect` memory for Bochs"));
        }
    }

    Ok(())
}

// Allocate memory for the stack via `mmap` and `mprotect` calls
// The allocation will look like this in memory:
// GUARD_SIZE (No perms)
// STACK_ALLOC_SIZE (Read/Write Actual Stack)
// GUARD_SIZE (No perms)
// Total is GUARD_SIZE * 2 + STACK_ALLOC_SIZE
fn allocate_stack() -> Result<usize, LucidErr> {
    let addr = std::ptr::null_mut::<libc::c_void>();
    let length = STACK_ALLOC_SIZE + (GUARD_SIZE * 2);
    let prot = libc::PROT_NONE;
    let flags = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;
    let fd = -1 as libc::c_int;
    let offset = 0 as libc::off_t;

    let base_alloc = unsafe {
        libc::mmap(
            addr,
            length,
            prot,
            flags,
            fd,
            offset
        )    
    };

    if base_alloc == libc::MAP_FAILED {
        return Err(LucidErr::from("Failed to `mmap` memory for Bochs stack"));
    }

    // Change the protections for the stack segment, calc the stack address
    let mprotect_addr = (base_alloc as usize + GUARD_SIZE) as *mut libc::c_void;
    let mprotect_len = STACK_ALLOC_SIZE;
    let mprotect_prot = libc::PROT_READ | libc::PROT_WRITE;

    let result = unsafe {
        libc::mprotect(
            mprotect_addr,
            mprotect_len,
            mprotect_prot
        )
    };

    if result < 0 {
        return Err(LucidErr::from("Failed to `mprotect` stack for Bochs"));
    }

    // Calculate what RSP we want to return, we're assuming that the stack data
    // once populated, will be <= the STACK_DATA_MAX, so we can safely calc
    // where we want RSP. We want to place it at the absolute end of the R/W
    // section as that will provide us with the most slack space as the stack 
    // grows down:
    // GUARD
    // STACK
    // STACK
    // STACK <-- RSP
    // STACK DATA
    // GUARD
    let rsp = (base_alloc as usize + GUARD_SIZE + STACK_ALLOC_SIZE)
        - STACK_DATA_MAX;
    assert!(rsp % PAGE_SIZE == 0); 

    // Return rsp
    Ok(rsp)
}

// Iterate through the arguments passed to the fuzzer, and determine if there
// are any arguments meant for Bochs, the strings will be placed on the stack 
// in reverse order so that arg[1] string is at a lower memory address than 
// arg[2] for example
fn parse_bochs_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();

    // Check to see if "--bochs-args" is present, if it is, capture all of the
    // args after as Bochs args
    let mut bochs_args = if let Some(idx) = args.iter().position(
        |arg| arg == "--bochs-args") {
        args[idx + 1..].to_vec()
    } else {
        Vec::new()
    };

    // Add in argv[0]
    bochs_args.insert(0, String::from("./bochs"));

    // Reverse the order of arguments
    bochs_args.into_iter().rev().collect()
}

// Pushes a u64 onto the stack
fn push_u64(stack: &mut Vec<u8>, value: u64) {
    let bytes = value.to_le_bytes();
    for &byte in bytes.iter().rev() {
        stack.insert(0, byte);
    }
}

// Pushes a NULL terminated string onto the "stack" and pads the string with 
// NULL bytes until we achieve 8-byte alignment
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

// I couldn't figure out how computers work so I had ChatGPT write this function
// for me to figure out how strings on the stack should work, but we got there!
fn _debug_print_stack(stack: &[u8], base_addr: usize) {
    // Ensure the stack length is a multiple of 8 (size of sizet)
    assert!(stack.len() % U64_SIZE == 0);

    let u64_slice: &[u64] = unsafe {
        std::slice::from_raw_parts(
            stack.as_ptr() as *const u64, stack.len() / 8)
    };

    for (i, &value) in u64_slice.iter().enumerate() {
        let offset = i * 8;
        let absolute_addr = base_addr + offset;
        println!("Offset: 0x{:X}, Absolute Address: 0x{:X}, Value: 0x{:016X}",
            offset, absolute_addr, value);
    }
}

// The stack layout should look like this when we're done, thanks to 
// https://articles.manugarg.com/aboutelfauxiliaryvectors for reference and
// @netspooky for their help
// 
// ==== LOWER ====
// RSP     -> argc
// argv[0] -> pointer
// argv[1] -> pointer
// ..
// argv[n] -> NULL
//
// envp[0] -> pointer
// envp[1] -> pointer
// ..
// envp[n] -> NULL
//
// auxv[0] -> pointer
// auxv[1] -> pointer
// ..
// auxv[n] -> AT_NULL vector
//
// padding
// 
// argv strings
// envvar strings
// end marker (NULL)
// ==== HIGHER ====
fn create_stack_data(base: usize, stack_addr: usize, elf: &Elf) ->
    Result<Vec<u8>, LucidErr> {
    // Create a vector to hold all of our stack data
    let mut stack_data = Vec::new();

    // Add the "end-marker" NULL, we're skipping adding any envvar strings for
    // now
    push_u64(&mut stack_data, 0u64);

    // Parse the argv entries for Bochs
    let args = parse_bochs_args();

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
            "Failed to Load Bochs, stack_data > STACK_DATA_MAX"));
    }

    Ok(stack_data)
}

fn create_stack(base: usize, elf: &Elf) -> Result<usize, LucidErr> {
    // Allocate memory for the stack
    let stack_addr = allocate_stack()?;

    // This should always be 16-byte aligned as the x86_64 ABI requires that 
    // at program entry, RSP % 16 == 0
    assert!(stack_addr % 16 == 0);

    // Populate a vector with all of the stack data
    let stack_data = create_stack_data(base, stack_addr, elf)?;

    // Copy the stack data into the allocated stack space
    let len = stack_data.len() as libc::size_t;
    let dst = stack_addr as *mut u8;
    let src = (stack_data[..stack_data.len()]).as_ptr();

    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, len);
    }

    Ok(stack_addr)
}

pub fn load_bochs(bochs_image: String) -> Result<Bochs, LucidErr> {
    // Read the executable file into memory
    let data = read(bochs_image).map_err(|_| LucidErr::from(
        "Unable to read binary data from Bochs binary"))?;

    // Parse ELF 
    let elf = parse_elf(&data)?;

    // We need to iterate through all of the loadable program headers and 
    // determine the size of the address range we need
    let mut mapping_size: usize = 0;
    for ph in elf.program_headers.iter() {
        if ph.is_load() {
            let end_addr = (ph.vaddr + ph.memsz) as usize;
            if mapping_size < end_addr { mapping_size = end_addr; }
        }
    }

    // Round the mapping up to a page
    if mapping_size % PAGE_SIZE > 0 {
        mapping_size += PAGE_SIZE - (mapping_size % PAGE_SIZE);
    }

    // Get an initial `mmap()` of the range
    let bochs_addr = initial_mmap(mapping_size)?;

    // Load the segments with their permissions and their binary data
    load_segments(bochs_addr, &elf)?;

    // Create a stack in memory for Bochs
    let stack_addr = create_stack(bochs_addr, &elf)?;

    // Return the entry point and RSP values
    let bochs = Bochs {
        entry: (bochs_addr as u64 + elf.elf_header.entry) as usize,
        rsp: stack_addr,
        addr: bochs_addr,
        size: mapping_size,
    };

    // Return to main
    Ok(bochs)
}