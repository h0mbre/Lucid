//! This file contains all of the logic related to capturing Bochs snapshots
//! and restoring them
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use std::io::Write;
use std::os::unix::io::AsRawFd;

use crate::context::{fault_handler, LucidContext, RegisterBank};
use crate::err::LucidErr;
use crate::files::FileTable;
use crate::misc::PAGE_SIZE;
use crate::mmu::Mmu;
use crate::{fault, prompt};

/// File path where we save the block of snapshot data
const DEVSHM_SNAPSHOT: &str = "/dev/shm/lucid_snapshot";

/// A data structure we use to inform a memcpy operation
#[derive(Clone)]
struct ResetIoVec {
    src: usize,
    dst: usize,
    len: usize,
}

/// Represents the snapshot data for Bochs
#[derive(Clone, Default)]
pub struct Snapshot {
    pub base: usize,        // Base address for writable memory block
    pub length: usize,      // Length of writable memory block
    pub regs: RegisterBank, // GPRs for Bochs
    mmu: Mmu,               // The saved state of the MMU
    _files: FileTable,      // Saved file table

    // Dirty page tracking members
    dirty_map: Vec<u8>,                    // Dirty page bitmap that Bochs updates
    pub dirty_map_addr: usize,             // Pointer to the dirty_map that Bochs uses
    pub dirty_block_start: usize,          // Beginning of dirty page range
    pub dirty_block_length: usize,         // Length of the dirty page range
    dirty_reset_list: Vec<(usize, usize)>, // List of ranges to reset (addr, len)
    reset_io_vecs: Vec<ResetIoVec>,        // List of memcpy operations

    // Statistics
    pub num_dirty_pages: usize, // The number of dirty pages observed
    pub num_memcpys: usize,     // Number of memcpy operations we do

    // For resetting memory
    data: usize, // Location in memory of saved snapshot data
}

impl Snapshot {
    /// Creates a new instance of a Snapshot
    pub fn new(base: usize, length: usize) -> Self {
        // Calculate the number of potential dirty pages, round up
        let num_pages = length.div_ceil(PAGE_SIZE);

        // Calculate the number of bytes we need in the bitmap, round up
        let bitmap_size = num_pages.div_ceil(8);

        // Allocate bitmap
        let dirty_map = vec![0u8; bitmap_size];

        // Mark the map address
        let dirty_map_addr = dirty_map.as_ptr() as usize;

        // Create snapshot
        Snapshot {
            base,
            length,
            regs: RegisterBank::default(),
            mmu: Mmu::default(),
            _files: FileTable::default(),
            dirty_map,
            dirty_map_addr,
            dirty_block_start: base,
            dirty_block_length: length,
            dirty_reset_list: Vec::new(),
            data: usize::default(),
            reset_io_vecs: Vec::new(),
            num_dirty_pages: usize::default(),
            num_memcpys: usize::default(),
        }
    }
}

/// Writes the contiguous block of writable memory belonging to Bochs to disk,
/// writable memory includes:
/// - stack
/// - heap/brk
/// - writable ELF segments
/// - extended CPU state save area
fn save_snapshot_devshm(base: usize, length: usize) -> Result<usize, LucidErr> {
    // Create slice from memory
    let slice = unsafe { std::slice::from_raw_parts(base as *const u8, length) };

    // Create file in /dev/shm
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(DEVSHM_SNAPSHOT)
        .map_err(|_| LucidErr::from("Failed to create snapshot file in /dev/shm"))?;

    // Write the slice to the file
    file.write_all(slice)
        .map_err(|_| LucidErr::from("Failed to write to snapshot file in /dev/shm"))?;

    // Make sure write goes through
    file.sync_all()
        .map_err(|_| LucidErr::from("Failed to flush disk write in snapshot"))?;

    // Get an fd for the /dev/shm file
    let fd = file.as_raw_fd();

    // Create CString
    let Ok(c_name) = std::ffi::CString::new(DEVSHM_SNAPSHOT) else {
        return Err(LucidErr::from("Failed to create /dev/shm name"));
    };

    // Unlink the shmem object
    let result = unsafe { libc::unlink(c_name.as_ptr()) };
    if result == -1 {
        return Err(LucidErr::from("Failed to unlink /dev/shm snapshot"));
    }

    // mmap the file
    let result = unsafe {
        libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            length,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };

    if result == libc::MAP_FAILED {
        return Err(LucidErr::from("Failed to mmap snapshot file"));
    }

    Ok(result as usize)
}

/// Takes a snapshot of all Bochs' mutable state that we care about when we go
/// to restore Bochs to it's pre-fuzzcase execution state
pub fn take_snapshot(contextp: *mut LucidContext) {
    prompt!("Taking snapshot of Bochs...");

    // Get a handle to the underlying context
    let context = LucidContext::from_ptr_mut(contextp);

    // Get base and length for readability
    let base = context.snapshot.base;
    let length = context.snapshot.length;
    prompt!("Snapshot dimensions: 0x{:X} - 0x{:X}", base, base + length);

    // Save the snapshot contents to disk in /dev/shm
    prompt!("Saving snapshotted memory to /dev/shm...");
    let save_result = save_snapshot_devshm(base, length);
    if let Err(e) = save_result {
        fault!(contextp, e);
    }
    prompt!("Saved snapshotted memory");

    // Get the save address
    context.snapshot.data = save_result.unwrap();

    // Snapshot the MMU
    context.snapshot.mmu = context.mmu.clone();

    // Snapshot the register state which is currently in register bank
    context.snapshot.regs = context.bochs_regs.clone();

    // Mprotect the range as non-writable
    let result = unsafe {
        libc::mprotect(
            context.snapshot.base as *mut libc::c_void,
            context.snapshot.length,
            libc::PROT_READ,
        )
    };

    if result == -1 {
        fault!(
            contextp,
            LucidErr::from("Failed to mprotect snapshot memory")
        );
    }

    prompt!("Snapshot complete!");
}

/// Walks the Snapshot's dirty page map looking for pages that were dirtied
/// for the first time during the fuzzing iteration
fn walk_dirty_page_map(snapshot: &mut Snapshot) -> Vec<usize> {
    // Collect dirty pages here
    let mut dirty_pages = Vec::new();

    // Iterate through the page map and collect dirty pages
    for (byte_idx, &byte) in snapshot.dirty_map.iter().enumerate() {
        if byte == 0 {
            continue;
        }

        // Iterate through each bit of this byte
        for bit_idx in 0..8 {
            // Find all the set bits
            if (byte & (1 << bit_idx)) != 0 {
                // Calculate the page index
                let page_idx = byte_idx * 8 + bit_idx;

                // Calculate the page address
                let page_addr = snapshot.dirty_block_start + page_idx * 4096;

                // Store the page
                dirty_pages.push(page_addr);
            }
        }
    }

    // Clear the dirty map
    snapshot.dirty_map.fill(0);

    // Return the dirty pages
    dirty_pages
}

/// Merges all ranges of dirty pages. For example if a previous range was
/// 0x0 - 0x3000 and a fuzzing iteration then dirtied page 0x3000 - 0x4000,
/// we would merge the range to be 0x0 - 0x4000. This function continuously
/// merges until there is no more possible merging.
fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if ranges.is_empty() {
        return ranges;
    }

    // Sort ranges by their starting address
    ranges.sort_by_key(|range| range.0);

    // Store newly merged ranges here
    let mut merged = Vec::new();

    // Start with the first range
    let mut current = ranges[0];

    // Iterate through remaining ranges
    for range in ranges.iter().skip(1) {
        let (start, length) = range;
        let end = start + length;
        let current_end = current.0 + current.1;

        // Merge if overlapping or page-adjacent
        if current_end >= *start {
            let new_end = current_end.max(end);
            current.1 = new_end - current.0;
        } else {
            merged.push(current);
            current = (*start, *length);
        }
    }

    // Push the final range
    merged.push(current);

    merged
}

/// Takes a list of newly dirtied pages and adjusts existing ranges of dirty
/// pages to restore incorporating the new pages
fn adjust_reset_ranges(
    mut reset_list: Vec<(usize, usize)>,
    dirty_pages: Vec<usize>,
) -> Vec<(usize, usize)> {
    // If the reset list is empty, create a new one
    if reset_list.is_empty() {
        for page in dirty_pages {
            reset_list.push((page, PAGE_SIZE));
        }
    }
    // Iterate through the dirty pages in order
    else {
        for page in dirty_pages {
            let mut added = false;

            for entry in &mut reset_list {
                let (start, length) = entry;
                let end = *start + *length;

                // Check to see if our page can be prepended to this range
                if page == *start - PAGE_SIZE {
                    // Our page comes right before this range, adjust the range
                    entry.0 = page;
                    entry.1 += PAGE_SIZE;
                    added = true;
                    break;
                }

                // Check to see if our page can be added to the end of this range
                if page == end {
                    // Our page comes at the end of this range, add to its length
                    entry.1 += PAGE_SIZE;
                    added = true;
                    break;
                }
            }

            // We didn't find a range we fit into, create a new range
            if !added {
                reset_list.push((page, PAGE_SIZE));
            }
        }
    }

    // It's possible that a new page could've combined two ranges, go through
    // and concat any ranges we can recursively
    merge_ranges(reset_list)
}

/// Adjusts the existing list of ResetIoVecs which are used to perform the actual
/// memcpy operations that copy snapshot data back over dirtied data by incorporating
/// the latest ranges of dirty pages discovered during fuzzing
fn adjust_io_vecs(snapshot: &Snapshot) -> Vec<ResetIoVec> {
    // Collect io vecs as we create them
    let mut new = Vec::new();

    // Iterate through reset ranges and create arguments to memcpy operations
    for (start, length) in snapshot.dirty_reset_list.iter() {
        // Calculate the offset of start
        let offset = start - snapshot.dirty_block_start;

        // Create io vec
        new.push(ResetIoVec {
            src: offset + snapshot.data, // Snapshot buffer to copy from
            dst: *start,                 // Dirty data to reset
            len: *length,
        });
    }

    new
}

/// A memcpy of snapshot data overtop data dirtied during fuzzing
#[inline]
fn reset_dirty_memory(iovec: &[ResetIoVec]) {
    for vec in iovec.iter() {
        unsafe {
            std::ptr::copy_nonoverlapping(vec.src as *const u8, vec.dst as *mut u8, vec.len);
        }
    }
}

/// Restores Bochs to its snapshot state for the next fuzzing iteration
pub fn restore_snapshot(contextp: *mut LucidContext) -> Result<(), LucidErr> {
    // Get a handle to the underlying context
    let context = LucidContext::from_ptr_mut(contextp);

    // We don't handle dirty files yet
    if context.dirty_files {
        return Err(LucidErr::from(
            "Dirty files detected while restoring snapshot",
        ));
    }

    // Restore the MMU
    context.mmu.restore(&context.snapshot.mmu);

    // Check the dirty page flag and walk the bitmap if there are new dirty
    // pages
    if context.new_dirty_page == 1 {
        let dirty_pages = walk_dirty_page_map(&mut context.snapshot);

        // Update statistics
        context.snapshot.num_dirty_pages += dirty_pages.len();

        // Get a copy of the reset list
        let reset_list = context.snapshot.dirty_reset_list.clone();

        // Adjust the reset ranges
        context.snapshot.dirty_reset_list = adjust_reset_ranges(reset_list, dirty_pages);

        // Adjust the iovec list
        context.snapshot.reset_io_vecs = adjust_io_vecs(&context.snapshot);

        // Update statistics
        context.snapshot.num_memcpys = context.snapshot.reset_io_vecs.len();

        // Reset the dirty page flag
        context.new_dirty_page = 0;
    }

    // Restore dirty memory
    reset_dirty_memory(&context.snapshot.reset_io_vecs);

    Ok(())
}
