//! This file contains all of the logic necessary to manage dynamically
//! allocated memory that Bochs asks for and uses (brk, mmap)
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use crate::err::LucidErr;
use crate::misc::PAGE_SIZE;

/// A megabyte of memory as a power of 2
const MEGABYTE: usize = 1_048_576;

/// The default size the MMU mmaps for brk pool
const DEFAULT_BRK_SIZE: usize = MEGABYTE;

/// The default size the MMU mmaps for mmap pool, this will be very dependent
/// on how much memory the Bochs guest has. This will need to be manually
/// adjusted if the Bochs guest has more memory than this.
const DEFAULT_MMAP_SIZE: usize = MEGABYTE * 512;

/// Our data structure to track dynamic memory usage in Bochs. We just pre-allocate
/// a large block of memory to use and keep bumping the current allocation towards
/// the boundary. As of now, we don't do any freeing or re-using of memory
#[derive(Clone, Default)]
pub struct Mmu {
    pub map_base: usize,   // Base address for entire mapping
    pub map_length: usize, // Total size of mapping
    pub brk_base: usize,   // Base address of brk region, never changes
    pub brk_size: usize,   // Size of the program break region
    pub curr_brk: usize,   // The current program break

    pub mmap_base: usize, // Base address of the `mmap` pool
    pub mmap_size: usize, // Size of the `mmap` pool
    pub curr_mmap: usize, // The current `mmap` page base
    pub next_mmap: usize, // The next allocation base address
}

impl Mmu {
    /// Create a new Mmu data structure
    pub fn new(map_address: usize) -> Result<Self, LucidErr> {
        // Straight-forward
        let length = (DEFAULT_BRK_SIZE + DEFAULT_MMAP_SIZE) as libc::size_t;
        assert!(length.is_multiple_of(PAGE_SIZE));

        // Try to `mmap` this block
        let result = unsafe {
            libc::mmap(
                map_address as *mut libc::c_void,
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        };

        if result == libc::MAP_FAILED {
            return Err(LucidErr::from("Failed `mmap` memory for MMU"));
        }

        // Create MMU
        Ok(Mmu {
            map_base: result as usize,
            map_length: length as usize,
            brk_base: result as usize,
            brk_size: DEFAULT_BRK_SIZE,
            curr_brk: result as usize,
            mmap_base: result as usize + DEFAULT_BRK_SIZE,
            mmap_size: DEFAULT_MMAP_SIZE,
            curr_mmap: result as usize + DEFAULT_BRK_SIZE,
            next_mmap: result as usize + DEFAULT_BRK_SIZE,
        })
    }

    /// `brk` syscalls are handled here
    pub fn update_brk(&mut self, addr: usize) -> Result<(), ()> {
        // If addr is NULL, just return nothing to do
        if addr == 0 {
            return Ok(());
        }

        // Check to see that the new address is in a valid range
        let limit = self.brk_base + self.brk_size;
        if !(self.curr_brk..limit).contains(&addr) {
            return Err(());
        }

        // So we have a valid program break address, update the current break
        self.curr_brk = addr;

        Ok(())
    }

    /// Check to see if a given address is in the program break
    pub fn in_brk(&self, addr: usize) -> bool {
        (self.brk_base..self.curr_brk).contains(&addr)
    }

    /// Logic for handling a `mmap` syscall with no fixed address support
    pub fn do_mmap(
        &mut self,
        len: usize,
        prot: usize,
        flags: usize,
        fd: usize,
        offset: usize,
    ) -> Result<(), &str> {
        // Page-align the len
        let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Make sure we have capacity left to satisfy this request
        if len + self.next_mmap > self.mmap_base + self.mmap_size {
            return Err("OOM");
        }

        // Sanity-check that we don't have any weird `mmap` arguments
        if prot as i32 != libc::PROT_READ | libc::PROT_WRITE {
            return Err("bad `prot` value");
        }

        if flags as i32 != libc::MAP_PRIVATE | libc::MAP_ANONYMOUS {
            return Err("bad `flags` value");
        }

        if fd as i64 != -1 {
            return Err("`fd` value != -1");
        }

        if offset != 0 {
            return Err("`offset` != 0");
        }

        // Set current to next, and set next to current + len
        self.curr_mmap = self.next_mmap;
        self.next_mmap = self.curr_mmap + len;

        // curr_mmap now represents the base of the new requested allocation
        Ok(())
    }

    /// Copy the contents of an existing MMU, used for snapshot restore
    pub fn restore(&mut self, mmu: &Mmu) {
        self.map_base = mmu.map_base;
        self.map_length = mmu.map_length;
        self.brk_base = mmu.brk_base;
        self.brk_size = mmu.brk_size;
        self.curr_brk = mmu.curr_brk;
        self.mmap_base = mmu.mmap_base;
        self.mmap_size = mmu.mmap_size;
        self.curr_mmap = mmu.curr_mmap;
        self.next_mmap = mmu.next_mmap;
    }

    /// Search MMU memory for pattern
    pub fn search_memory(&self, pattern: &[u8]) -> Vec<usize> {
        assert!(self.map_length > pattern.len());
        let mut needles = Vec::new();

        // Determine the last index to search from
        let last_idx = self.map_length - pattern.len();

        // Iterate through memory looking for pattern
        let mut curr = self.map_base;
        for _ in 0..last_idx {
            // Make a slice from current position
            let curr_slice =
                unsafe { std::slice::from_raw_parts(curr as *const u8, pattern.len()) };

            // Check for match
            if curr_slice == pattern {
                needles.push(curr);
            }

            // Increment current
            curr += 1;
        }

        needles
    }
}
