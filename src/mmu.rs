/// This file contains all of the logic necessary to manage dynamically 
/// allocated memory that Bochs asks for and uses (brk, mmap)
use crate::err::LucidErr;

// Duh
const PAGE_SIZE: usize = 0x1000;

// The default size the MMU mmaps for brk pool
const DEFAULT_BRK_SIZE: usize = 0x1000 * 8;

// The default size the MMU mmaps for mmap pool
const DEFAULT_MMAP_SIZE: usize = 0x1000 * 0x1000;

// Structure to track memory usage in Bochs
#[derive(Clone)]
pub struct Mmu {
    pub brk_base: usize,        // Base address of brk region, never changes
    pub brk_size: usize,        // Size of the program break region
    pub curr_brk: usize,        // The current program break
    
    pub mmap_base: usize,       // Base address of the `mmap` pool
    pub mmap_size: usize,       // Size of the `mmap` pool
    pub curr_mmap: usize,       // The current `mmap` page base
    pub next_mmap: usize,       // The next allocation base address
}

impl Mmu {
    pub fn new() -> Result<Self, LucidErr> {
        // We don't care where it's mapped
        let addr = std::ptr::null_mut::<libc::c_void>();

        // Straight-forward
        let length = (DEFAULT_BRK_SIZE + DEFAULT_MMAP_SIZE) as libc::size_t;

        // This is normal
        let prot = libc::PROT_WRITE | libc::PROT_READ;

        // This might change at some point?
        let flags = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

        // No file backing
        let fd = -1 as libc::c_int;

        // No offset
        let offset = 0 as libc::off_t;

        // Try to `mmap` this block
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
            return Err(LucidErr::from("Failed `mmap` memory for MMU"));
        }

        // Create MMU
        Ok(Mmu {
            brk_base: result as usize,
            brk_size: DEFAULT_BRK_SIZE,
            curr_brk: result as usize,
            mmap_base: result as usize + DEFAULT_BRK_SIZE,
            mmap_size: DEFAULT_MMAP_SIZE,
            curr_mmap: result as usize + DEFAULT_BRK_SIZE,
            next_mmap: result as usize + DEFAULT_BRK_SIZE,
        })
    }

    // Logic for handling a `brk` syscall
    pub fn update_brk(&mut self, addr: usize) -> Result<(), ()> {
        // If addr is NULL, just return nothing to do
        if addr == 0 { return Ok(()); }

        // Check to see that the new address is in a valid range
        let limit = self.brk_base + self.brk_size;
        if !(self.curr_brk..limit).contains(&addr) { return Err(()); }

        // So we have a valid program break address, update the current break
        self.curr_brk = addr;

        Ok(())
    }

    // Check to see if a given address is in the program break
    pub fn in_brk(&self, addr: usize) -> bool {
        (self.brk_base..self.curr_brk).contains(&addr)
    }

    // Logic for handling a `mmap` syscall with no fixed address support
    pub fn do_mmap(
        &mut self,
        len: usize,
        prot: usize,
        flags: usize,
        fd: usize,
        offset: usize
    ) -> Result<(), ()> {
        // Page-align the len
        let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Make sure we have capacity left to satisfy this request
        if len + self.next_mmap > self.mmap_base + self.mmap_size { 
            return Err(());
        }

        // Sanity-check that we don't have any weird `mmap` arguments
        if prot as i32 != libc::PROT_READ | libc::PROT_WRITE {
            return Err(())
        }

        if flags as i32 != libc::MAP_PRIVATE | libc::MAP_ANONYMOUS {
            return Err(())
        }

        if fd as i64 != -1 {
            return Err(())
        }

        if offset != 0 {
            return Err(())
        }

        // Set current to next, and set next to current + len
        self.curr_mmap = self.next_mmap;
        self.next_mmap = self.curr_mmap + len;

        // curr_mmap now represents the base of the new requested allocation
        Ok(())
    }
}