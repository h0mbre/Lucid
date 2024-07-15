/// This file contains all of the logic related to capturing Bochs snapshots
/// and restoring them
use crate::context::{fault_handler, LucidContext, RegisterBank};
use crate::err::LucidErr;
use crate::files::FileTable;
use crate::mmu::Mmu;
use crate::{fault, prompt};

const SHMEM_NAME: &str = "/LucidShmem";

#[derive(Clone, Default)]
pub struct Snapshot {
    fd: i32,                // File descriptor for shmem object
    pub base: usize,        // Base address for writable memory block
    pub length: usize,      // Length of writable memory block
    pub regs: RegisterBank, // GPRs for Bochs
    mmu: Mmu,               // The saved state of the MMU
    _files: FileTable,      // Saved file table
}

// Create shared object and resize it
fn create_shmem(contextp: *mut LucidContext, base: usize, length: usize) -> i32 {
    // Create CString
    let Ok(c_name) = std::ffi::CString::new(SHMEM_NAME) else {
        fault!(contextp, LucidErr::from("Failed to create shmem name"));
    };

    // Create the shared memory object, think of it as creating/opening a file
    let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o666) };
    if fd == -1 {
        fault!(contextp, LucidErr::from("Failed to shm_open"));
    }

    // Next we have to set its length
    let result = unsafe { libc::ftruncate(fd, length as libc::off_t) };
    if result == -1 {
        fault!(contextp, LucidErr::from("Failed to ftruncate"));
    }

    // Now that we set the length, write the snapshot data to it
    let mut bytes_total = 0;
    let mut curr_base = base;
    while bytes_total < length as isize {
        let bytes_written = unsafe {
            libc::write(
                fd,
                curr_base as *const libc::c_void,
                length - bytes_total as usize,
            )
        };

        // Check for failure
        if bytes_written == -1 {
            fault!(contextp, LucidErr::from("Failed a write operation"));
        }

        // Check for EOF
        if bytes_written == 0 {
            break;
        }

        // Update the total
        bytes_total += bytes_written;

        // Update the base
        curr_base = base + bytes_total as usize;
    }

    if bytes_total != length as isize {
        fault!(
            contextp,
            LucidErr::from("Failed to write snapshot data to shmem")
        );
    }

    // Unlink the shmem object
    let result = unsafe { libc::shm_unlink(c_name.as_ptr()) };
    if result == -1 {
        fault!(contextp, LucidErr::from("Failed to unlink shmem object"));
    }

    // Return the fd
    fd
}

// Take a snapshot of Bochs' state
pub fn take_snapshot(contextp: *mut LucidContext) {
    prompt!("Taking snapshot of Bochs...");

    // Get a handle to the underlying context
    let context = LucidContext::from_ptr_mut(contextp);

    // Create the shared memory object
    prompt!(
        "Snapshot dimensions: 0x{:X} - 0x{:X}",
        context.snapshot.base,
        context.snapshot.base + context.snapshot.length
    );
    context.snapshot.fd = create_shmem(contextp, context.snapshot.base, context.snapshot.length);

    // Snapshot the MMU
    context.snapshot.mmu = context.mmu.clone();

    // Snapshot the register state which is currently in register bank
    context.snapshot.regs = context.bochs_regs.clone();

    prompt!("Snapshot complete!");
}

// This function will take the saved data in the shm object and just mmap it
// overtop of the writable memory block to restore the memory contents
#[inline]
fn restore_memory_block(base: usize, length: usize, fd: i32) -> Result<(), LucidErr> {
    // mmap the saved memory contents overtop of the dirty contents
    let result = unsafe {
        libc::mmap(
            base as *mut libc::c_void,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            fd,
            0,
        )
    };

    if result == libc::MAP_FAILED || result != base as *mut libc::c_void {
        return Err(LucidErr::from("Failed to mmap restore snapshot"));
    }

    Ok(())
}

// Restore Bochs' to its snapshot state
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

    // Restore the dirty memory block
    let base = context.snapshot.base;
    let length = context.snapshot.length;
    let fd = context.snapshot.fd;
    restore_memory_block(base, length, fd)?;

    Ok(())
}
