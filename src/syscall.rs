/// This file contains the logic for handling syscalls that Bochs attempts

use crate::context::{LucidContext, Fault, CTX_MAGIC, fault_handler};
use crate::{green, clear, fault};

// Anytime Bochs tries to return its own pid_t it gets this
const BOCHS_PID: i32 = 0x1337;

// Terminal size constants
const WS_ROW: libc::c_ushort = 25;
const WS_COL: libc::c_ushort = 160;
const WS_XPIXEL: libc::c_ushort = 0;
const WS_YPIXEL: libc::c_ushort = 0;

// File constants
const _STDIN:   libc::c_int = 0;
const STDOUT:   libc::c_int = 1;
const STDERR:   libc::c_int = 2;

// Write out the contents of an iovec to our own STDOUT 
fn write_iovec(iovec_p: *const libc::iovec) -> usize {
    // Get the underlying structure
    let iovec = unsafe { &*iovec_p };

    // Determine where we're reading from
    let base = iovec.iov_base as *const u8;

    // Determine read length
    let len = iovec.iov_len;

    // Loop and write each character
    for i in 0..len {
        // Get the current byte to print
        let byte = unsafe { *base.add(i) };

        // Print the current byte
        print!("{}", byte as char);
    }

    len
}

// This is where we process Bochs making a syscall
pub extern "C" fn lucid_syscall(contextp: *mut LucidContext, n: usize,
    a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize)
    -> u64 {
    // Get the context
    let context = unsafe { &mut *contextp };

    // Make sure the magic number is correct as a semi-sanity check
    if context.magic != CTX_MAGIC { 
        fault!(contextp, Fault::SyscallMagic);
    }

    // Match on the syscall number
    match n {
        // read
        0x0 => {
            // Check to make sure we have the requested file-descriptor
            let Some(file) = context.files.get_file(a1 as i32) else {
                println!("Non-existent file fd: {}", a1);
                fault!(contextp, Fault::NoFile);
            };

            // Now we need to make sure the buffer passed to read isn't NULL
            let buf_p = a2 as *mut u8;
            if buf_p.is_null() {
                context.tls.errno = libc::EINVAL;
                return -1_i64 as u64;
            }

            // Adjust read size if necessary
            let length = std::cmp::min(a3, file.contents.len() - file.cursor);

            // Copy the contents over to the buffer
            unsafe { 
                std::ptr::copy(
                    file.contents.as_ptr().add(file.cursor),    // src
                    buf_p,                                      // dst
                    length);                                    // len
            }

            // Adjust the file cursor
            file.cursor += length;

            // Success
            length as u64
        },
        // open
        0x2 => {
            // Get pointer to path string we're trying to open
            let path_p = a1 as *const libc::c_char;

            // Make sure it's not NULL
            if path_p.is_null() {
                fault!(contextp, Fault::NullPath);
            }            

            // Create c_str from pointer
            let c_str = unsafe { std::ffi::CStr::from_ptr(path_p) };

            // Create Rust str from c_str
            let Ok(path_str) = c_str.to_str() else {
                fault!(contextp, Fault::InvalidPathStr);
            };

            // Validate permissions
            if a2 as i32 != 32768 {
                println!("Unhandled file permissions: {}", a2);
                fault!(contextp, Fault::Syscall);
            }

            // Open the file
            let fd = context.files.open(path_str);
            if fd.is_err() {
                // We couldn't find the requested file, return -1
                return -1_i64 as u64;
            }

            // Success
            fd.unwrap() as u64
        },
        // close
        0x3 => {
            // Success, we closed it for sure dude
            0
        },
        // mmap
        0x9 => {
            // If a1 is NULL, we just do a normal mmap
            if a1 == 0 {
                if context.mmu.do_mmap(a2, a3, a4, a5, a6).is_err() {
                    fault!(contextp, Fault::InvalidMmap);
                }

                // Succesful regular mmap
                return context.mmu.curr_mmap as u64;
            }

            // We have a non-null address, we don't support fixed address mmap
            // for addresses that are not in the brk pool
            if !context.mmu.in_brk(a1) {
                fault!(contextp, Fault::InvalidMmap);
            }

            // We have a brk pool address to mmap, which amounts to a NOP
            a1 as u64
        },
        // munmap
        0xB => {
            // Right now, we don't re-use memory, return success
            0
        },
        // brk
        0xC => {
            // Try to update the program break
            if context.mmu.update_brk(a1).is_err() {
                fault!(contextp, Fault::InvalidBrk);
            }

            // Return the program break
            context.mmu.curr_brk as u64
        },
        // ioctl
        0x10 => {
            // Make sure the fd is 1, that's all we handle right now?
            if a1 != 1 {
                fault!(contextp, Fault::Syscall);
            }

            // Check the `cmd` argument
            match a2 as u64 {
                // Requesting window size
                libc::TIOCGWINSZ => {   
                    // Arg 3 is a pointer to a struct winsize
                    let winsize_p = a3 as *mut libc::winsize;

                    // If it's NULL, return an error, set errno
                    if winsize_p.is_null() {
                        context.tls.errno = libc::EINVAL;
                        return -1_i64 as u64;
                    }

                    // Deref the raw pointer
                    let winsize = unsafe { &mut *winsize_p };

                    // Set to some constants
                    winsize.ws_row      = WS_ROW;
                    winsize.ws_col      = WS_COL;
                    winsize.ws_xpixel   = WS_XPIXEL;
                    winsize.ws_ypixel   = WS_YPIXEL;

                    // Return success
                    0
                },
                _ => {
                    fault!(contextp, Fault::Syscall);
                }
            }
        },
        // writev
        0x14 => {
            // Get the fd
            let fd = a1 as libc::c_int;

            // Make sure it's an fd we handle
            if fd != STDOUT && fd != STDERR {
                println!("Attempted write to fd: {}", fd);
                fault!(contextp, Fault::Syscall);
            }

            // An accumulator that we return
            let mut bytes_written = 0;

            // Get the iovec count
            let iovcnt = a3 as libc::c_int;

            // Get the pointer to the iovec
            let mut iovec_p = a2 as *const libc::iovec;

            // If the pointer was NULL, just return error
            if iovec_p.is_null() {
                return -1_i64 as u64;
            }

            // Iterate through the iovecs and write the contents
            green!();
            for i in 0..iovcnt {
                bytes_written += write_iovec(iovec_p);

                // Update iovec_p
                iovec_p = unsafe { iovec_p.offset(1 + i as isize) };
            }
            clear!();

            // Return how many bytes were written total
            bytes_written as i64 as u64
        },
        // nanosleep
        0x23 => {
            0
        },
        // arch_prctl
        0x9E => {
            const ARCH_SET_FS: usize = 0x1002;
            match a1 {
                // Program is trying to set the FS register, probably for TLS
                ARCH_SET_FS => {
                    // Just make sure this is a valid pointer
                    let fs_val_p = a2 as *const libc::c_ulong;
                    if fs_val_p.is_null() {
                        context.tls.errno = libc::EINVAL;
                        return -1_i64 as u64;
                    }

                    // Deref the raw pointer
                    let fs_val = unsafe { &*fs_val_p };

                    // Track the FS register value it wanted to set 
                    context.fs_reg = *fs_val as usize;

                    // Success
                    0
                }
                _ => {
                    println!("Unhandled arch_prctl code: 0x{:X}", a1);
                    fault!(contextp, Fault::Syscall);
                }
            }
        },
        // set_tid_address
        0xDA => {
            // Just return Boch's pid, no need to do anything
            BOCHS_PID as i64 as u64
        },
        // clock_gettime
        0xE4 => {
            // Validate the clock id
            if a1 as i32 != libc::CLOCK_REALTIME {
                println!("Unhandled clock_gettime clk_id: {}", a1);
                fault!(contextp, Fault::Syscall);
            }

            // Make sure tp is not null
            let tp_p = a2 as *mut libc::timespec;
            if tp_p.is_null() {
                context.tls.errno = libc::EFAULT;
                return -1_i64 as u64;
            }

            // Deref the raw pointer
            let tp = unsafe { &mut *tp_p };

            // Update the current clock time
            context.clock_time += 1;

            // Set the value
            tp.tv_sec = 0;
            tp.tv_nsec = context.clock_time as i64;

            // Success
            0
        },
        // exit_group
        0xE7 => {
            fault!(contextp, Fault::EarlyBochsExit);
        }
        _ => {
            println!("Unhandled syscall number: 0x{:X}", n);
            fault!(contextp, Fault::Syscall);
        }
    }
}