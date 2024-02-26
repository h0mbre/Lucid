/// This file contains the logic for handling syscalls that Bochs attempts

use crate::context::{LucidContext, Fault, fault_handler};
use crate::{green, clear};
use crate::misc::PROMPT_PADDING;

// Anytime Bochs tries to return its own pid_t it gets this
const BOCHS_PID: i32 = 0x1337;

// Terminal size constants
const WS_ROW: libc::c_ushort = 25;
const WS_COL: libc::c_ushort = 160;
const WS_XPIXEL: libc::c_ushort = 0;
const WS_YPIXEL: libc::c_ushort = 0;

// File constants
const STDOUT: libc::c_int = 1;

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
    a1: usize, a2: usize, a3: usize, _a4: usize, _a5: usize, _a6: usize)
    -> i64 {
    // Get the context
    let _context = unsafe { &*contextp };

    // Match on the syscall number
    match n {
        // ioctl
        0x10 => {
            // Make sure the fd is 1, that's all we handle right now?
            if a1 != 1 {
                fault_handler(contextp, Fault::Syscall);
            }

            // Check the `cmd` argument
            match a2 as u64 {
                // Requesting window size
                libc::TIOCGWINSZ => {   
                    // Arg 3 is a pointer to a struct winsize
                    let winsize_p = a3 as *mut libc::winsize;

                    // If it's NULL, return an error, we don't set errno yet
                    // that's a weird problem
                    // TODO: figure out that whole TLS issue yikes
                    if winsize_p.is_null() {
                        return -1;
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
                    fault_handler(contextp, Fault::Syscall);
                    panic!();
                }
            }
        },
        // writev
        0x14 => {
            // Get the fd
            let fd = a1 as libc::c_int;

            // Make sure it's an fd we handle
            if fd != STDOUT {
                fault_handler(contextp, Fault::Syscall);
                panic!();
            }

            // An accumulator that we return
            let mut bytes_written = 0;

            // Get the iovec count
            let iovcnt = a3 as libc::c_int;

            // Get the pointer to the iovec
            let mut iovec_p = a2 as *const libc::iovec;

            // If the pointer was NULL, just return error
            if iovec_p.is_null() {
                return -1;
            }

            // Iterate through the iovecs and write the contents
            green!();
            print!("{}", PROMPT_PADDING);
            for i in 0..iovcnt {
                bytes_written += write_iovec(iovec_p);

                // Update iovec_p
                iovec_p = unsafe { iovec_p.offset(1 + i as isize) };
            }
            clear!();

            // Return how many bytes were written total
            bytes_written as i64
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
                    if a2 == 0 { return -1; }
                    0
                }
                _ => {
                    println!("Unhandled arch_prctl code: 0x{:X}", a1);
                    fault_handler(contextp, Fault::Syscall);
                    panic!();
                }
            }
        },
        // set_tid_address
        0xDA => {
            // Just return Boch's pid, no need to do anything
            BOCHS_PID as i64
        },
        // exit_group
        0xE7 => {
            fault_handler(contextp, Fault::EarlyBochsExit);
            panic!();
        }
        _ => {
            println!("Unhandled syscall number: 0x{:X}", n);
            fault_handler(contextp, Fault::Syscall);
            panic!();
        }
    }
}