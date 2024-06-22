/// This file contains the logic for handling syscalls that Bochs attempts
use crate::context::{LucidContext, fault_handler};
use crate::files::File;
use crate::{green, clear, fault};
use crate::err::LucidErr;

// Anytime Bochs tries to return its own pid_t it gets this
const BOCHS_PID: i32 = 0x1337;

// File constants
const _STDIN:   libc::c_int = 0;
const STDOUT:   libc::c_int = 1;
const STDERR:   libc::c_int = 2;

// Terminal size constants
const WS_ROW: libc::c_ushort = 25;
const WS_COL: libc::c_ushort = 160;
const WS_XPIXEL: libc::c_ushort = 0;
const WS_YPIXEL: libc::c_ushort = 0;

// Write out the contents of an iovec to our own STDOUT 
fn write_iovec(iovec_p: *const libc::iovec, verbose: bool) -> usize {
    // Get the underlying structure
    let iovec = unsafe { &*iovec_p };

    // Determine where we're reading from
    let base = iovec.iov_base as *const u8;

    // Determine read length
    let len = iovec.iov_len;

    // Loop and write each character
    if verbose {
        for i in 0..len {
            // Get the current byte to print
            let byte = unsafe { *base.add(i) };

            // Print the current byte
            print!("{}", byte as char);
        }
    }

    len
}

// Special function to handle writes to STDOUT and STDERR
fn write_stdout_stderr(mut iovec_p: *const libc::iovec, iovcnt: i32,
    verbose: bool) -> usize {
    // Format terminal output
    if verbose { green!(); }
    
    // Accumulator
    let mut bytes_written = 0;

    // Iterate through each iovec and write from them
    for i in 0..iovcnt {
        bytes_written += write_iovec(iovec_p, verbose);

        // Update the pointer address
        iovec_p = unsafe { iovec_p.offset(1 + i as isize) };
    }

    // Turn off terminal formatting
    if verbose { clear!(); }

    bytes_written
}

// Stand-alone function to write to a regular file baby
fn write_regular_file(file: &mut File, iovec_p: *const libc::iovec,
    iovcnt: i32) -> usize {
    
    // Accumulator
    let mut bytes_written = 0;

    // Iterate through each iovec and write from them to the file buffer
    for i in 0..iovcnt {
        // Access underlying iovec
        let iovec = unsafe { &*iovec_p.add(i as usize) };

        // Create a slice of bytes from the iovec dimensions
        let slice = unsafe { 
            std::slice::from_raw_parts(
                iovec.iov_base as *const u8,
                iovec.iov_len
            )
        };

        // Calc required bytes length
        let required = file.cursor + slice.len();

        // Check to see if we need to add capacity
        if file.contents.capacity() < required {
            // Add the capacity
            let added_capacity = required - file.contents.capacity();

            // Add that capacity to the file contents vector
            file.contents.reserve(added_capacity);
        }

        // Now update the length if necessary of the vector
        if file.contents.len() < required {
            file.contents.resize(required, 0);
        }

        // Copy the bytes from the iovec over
        file.contents[file.cursor..required]
            .copy_from_slice(slice);

        // Update the file cursor and the bytes written
        file.cursor += slice.len();
        bytes_written += slice.len();
    }

    bytes_written
}

// This is where we process Bochs making a syscall
pub extern "C" fn lucid_syscall(contextp: *mut LucidContext, n: usize,
    a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize)
    -> u64 {
    // Get the context
    let context = LucidContext::from_ptr_mut(contextp);

    // Check if fuzzing
    let fuzzing = context.is_fuzzing();

    // Match on the syscall number
    match n {
        // read
        0x0 => {
            let length = {
                // Check to make sure we have the requested file-descriptor
                let Some(file) = context.files.get_file_mut(a1 as i32) else {
                    fault!(contextp, LucidErr::from("Non-existent read fd"));
                };

                // Now we need to make sure the buffer passed to read isn't NULL
                let buf_p = a2 as *mut u8;
                if buf_p.is_null() {
                    return -libc::EINVAL as u64;
                }

                // Adjust read size if necessary
                let length =
                    std::cmp::min(a3, file.contents.len() - file.cursor);

                // Copy the contents over to the buffer
                unsafe { 
                    std::ptr::copy_nonoverlapping(
                        file.contents.as_ptr().add(file.cursor),    // src
                        buf_p,                                      // dst
                        length);                                    // len
                }

                // Adjust the file cursor
                file.cursor_add(length);

                if fuzzing {
                    file.set_dirty_cursor();
                }

                length
            };

            if fuzzing {
                context.dirty_files = true;
            }

            // Success
            length as u64

        },
        // open
        0x2 => {
            // Get pointer to path string we're trying to open
            let path_p = a1 as *const libc::c_char;

            // Make sure it's not NULL
            if path_p.is_null() {
                fault!(contextp, LucidErr::from("NULL path value"));
            }            

            // Create c_str from pointer
            let c_str = unsafe { std::ffi::CStr::from_ptr(path_p) };

            // Create Rust str from c_str
            let Ok(path_str) = c_str.to_str() else {
                fault!(contextp, LucidErr::from("Invalid path string"));
            };

            // Open the file, if we're fuzzing this marks file and file table
            // dirty internally
            let fd = context.files.open(path_str, fuzzing);
            if fd.is_err() {
                // We couldn't find the requested file, return -1
                return -libc::ENOENT as u64;
            }

            // If we're fuzzing, this file is completely dirty
            if fuzzing {
                context.dirty_files = true;
            }

            // Success
            fd.unwrap() as u64
        },
        // close
        0x3 => {
            // Close the file ONLY if we're not fuzzing
            if !fuzzing {
                context.files.close(a1 as i32);
            }

            else {
                fault!(contextp, LucidErr::from("Fuzzer called close"));
            }

            // Success
            0
        },
        // fstat
        0x5 => {
            // Make sure we have a file for this fd
            let Some(file) = context.files.get_file(a1 as i32) else {
                fault!(contextp, LucidErr::from("Non-existent fstat fd"));
            };
            
            // Ok means that its a real file, otherwise it's tmpfile
            let Ok(stat) = context.files.do_fstat(file) else {
                fault!(contextp, LucidErr::from("No fstat metadata"));
            };

            // Now we can copy the stat struct over to the buf ptr
            let buf_p = a2 as *mut libc::stat;

            // Make sure it's not NULL, Bochs wouldn't do this to us, right?
            if buf_p.is_null() {
                fault!(contextp, LucidErr::from("Buffer for fstat NULL"));
            }

            // Now we just have to copy the struct over to the buf_p
            unsafe { std::ptr::copy(&stat as *const libc::stat, buf_p, 1); }

            // Success
            0
        },
        // lseek
        0x8 => {
            let new_cursor = {
                // Make sure this is a valid fd
                let Some(file) = context.files.get_file_mut(a1 as i32) else {
                    fault!(contextp, LucidErr::from("Non-existent lseek fd"));
                };

                // Get the offset
                let offset = a2 as i64;

                // Adjust the file's cursor
                match a3 as i32 {
                    libc::SEEK_SET => {
                        // Validate that offset isn't negative
                        if offset < 0 {
                            fault!(contextp,
                                LucidErr::from("Negative lseek offset"));
                        }

                        // Set the cursor to the offset
                        file.set_cursor(offset as usize);
                    },
                    libc::SEEK_CUR => {
                        // Set the cursor to current plus offset
                        file.set_cursor((file.cursor as i64 + offset) as usize);
                    }
                    libc::SEEK_END => {
                        // Set the cursor to the end of the file plus offset
                        file.set_cursor(
                            (file.contents.len() as i64 + offset) as usize);
                    },
                    _ => {
                        fault!(contextp, LucidErr::from("Unhandled lseek arg"));
                    }
                }

                if fuzzing {
                    file.set_dirty_cursor();
                }

                file.get_cursor()
            };

            // If we're fuzzing, this is now dirty
            if fuzzing {
                context.dirty_files = true;
            }

            new_cursor as u64
        }
        // mmap
        0x9 => {
            // If a1 is NULL, we just do a normal mmap
            if a1 == 0 {
                if context.mmu.do_mmap(a2, a3, a4, a5, a6).is_err() {
                    fault!(contextp, LucidErr::from("Invalid mmap request"));
                }

                // Succesful regular mmap
                return context.mmu.curr_mmap as u64;
            }

            // We have a non-null address, we don't support fixed address mmap
            // for addresses that are not in the brk pool
            if !context.mmu.in_brk(a1) {
                fault!(contextp, LucidErr::from("Invalid mmap request"));
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
                fault!(contextp, LucidErr::from("Invalid brk"));
            }

            // Return the program break
            context.mmu.curr_brk as u64
        },
        // rt_sigaction
        0xD => {
            // Success
            0 
        },
        // rt_sigprocmask
        0xE => {
            // Success
            0
        },
        // ioctl
        0x10 => {
            if a1 != 1 || a2  != libc::TIOCGWINSZ as usize {
                return -libc::ENOTTY as u64;
            }

            // Arg 3 is a pointer to a struct winsize
            let winsize_p = a3 as *mut libc::winsize;

            // If it's NULL, return an error, set errno
            if winsize_p.is_null() {
                return -libc::EINVAL as u64;
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
        // readv
        0x13 => {
            // Get the fd
            let fd = a1 as libc::c_int;

            // Make sure it's a valid fd
            let Some(file) = context.files.get_file_mut(fd) else {
                return -libc::EBADF as u64;
            };

            // Return bytes read
            let mut bytes_read = 0;

            // Get the iovec count
            let iovcnt = a3 as libc::c_int;

            // Get a pointer to the array of iovec
            let iovec_p = a2 as *const libc::iovec;

            // If the pointer is NULL, just return error
            if iovec_p.is_null() {
                return -libc::EFAULT as u64;
            }

            // Iterate through the iovecs and read the file contents into the 
            // buffers
            for i in 0..iovcnt as usize {
                // Get the underlying struct
                let iovec = unsafe { &*iovec_p.add(i) };

                // Get the base address
                let base = iovec.iov_base as *mut u8;

                // Get the length of the iovec
                let mut length = iovec.iov_len;

                // Make sure we have enough room
                if length > file.contents.len() - file.get_cursor() {
                    length = file.contents.len() - file.get_cursor();
                }

                // Copy the bytes over
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        file.contents.as_ptr().add(file.cursor),    // src
                        base,                                       // dst
                        length);                                    // len
                }
                
                // Update the cursor
                file.cursor_add(length);

                // Update total
                bytes_read += length;

                // Mark cursor as dirty
                if fuzzing && !file.has_dirty_cursor() && bytes_read > 0 {
                    file.set_dirty_cursor();
                }
            }

            // If bytes read is more than 0, we have a dirty file
            if fuzzing && bytes_read > 0 {
                context.dirty_files = true
            }

            // Return the bytes read
            bytes_read as u64
        },
        // writev
        0x14 => {
            // Get the fd
            let fd = a1 as libc::c_int;    

            // Get the iovec count
            let iovcnt = a3 as libc::c_int;

            // Get the pointer to the iovec
            let iovec_p = a2 as *const libc::iovec;

            // If the pointer was NULL, just return error
            if iovec_p.is_null() {
                return -libc::EFAULT as u64;
            }

            // Special handling for STDOUT and STDERR
            let bytes_written = if fd == STDOUT || fd == STDERR {
                    write_stdout_stderr(iovec_p, iovcnt, context.verbose)
            }

            // This is a regular file write
            else {
                // Get mutable access to the requested file
                let Some(file) = context.files.get_file_mut(fd) else {
                    fault!(contextp, LucidErr::from("Non-existent writev fd"));
                };
                
                // Handle the regular file write
                let bytes_w = write_regular_file(file, iovec_p, iovcnt);

                // Dirty file if necessary
                if fuzzing && bytes_w > 0 {
                    if !file.has_dirty_cursor() {
                        file.set_dirty_cursor();
                    }

                    if !file.has_dirty_contents() {
                        file.set_dirty_contents();
                    }
                }

                bytes_w
            };

            // Mark context as having dirty files
            if fuzzing && fd != STDOUT && fd != STDERR {
                context.dirty_files = true;
            }

            // Return how many bytes were written total
            bytes_written as i64 as u64
        },
        // nanosleep
        0x23 => {
            // Success
            0
        },
        // setitimer
        0x26 => {
            // Success
            0
        },
        // unlink
        0x57 => {
            // Get a pointer to the path string we're trying to unlink
            let path_p = a1 as *const libc::c_char;

            // Make sure it's not NULL
            if path_p.is_null() {
                fault!(contextp, LucidErr::from("NULL path in unlink"));
            }

            // Create c_str from pointer
            let c_str = unsafe { std::ffi::CStr::from_ptr(path_p) };

            // Create Rust str from c_str
            let Ok(path_str) = c_str.to_str() else {
                fault!(contextp, LucidErr::from("Invalid path string"));
            };

            // Make sure it's a tmpfile
            if !path_str.contains("tmpfile") {
                fault!(contextp, LucidErr::from("Non-tmpfile unlink"));
            }

            // Return success
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
                        return -libc::EINVAL as u64;
                    }

                    // Deref the raw pointer
                    let fs_val = unsafe { &*fs_val_p };

                    // Track the FS register value it wanted to set 
                    context.fs_reg = *fs_val as usize;

                    // Success
                    0
                }
                _ => {
                    fault!(contextp,
                        LucidErr::from("Unhandled arch_prctl code"));
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
                fault!(contextp,
                    LucidErr::from("Unhandled clock_gettime clk_id"));
            }

            // Make sure tp is not null
            let tp_p = a2 as *mut libc::timespec;
            if tp_p.is_null() {
                return -libc::EFAULT as u64;
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
            fault!(contextp, LucidErr::from("Bochs exited early"));
        }
        _ => {
            fault!(contextp, LucidErr::from("Unhandled syscall number"));
        }
    }
}