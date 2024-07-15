/// This file contains miscellaneous helper functions
use core::arch::x86_64::{_fxrstor64, _fxsave64, _xgetbv, _xrstor64, _xsave64};

#[macro_export]
macro_rules! prompt {
    () => ({
        print!("\x1b[1;35m[lucid]\x1b[0m\n");
    });
    ($($arg:tt)*) => ({
        print!("\x1b[1;35m[lucid]\x1b[0m ");
        println!($($arg)*);
    });
}

#[macro_export]
macro_rules! prompt_warn {
    () => ({
        print!("\x1b[1;33m[lucid]\x1b[0m\n");
    });
    ($($arg:tt)*) => ({
        print!("\x1b[1;33m[lucid]\x1b[0m ");
        println!($($arg)*);
    });
}

#[macro_export]
macro_rules! fatal {
    ($err:expr) => {{
        print!("\n\x1b[1;31mfatal:\x1b[0m ");
        $err.display();
        std::process::exit(-1);
    }};
}

// Hides `unreachable!()`
#[macro_export]
macro_rules! fault {
    ($contextp:expr, $fault:expr) => {{
        fault_handler($contextp, $fault);
        unreachable!();
    }};
}

#[macro_export]
macro_rules! green {
    () => {{
        print!("\x1b[1;32m");
    }};
}

#[macro_export]
macro_rules! red {
    () => {{
        print!("\x1b[1;31m");
    }};
}

#[macro_export]
macro_rules! clear {
    () => {{
        print!("\x1b[0m");
    }};
}

#[macro_export]
macro_rules! mega_panic {
    ($msg:expr) => {{
        use core::arch::asm;

        // Length of the message
        let msg_len = $msg.len();
        let msg_ptr = $msg.as_ptr();
        let stderr: usize = 2;

        // Unsafe block for inline assembly
        unsafe {
            // Write the message to stderr
            asm!(
                "mov rax, 1",               // syscall number for sys_write
                "mov rdi, {0}",             // file descriptor (stderr)
                "mov rsi, {1}",             // pointer to the message
                "mov rdx, {2}",             // length of the message
                "syscall",                  // make the syscall
                in(reg) stderr,
                in(reg) msg_ptr,
                in(reg) msg_len,
                out("rax") _, out("rdi") _, out("rsi") _, out("rdx") _,
            );

            // Call the exit syscall with an exit code
            asm!(
                "mov rax, 60",              // syscall number for sys_exit
                "mov rdi, 1",               // exit code 1 (error)
                "syscall",                  // make the syscall
                options(noreturn),
            );
        }
    }};
}

// Wrappers for these unsafe functions to tuck unsafes away
pub fn get_xcr0() -> u64 {
    unsafe { _xgetbv(0) }
}

pub fn xsave64(save_area: *mut u8, xcr0: u64) {
    unsafe { _xsave64(save_area, xcr0) }
}

pub fn fxsave64(save_area: *mut u8) {
    unsafe { _fxsave64(save_area) }
}

pub fn xrstor64(save_area: *const u8, xcr0: u64) {
    unsafe { _xrstor64(save_area, xcr0) }
}

pub fn fxrstor64(save_area: *const u8) {
    unsafe { _fxrstor64(save_area) }
}
