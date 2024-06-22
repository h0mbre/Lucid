/// This file contains miscellaneous helper functions 

use core::arch::x86_64::{_xgetbv, _xsave64, _fxsave64, _xrstor64, _fxrstor64};

#[macro_export]
macro_rules! prompt {
    () => ({
        print!("\x1b[1;35m\u{2726}lucid\u{2726}\x1b[0m\n");
    });
    ($($arg:tt)*) => ({
        print!("\x1b[1;35m\u{2726}lucid\u{2726}\x1b[0m ");
        println!($($arg)*);
    });
}

#[macro_export]
macro_rules! prompt_warn {
    () => ({
        print!("\x1b[1;33m\u{2726}lucid\u{2726}\x1b[0m\n");
    });
    ($($arg:tt)*) => ({
        print!("\x1b[1;33m\u{2726}lucid\u{2726}\x1b[0m ");
        println!($($arg)*);
    });
}

#[macro_export]
macro_rules! fatal {
    ($err:expr) => {
        {
            print!("\n\x1b[1;31mfatal:\x1b[0m ");
            $err.display();
            std::process::exit(-1);
        }
    };
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
    () => ({
        print!("\x1b[1;32m");
    });
}

#[macro_export]
macro_rules! red {
    () => ({
        print!("\x1b[1;31m");
    });
}

#[macro_export]
macro_rules! clear {
    () => ({
        print!("\x1b[0m");
    });
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

// Retrieve command line argument presence
pub fn get_arg(arg: &str) -> bool {
    // Retrieve envvars
    let args: Vec<String> = std::env::args().collect();

    // Check to see if we have the provided args
    args.contains(&arg.to_string())
}

// Retrieve the value corresponding to a given command line argument
pub fn get_arg_val(arg: &str) -> Option<String> {
    // Retrieve envvars
    let args: Vec<String> = std::env::args().collect();

    // Check to see if we have the provided args
    if !args.contains(&arg.to_string()) { return None; }

    // Search for corresponding value
    let mut val = None;
    for (i, a) in args.iter().enumerate() {
        if a == arg {
            if i >= args.len() - 1 {
                return None;
            }
            
            val = Some(args[i + 1].clone());
            break;
        }
    }

    val
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