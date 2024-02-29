/// This file contains miscellaneous helper functions 

// Padding to print Bochs messages in line with prompt, should be length of the
// prompt
pub const PROMPT_PADDING: &str = "       ";

#[macro_export]
macro_rules! prompt {
    () => ({
        print!("\x1b[1;35mlucid\u{2726}\x1b[0m\n");
    });
    ($($arg:tt)*) => ({
        print!("\x1b[1;35mlucid\u{2726}\x1b[0m ");
        println!($($arg)*);
    });
}

#[macro_export]
macro_rules! fatal {
    ($err:expr) => {
        {
            print!("\x1b[1;31mfatal:\x1b[0m ");
            $err.display();
            std::process::exit(-1);
        }
    };
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