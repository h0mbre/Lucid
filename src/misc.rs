/// This file contains miscellaneous helper functions 

#[macro_export]
macro_rules! prompt {
    () => ({
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        print!("\x1b[1;33m[{}]\x1b[0m", timestamp);
        print!(" \x1b[1;36mlucid\x1b[0m\x1b[1;35m>\x1b[0m\n");
    });
    ($($arg:tt)*) => ({
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        print!("\x1b[1;33m[{}]\x1b[0m", timestamp);
        print!(" \x1b[1;36mlucid\x1b[0m\x1b[1;35m>\x1b[0m ");
        println!($($arg)*);
    });
}

#[macro_export]
macro_rules! fatal {
    ($err:expr) => {
        {
            print!("\x1b[1;31mFATAL:\x1b[0m ");
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