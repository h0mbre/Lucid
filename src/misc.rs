/// This file contains miscellaneous helper functions 

#[macro_export]
macro_rules! prompt {
    () => ({
        print!("lucid\u{25CF}\n");
    });
    ($($arg:tt)*) => ({
        print!("lucid\u{25CF} ");
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