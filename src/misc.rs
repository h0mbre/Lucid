/// This file contains miscellaneous helper functions 

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