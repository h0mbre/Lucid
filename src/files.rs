/// This file contains all of the logic related to file I/O from Bochs
use std::fs::read;

use crate::err::LucidErr;

#[derive(Clone)]
pub struct FileTable {
    files: Vec<File>,
}

impl FileTable {
    // We will attempt to open and read all of our required files ahead of time
    pub fn new() -> Result<Self, LucidErr> {
        // Retrieve .bochsrc
        let args: Vec<String> = std::env::args().collect();

        // Check to see if we have a "--bochsrc-path" argument
        if args.len() < 3 || !args.contains(&"--bochsrc-path".to_string()) {
            return Err(LucidErr::from("No `--bochsrc-path` argument"));
        }

        // Search for the value
        let mut bochsrc = None;
        for (i, arg) in args.iter().enumerate() {
            if arg == "--bochsrc-path" {
                if i >= args.len() - 1 {
                    return Err(
                        LucidErr::from("Invalid `--bochsrc-path` value"));
                }
            
                bochsrc = Some(args[i + 1].clone());
                break;
            }
        }

        if bochsrc.is_none() { return Err(
            LucidErr::from("No `--bochsrc-path` value provided")); }
        let bochsrc = bochsrc.unwrap();

        // Try to read the file
        let Ok(data) = read(&bochsrc) else { 
            return Err(LucidErr::from(
                &format!("Unable to read data BLEGH from '{}'", bochsrc)));
        };

        // Create a file now for .bochsrc
        let bochsrc_file = File {
            fd: 3,
            path: ".bochsrc".to_string(),
            contents: data.clone(),
            cursor: 0,
        };

        // Insert the file into the FileTable
        Ok(FileTable {
            files: vec![bochsrc_file],
        })
    }

    // Attempt to open a file
    pub fn open(&mut self, path: &str) -> Result<i32, ()> {
        // Try to find the requested path
        for file in self.files.iter() {
            if file.path == path {
                return Ok(file.fd);
            }
        }

        // We didn't find the file
        Err(())
    }

    // Look a file up by fd and then return a mutable reference to it
    pub fn get_file(&mut self, fd: i32) -> Option<&mut File> {
        self.files.iter_mut().find(|file| file.fd == fd)
    }
}

#[derive(Clone)]
pub struct File {
    pub fd: i32,            // The file-descriptor Bochs has for this file
    pub path: String,       // The file-path for this file
    pub contents: Vec<u8>,  // The actual file contents
    pub cursor: usize,      // The current cursor in the file
}