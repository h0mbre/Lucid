/// This file contains all of the logic related to file I/O from Bochs
use std::fs::read;

// This is the file-descriptor number base for assignment, we start here because
// 0, 1, and 2 are all taken by STDIN, STDOUT, and STDERR
const FD_BASE: usize = 3;

#[derive(Clone)]
pub struct FileTable {
    files: Vec<File>,
}

impl FileTable {
    // We will attempt to open and read all of our required files ahead of time
    pub fn new() -> Self {
        // Return an empty file table
        FileTable {
            files: Vec::new(),
        }
    }

    // Attempt to open a file
    pub fn open(&mut self, path: &str) -> Result<i32, ()> {
        let Ok(data) = read(path) else {
            return Err(());
        };

        // Calculate fd value
        let fd = (FD_BASE + self.files.len()) as i32;

        // Create file and store it
        self.files.push(
            File {
                fd,
                path: path.to_string(),
                contents: data,
                cursor: 0
            }
        );

        // Return fd
        Ok(fd)
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