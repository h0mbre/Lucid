//! This file contains all of the logic related to file I/O from Bochs

use std::fs::{metadata, read, Metadata};
use std::os::unix::fs::MetadataExt;

// Maximum number of files we allow Bochs to open
const NUM_FILE_MAX: usize = 15;

// The base FD number accounting for 0, 1, 2 being reserved
const BASE_FD: i32 = 3;

// This is a list of files that we know about and want to block opening for
const FILE_DENY_LIST: [&str; 2] = [
    "/etc/localtime", // Not needed
    "bochsout.txt",   // Force logging to go to stderr
];

#[derive(Clone, Default)]
pub struct FileTable {
    pub files: Vec<File>,
}

impl FileTable {
    // We will attempt to open and read all of our required files ahead of time
    pub fn new() -> Self {
        // Return an empty file table
        FileTable {
            files: Vec::with_capacity(NUM_FILE_MAX),
        }
    }

    // Attempt to close a file by fd
    pub fn close(&mut self, fd: i32) {
        for i in 0..self.files.len() {
            let file = &self.files[i];
            if file.fd == fd {
                self.files.remove(i);
                break;
            }
        }
    }

    // Attempt to open a file, we also handle creating files in here, if they
    // are tmpfiles, otherwise, we don't support
    pub fn open(&mut self, path: &str, fuzzing: bool) -> Result<i32, ()> {
        // Check to see if we're creating too many files
        if self.files.len() >= NUM_FILE_MAX {
            return Err(());
        }

        // Validate file
        if FILE_DENY_LIST.contains(&path) && !path.contains("tmpfile") {
            return Err(());
        }

        // Create a mutable file to add to
        let mut file = File::new();

        // Make sure the file exists, if it doesn't create it
        let meta = metadata(path);
        let data = read(path);

        // The metadata and contents are there, it's probably a real file
        if meta.is_ok() && data.is_ok() {
            file.metadata = Some(meta.unwrap());
            file.contents = data.unwrap();
        }
        // Check for the tmpfile possibility
        else if path.contains("tmpfile") {
            // Just to be explicit, but these should be default (NOPs)
            file.metadata = None;
            file.contents = Vec::new();
        }
        // Rule out any weird TOCTOU cases?
        else {
            return Err(());
        }

        // Calculate fd value
        let fd = if !self.files.is_empty() {
            // If we have files already, just get the last one and add 1
            self.files[self.files.len() - 1].fd + 1
        } else {
            BASE_FD
        };

        // Set fd
        file.fd = fd;

        // Set the pathname
        file.path = path.to_string();

        // Set cursor
        file.cursor = 0;

        // If we're fuzzing, this is a dirty file
        file.dirty_file = fuzzing;

        // Create file and store it
        self.files.push(file);

        // Return fd
        Ok(fd)
    }

    // Look a file up by fd and then return a mutable reference to it
    pub fn get_file_mut(&mut self, fd: i32) -> Option<&mut File> {
        self.files.iter_mut().find(|file| file.fd == fd)
    }

    // Look up a file by fd and then return a read-only reference to it
    pub fn get_file(&self, fd: i32) -> Option<&File> {
        self.files.iter().find(|file| file.fd == fd)
    }

    // Return an fstat struct if we can
    pub fn do_fstat(&self, file: &File) -> Result<libc::stat, ()> {
        // If we don't have metadata, return error
        if file.metadata.is_none() {
            return Err(());
        }

        let metadata = file.metadata.as_ref().unwrap();

        // Zero init a whole instance bc it contains private fields
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };

        // Initialize each field we can touch publicly
        stat.st_dev = metadata.dev() as libc::dev_t;
        stat.st_ino = metadata.ino();
        stat.st_mode = metadata.mode();
        stat.st_nlink = metadata.nlink() as libc::nlink_t;
        stat.st_uid = metadata.uid();
        stat.st_gid = metadata.gid();
        stat.st_rdev = metadata.rdev() as libc::dev_t;
        stat.st_size = metadata.len() as libc::off_t;
        stat.st_blksize = metadata.blksize() as libc::blksize_t;
        stat.st_blocks = metadata.blocks() as libc::blkcnt_t;
        stat.st_atime = metadata.atime() as libc::time_t;
        stat.st_mtime = metadata.mtime() as libc::time_t;
        stat.st_ctime = metadata.ctime() as libc::time_t;

        // Return struct
        Ok(stat)
    }
}

#[derive(Clone)]
pub struct File {
    pub fd: i32,                    // The file-descriptor Bochs has for this file
    pub path: String,               // The file-path for this file
    pub metadata: Option<Metadata>, // The file metadata
    pub contents: Vec<u8>,          // The actual file contents
    pub cursor: usize,              // The current cursor in the file
    pub dirty_file: bool,           // Created during fuzzing
    pub dirty_cursor: bool,         // The cursor was changed during fuzzing
    pub dirty_contents: bool,       // File contents were changed during fuzzing
}

impl File {
    fn new() -> Self {
        File {
            fd: 0,
            path: "".to_string(),
            metadata: None,
            contents: Vec::new(),
            cursor: 0,
            dirty_file: false,
            dirty_cursor: false,
            dirty_contents: false,
        }
    }

    pub fn set_cursor(&mut self, new: usize) {
        self.cursor = new;
    }

    pub fn get_cursor(&self) -> usize {
        self.cursor
    }

    pub fn cursor_add(&mut self, length: usize) {
        self.cursor += length;
    }

    pub fn has_dirty_cursor(&self) -> bool {
        self.dirty_cursor
    }

    pub fn set_dirty_cursor(&mut self) {
        self.dirty_cursor = true;
    }

    pub fn has_dirty_contents(&self) -> bool {
        self.dirty_contents
    }

    pub fn set_dirty_contents(&mut self) {
        self.dirty_contents = true;
    }
}
