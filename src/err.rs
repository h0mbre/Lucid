//! A place-holder for perhaps a more detailed/robust error reporting system in
//! the future
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

#[derive(Debug, Clone)]
pub struct LucidErr {
    message: String,
}

impl LucidErr {
    pub fn from(message: &str) -> Self {
        LucidErr {
            message: message.to_string(),
        }
    }

    pub fn display(&self) {
        println!("{}", self.message);
    }
}
