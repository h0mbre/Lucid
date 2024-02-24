/// A place-holder for perhaps a more detailed/robust error reporting system in
/// the future

use crate::context::{Fault};

#[derive(Debug)]
pub struct LucidErr {
    message: String,
}

impl LucidErr {
    pub fn from(message: &str) -> Self {
        LucidErr {
            message: message.to_string(),
        }
    }

    pub fn from_fault(fault: Fault) -> Self {
        LucidErr {
            message: format!("{}", fault),
        }
    }

    pub fn display(&self) {
        println!("{}", self.message);
    }
}