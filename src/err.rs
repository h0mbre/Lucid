/// A place-holder for perhaps a more detailed/robust error reporting system in
/// the future

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