use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum Errors {
    InvalidInterval(u64),
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {:?}", &self)
    }
}

impl Error for Errors {}
