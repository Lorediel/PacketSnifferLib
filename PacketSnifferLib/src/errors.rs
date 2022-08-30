use std::error::Error;
use std::fmt;

#[derive(Debug)]
///Represent an enum of possible customized errors
pub enum Errors {
    /// Refers to " Error: Invalid Interval value: x, interval must be greater than 100 ms".
    InvalidInterval(u64),
    /// Refers to " Error: Invalid device name: x".
    InactivableCapture(String),
    /// Refers to " Cannot capture from device: x, check if the name is correct or if you have permissions".
    InvalidCapture(String),
    /// Refers to" Cannot get device list, check if you have permission or if there are available devices".
    UnavailableDeviceList,
    /// Refers to " File error: x".
    FileError(String)
}


impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Errors::InvalidInterval(i) => {write!(f, "Error: Invalid Interval value: {}, interval must be greater than 100 ms", i)},
            Errors::InvalidCapture(name) => {write!(f, "Error: Invalid device name: {}", name)},
            Errors::InactivableCapture(device_name) => {write!(f, "Cannot capture from device: {}, check if the name is correct or if you have permissions", device_name)},
            Errors::UnavailableDeviceList => {write!(f, "Cannot get device list, check if you have permission or if there are available devices")},
            Errors::FileError(err) => {write!(f, "File error: {}", err)}
            _ => (write!(f, "Generic error")),


        }
        //write!(f, "Error: {:?}", &self)
    }
}

impl Error for Errors {}
