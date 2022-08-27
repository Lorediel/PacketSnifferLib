use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum Errors {
    InvalidInterval(u64),
<<<<<<< HEAD:PacketSnifferLib/src/errors.rs
    InactivableCapture(String),
    InvalidCapture(String),
    UnavailableDeviceList,
    FileError(String)
}


impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Errors::InvalidInterval(i) => {write!(f, "Error: Invalid Interval value: {}, interval must be greater than 100 ms", i)},
            Errors::InvalidCapture(name) => {write!(f, "Error: Invalid device name: {}", name)},
            Errors::InactivableCapture(device_name) => {write!(f, "Cannot capture from device: {}, check if the name is correct", device_name)},
            Errors::UnavailableDeviceList => {write!(f, "Cannot get device list, check if you have permission or if there are available devices")},
            Errors::FileError(err) => {write!(f, "File error: {}", err)}
            _ => (write!(f, "Generic error")),


        }

        //write!(f, "Error: {:?}", &self)
=======
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {:?}", &self)
>>>>>>> 9fc9d9a5a7872250a9e9466f542d81a5df060233:src/errors.rs
    }
}

impl Error for Errors {}
