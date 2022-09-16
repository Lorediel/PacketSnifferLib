use std::error::Error;
use std::fmt;

#[derive(Debug)]
///Represent an enum of possible customized errors
pub enum PacketSnifferError {
    /// Refers to " Error: Invalid Interval value: x, interval must be greater than 100 ms".
    InvalidInterval(u64),
    /// Refers to " Error: Invalid device name: x".
    InactivableCapture(String, String),
    /// Refers to " Cannot capture from device: x, check if the name is correct or if you have permissions".
    InvalidCapture(String, String),
    /// Refers to " Cannot get device list, check if you have permission or if there are available devices".
    UnavailableDeviceList(String),
    /// Refers to " File error: x".
    FileError(String),
    /// Refers to "  "
    InvalidFilter(String, String)
}

impl fmt::Display for PacketSnifferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PacketSnifferError::InvalidInterval(i) => {write!(f, "Error: Invalid Interval value: {}, interval must be greater than 100 ms", i)},
            PacketSnifferError::InvalidCapture(name, error_string) => {write!(f, "Error: Possible invalid device name: {}.\nDetailed error: {}", name, error_string)},
            PacketSnifferError::InactivableCapture(device_name, error_string) => {write!(f, "Cannot capture from device: {}, check if the name is correct or if you have permissions.\nDetailed error: {}", device_name, error_string)},
            PacketSnifferError::UnavailableDeviceList(error_string) => {write!(f, "Cannot get device list, check if you have permission or if there are available devices.\nDetailed error: {}", error_string)},
            PacketSnifferError::FileError(err) => {write!(f, "File error: {}", err)},
            PacketSnifferError::InvalidFilter(filter, error_string) => {write!(f, "Invalid filter: {}, check https://biot.com/capstats/bpf.html to know the syntax.\nDetailed error: {}", filter, error_string)}
        }
    }
}

impl Error for PacketSnifferError {}
