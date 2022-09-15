use clap::{
    Args,
    Parser,
    Subcommand
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct MyCommand{
    #[clap(subcommand)]
    pub command_type: Comms
}

#[derive(Debug, Subcommand)]
pub enum Comms {
    /// Start a capture
    Capture(CaptureCommand),
    /// Get the list of all the possible devices, their name, description and addressese
    Devices(DevicesCommand)
}

#[derive(Debug, Args)]
pub struct CaptureCommand {
    /// The name of the network interface you want to analyze
    pub device_name: String,
    /// Name of the file you want the report to be generated. If the file does not exist it will create a new one, however if it does it will append new information
    pub file_name: String,
    /// The interval after which a new report is generated in the file
    pub interval: u64,
}

#[derive(Debug, Args)]
pub struct DevicesCommand {

}