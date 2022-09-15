mod args;

extern crate core;
use args::MyCommand;
use std::{thread};
use PacketSnifferLib::PacketCatcher;
use std::string::String;
use std::thread::{JoinHandle};
use clap::Parser;
use crate::args::Comms::{Capture, Devices};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {

    #[clap(short, long, value_parser)]
    device_name: String,

    #[clap(short, long, value_parser)]
    file_name: String,

    #[clap(short, long, value_parser)]
    interval: u64
}


pub fn main_capture(device_name: String, file_name: String, interval: u64) -> JoinHandle<()> {


    let t1 = thread::spawn(move || {
        let mut p = PacketCatcher::new();
        let x = p.capture(device_name, file_name, interval, None);
        let mut success = true;
        match x {
            Ok(_) => {}
            Err(e) => {
                println!("{}", e);
                success = false
            }
        }

        if success {
        loop {
            println!("Capture running...");
            let mut command = String::new();
            std::io::stdin().read_line(&mut command).unwrap();
            //let command_str = command.trim().to_lowercase().as_str();

            match command.trim().to_lowercase().as_str() {
                "stop" => {
                    p.stop_capture();
                    println!("Capture terminated");
                    //throbber.success("Capture terminated!".to_string());
                    //throbber.end();
                    break;
                },
                "pause" => {
                    p.switch(true);
                    println!("Capture suspended");
                    //throbber.success("Capture suspended".to_string());
                },
                "resume" => {
                    p.switch(false);
                    println!("Capture running...");
                    //throbber.start();
                },
                _ => {
                    println!("Wrong command");
                }
            }
        }
    }
    }

    );

    t1

}


fn main() {

    let args = MyCommand::parse();

    match args.command_type{
        Capture(cap_values) => {
            let mut file_txt = cap_values.file_name.clone();
            file_txt.push_str(".txt");
            let h = main_capture(cap_values.device_name, file_txt, cap_values.interval);
            h.join().unwrap();
        },
        Devices(_) => {
            match PacketSnifferLib::parse_network_adapter() {
                Ok(_) => {},
                Err(e) => {println!("{}", e)}
            }
        }

    }
}


