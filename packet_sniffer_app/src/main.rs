mod args;

extern crate core;
use args::MyCommand;
use std::{thread};
use PacketSnifferLib::PacketCatcher;
use std::string::String;
use std::thread::{JoinHandle};
use clap::Parser;
use crate::args::Comms::{Capture, Devices};

pub fn main_capture(device_name: String, file_name: String, interval: u64, filter: Option<String>) -> JoinHandle<()> {

    let t1 = thread::spawn(move || {
        let mut p = PacketCatcher::new();
        let mut paused = false;
        let x = p.capture(device_name, file_name, interval, filter);
        let mut success = true;
        match x {
            Ok(_) => {}
            Err(e) => {
                println!("{}", e);
                success = false
            }
        }
        if success {
            println!("Capture running...");
            println!("Type:\n- \"pause\" to temporarily pause the capture\n- \"resume\" to resume the capture\n- \"stop\" to interrupt the capture");
        loop {

            let mut command = String::new();
            std::io::stdin().read_line(&mut command).unwrap();

            match command.trim().to_lowercase().as_str() {
                "stop" => {
                    p.stop_capture();
                    println!("Capture terminated");
                    break;
                },
                "pause" => {
                    if !paused {
                        p.switch(true);
                        println!("Capture suspended");
                        paused = true;
                    }
                    else {
                        println!("Capture is already paused");
                    }
                },
                "resume" => {
                    if paused {
                        p.switch(false);
                        println!("Capture running...");
                        paused = false;
                    }
                    else {
                        println!("Capture is not paused");
                    }
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
            let h = main_capture(cap_values.device_name, file_txt, cap_values.interval, cap_values.filter);
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


