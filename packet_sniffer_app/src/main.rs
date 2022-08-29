extern crate core;

use std::{io, thread};
use std::time::Duration;
use PacketSnifferLib::PacketCatcher;
use std::string::String;
use std::thread::JoinHandle;
use clap::Parser;

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


pub fn mainwork(device_name: String, file_name: String) -> JoinHandle<()> {


    let t1 = thread::spawn(move || {

        println!("Capture started \n");
        let mut p = PacketCatcher::new();
        //let x = p.capture(device_name.as_str(), file_name.as_str(), 1000, None);
        let x = p.capture("\\Device\\NPF_{434FE10D-2348-48BF-9823-09CD95698329}", "prova.txt", 1000, None);
        match x {
            Ok(v) => {}
            Err(e) => { println!("{:?}", e) }
        }

         loop {

            let mut command = String::new();
            std::io::stdin().read_line(&mut command).unwrap();
            //let command_str = command.trim().to_lowercase().as_str();

            match command.trim().to_lowercase().as_str() {

                "stop" => {
                    p.stop_capture();
                    println!("Capture terminated");

                },
                "pause" => {
                    p.switch(true);
                    println!("Capture suspended");
                },
                "resume" => {
                    p.switch(false);
                    println!("Capture resumed");
                },
                _ => {
                    println!("Wrong command");
                }

            }
        }
    }

    );

    t1

}


fn main() {

/*

    println!("Choose one of the following available devices on your machine: \n");
    let v = PacketCatcher::parse_network_adapter().unwrap();

    let mut input_code = String::new();
    io::stdin()
        .read_line(&mut input_code)
        .expect("failed to read from stdin");

    let trimmed = input_code.trim().to_owned();
    let device_name = match trimmed.parse::<usize>() {
        Ok(i) => v[i - 1].clone().replace("\\", "\\\\"),
        Err(..) => 0.to_string(),
    };

    println!("You have chosen the folllowing device to be sniffed: \n{}", device_name);

    println!("Write the name of the text file that will contain the report");

    let mut file_name = String::new();
    io::stdin()
        .read_line(&mut file_name)
        .expect("failed to read from stdin");

   // let trimmed_file = file_name.trim();

    let thread = mainwork(device_name, file_name.trim().to_owned());
    thread.join();

 */

    let args = Args::parse();
    let thread = mainwork(args.device_name, args.file_name);
    thread.join();

}


