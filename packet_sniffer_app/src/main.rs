use std::{io, thread};
use std::time::Duration;
//use clap::error::ContextValue::String;
use PacketSnifferLib::PacketCatcher;
use std::string::String;
use std::sync::mpsc::{channel, Receiver, Sender};

enum Message {
    DeviceName(String),
    Command(String)
}

pub fn mainwork(device_name: &str, file_name: &str) {
    let (tx, rx) = channel();

    let t1 = thread::spawn(move ||
        loop {
            let mut command = String::new();
            std::io::stdin().read_line(&mut command).unwrap();
            tx.send(command).unwrap();
        });

    /* let t2 = thread::spawn(move|| {
        let x = p.capture(device_name, "prova.txt", 1000, None);
        match x {
            Ok(v) => {}
            Err(e) => { println!("{:?}", e) }
        }
        thread::sleep(Duration::from_secs(5));
        p.stop_capture();
        p.h_cap.unwrap().join();

        loop {
            match rx.try_recv() {
                Ok(command) => {
                    let com = command.trim();
                    match command {
                        _ => println!("cao")
                    }
                },
                _ => println!("Command not recognized!")
            };
        }
    )
    }
} */
}

fn main() {

    println!("Choose one of the following available devices on your machine: \n");
    let v = PacketCatcher::parse_network_adapter().unwrap();

    let mut input_code = String::new();
    io::stdin()
        .read_line(&mut input_code)
        .expect("failed to read from stdin");

    let trimmed = input_code.trim();
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

    let trimmed_file = file_name.trim();

    mainwork(device_name.as_str(), trimmed_file);


}
