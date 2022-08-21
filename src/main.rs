use std::fmt::Display;
use std::thread;
use std::time::Duration;
//MAIN PER TESTARE
//Per runnare il main: sudo cargo run --package PacketSnifferLib --bin PacketSnifferLib
use pcap::{BpfInstruction, Device};
use PacketSnifferLib::PacketCatcher;

fn main() {
    let mut p = PacketCatcher::new();
    //Fare filtri manualmente perché pcap non funzionano
    p.capture("en0", "rslts", 2, None);
    thread::sleep(Duration::from_secs(15));
    p.switch(true);
    println!("qui");
    p.empty_report();
    p.h.unwrap().join();
    //println!("{:?}", Device::list().unwrap());
    //thread::sleep(Duration::from_secs(100));
}
