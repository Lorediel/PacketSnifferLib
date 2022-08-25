
use std::thread;
use std::time::Duration;
//MAIN PER TESTARE
//Per runnare il main: sudo cargo run --package PacketSnifferLib --bin PacketSnifferLib
use PacketSnifferLib::PacketCatcher;
use crate::filter::Filter;
mod filter;

fn main() {

    let mut p = PacketCatcher::new();
    //Fare filtri manualmente perché pcap non funzionano
    let res = p.capture("en0", "/Users/lorenzodamico/Desktop/prova.txt", 99, None);
   // p.capture("\\Device\\NPF_{434FE10D-2348-48BF-9823-09CD95698329}", "C:\\Users\\david\\Desktop\\prova.txt", 2, None);
    //PacketCatcher::parse_network_adapter();
    match res {
        Ok(_) => {},
        Err(e) => {println!("{}",e )}
    }
    //p.empty_report("C:\\Users\\david\\Desktop\\prova.txt");
    thread::sleep(Duration::from_secs(1));
    p.stop_capture();
    p.h_cap.unwrap().join();

    //println!("{:?}", Device::list().unwrap());
    //thread::sleep(Duration::from_secs(100));

}
