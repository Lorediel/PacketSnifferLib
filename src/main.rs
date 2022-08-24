
use std::thread;
use std::time::Duration;
//MAIN PER TESTARE
//Per runnare il main: sudo cargo run --package PacketSnifferLib --bin PacketSnifferLib
use PacketSnifferLib::PacketCatcher;
use crate::filter::Filter;
mod filter;

fn main() {
    //let mut f = Filter::new(Some("ciao".to_string()), None, None, None, None, None, None, None);
    //f.parse_filter();

    let mut p = PacketCatcher::new();
    //Fare filtri manualmente perché pcap non funzionano

    //p.capture("en0", "/Users/alessandrogelsi/Desktop/prova.txt", 2, None);
    p.capture("\\Device\\NPF_{434FE10D-2348-48BF-9823-09CD95698329}", "C:\\Users\\david\\Desktop\\prova.txt", 2, None);
    //PacketCatcher::parse_network_adapter();
    thread::sleep(Duration::from_secs(2));


    p.switch(true);
    p.empty_report("C:\\Users\\david\\Desktop\\prova.txt");

    p.stop_capture();
    p.h.unwrap().join();

    //println!("{:?}", Device::list().unwrap());
    //thread::sleep(Duration::from_secs(100));

}
