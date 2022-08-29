use std::thread;
use std::time::Duration;
use PacketSnifferLib::PacketCatcher;

fn main() {

    let mut p = PacketCatcher::new();
    PacketCatcher::parse_network_adapter();
    let x = p.capture("\\Device\\NPF_{434FE10D-2348-48BF-9823-09CD95698329}", "prova.txt", 1000, None);
    match x {
        Ok(v) => {}
        Err(e) => {println!("{:?}",e)}
    }
    thread::sleep(Duration::from_secs(5));
    p.stop_capture();
    p.h_cap.unwrap().join();
}
