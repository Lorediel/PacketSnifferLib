//MAIN PER TESTARE
//Per runnare il main: sudo cargo run --package PacketSnifferLib --bin PacketSnifferLib
use pcap::Device;

fn main() {
    let mut cap = Device::lookup().unwrap().open().unwrap();

    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
    }
}