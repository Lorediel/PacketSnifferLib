//MAIN PER TESTARE
//Per runnare il main: sudo cargo run --package PacketSnifferLib --bin PacketSnifferLib
use pcap::Device;
use PacketSnifferLib::PacketCatcher;

fn main() {
    let mut p = PacketCatcher::new();
    p.capture("en0", "rslts", 2, None);
}