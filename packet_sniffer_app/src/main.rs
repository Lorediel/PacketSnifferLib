use std::thread;
use std::time::Duration;
use PacketSnifferLib::PacketCatcher;

fn main() {

    let mut p = PacketCatcher::new();
    let x = p.capture("en0", "prova.txt", 2000, None);
    match x {
        Ok(v) => {}
        Err(e) => {println!("{}",e)}
    }
    thread::sleep(Duration::from_secs(20));
    p.stop_capture();
    p.h_cap.unwrap().join();
}
