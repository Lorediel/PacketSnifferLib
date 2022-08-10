mod report;

use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp, Unknown};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::{Active, Capture, Inactive, Packet};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;
use report::*;

pub struct PacketCatcher{
    cv_m: Arc<(Condvar,Mutex<bool>)>
}
impl PacketCatcher {

    pub fn new() -> PacketCatcher {
        PacketCatcher{cv_m: Arc::new((Condvar::new(), Mutex::new(false)))}
    }

    pub fn capture(
        &mut self,
        device_name: &str,
        filename: &str,
        interval: u32,
        filter: Option<&str>,
    ) {
        let mut cap = Capture::from_device(device_name)
            .unwrap()
            .promisc(true)
            .open()
            .unwrap();
        //Applica il filtro nel caso ci sia, altrimenti non fare nulla
        match filter {
            Some(filter) => {
                cap.filter(filter, true);
            }
            None => {}
        }

        let mut map = HashMap::new();

        let is_blocked = Arc::clone(&self.cv_m);
        let h = thread::spawn(move || {
            while let Ok(packet) = cap.next() {
                let (cvar, lock) = &*is_blocked;

                let mut is_b = lock.lock().unwrap();
                while *is_b {
                    is_b = cvar.wait(is_b).unwrap();
                }
                let x = cap.next();

                let packet = x.unwrap();
                //self.tx.send(packet);
                parse_packet(packet, &mut map);


                for (key, value) in map.iter() {
                    println!("{:?}, {:?}", key, value);
                }
            }
        });




        fn parse_packet(packet: Packet, report_map: &mut HashMap<AddressPortPair, Report>) {
            match SlicedPacket::from_ethernet(&packet) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    let transport_level = parse_transport(value.transport);
                    let network_level = parse_network(value.ip);

                    if transport_level.is_some() && network_level.is_some() {
                        let tl = transport_level.unwrap();
                        let nl = network_level.unwrap();
                        let pair = AddressPortPair::new(
                            nl.source_address,
                            tl.source_port.unwrap(),
                            nl.destination_address,
                            tl.destination_port.unwrap(),
                        );

                        let ts = packet.header.ts;
                        let bytes: u32 = packet.header.len;
                        let this_entry = report_map.entry(pair).or_insert(Report::new(
                            ts.tv_sec.unsigned_abs(),
                            bytes,
                            tl.protocol.clone(),
                            nl.protocol.clone(),
                        ));
                        this_entry.update_report(
                            ts.tv_sec.unsigned_abs(),
                            bytes,
                            tl.protocol.clone(),
                            nl.protocol.clone(),
                        );
                    }
                }
            }
        }
    }
}
