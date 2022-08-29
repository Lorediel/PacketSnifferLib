mod report;
mod errors;


use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp, Unknown};
use etherparse::{SlicedPacket};
use pcap::{Capture, Device, Packet};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::string::String;
use std::time::Duration;
use report::*;
use crate::errors::Errors;
use crate::Errors::InvalidInterval;

pub struct PacketCatcher{
    cv_m: Arc<(Condvar,Mutex<bool>)>,
    report_map: Arc< Mutex<HashMap<AddressPortPair, Report>>>,
    stop: Arc<Mutex<bool>>,
    pub h_cap: Option<JoinHandle<()>>,
    pub h_write: Option<JoinHandle<()>>
}
impl PacketCatcher {

    pub fn new() -> PacketCatcher {
        let report_map = Arc::new(Mutex::new(HashMap::new()));
        PacketCatcher{cv_m: Arc::new((Condvar::new(), Mutex::new(false))), report_map, stop: Arc::new(Mutex::new(false)), h_cap: None, h_write: None}
    }

    pub fn capture(
        &mut self,
        device_name: String,
        filename: String,
        interval: u64,
        filter: Option<&str>,
    ) -> Result<(), Errors> {
        if interval < 100 {
            return Err(Errors::InvalidInterval(interval));
        }

        let mut cap =
            match Capture::from_device(device_name.as_str()) {
                Ok(capture_active) => {
                    match capture_active.promisc(true)
                        .immediate_mode(true)
                        .open() {
                        Ok(activated_cap) => {activated_cap},
                        Err(e) => {return Err(Errors::InactivableCapture(device_name.clone()))}
                    }
                },
                Err(e) => {
                    return Err(Errors::InvalidCapture(e.to_string()));
                }};

        let is_blocked = Arc::clone(&self.cv_m);
        let arc_map = Arc::clone(&self.report_map);
        let stop_capture = Arc::clone(&self.stop);
        let h = thread::spawn(move || {
            let mut i = 0;
            'outer: loop {
                {
                    let is_stopped = stop_capture.lock().unwrap();

                    if *is_stopped {
                        break 'outer;
                    }
                }
                {
                    let (cvar, lock) = &*is_blocked;
                    let mut is_b = lock.lock().unwrap();
                    while *is_b {
                        is_b = cvar.wait(is_b).unwrap();
                        std::mem::drop(cap);
                        cap = Capture::from_device(device_name.as_str())
                            .unwrap()
                            .promisc(true)
                            .immediate_mode(true)
                            .open()
                            .unwrap();
                    }
                }
                match cap.next_packet() {
                    Ok(packet) => {

                        let mut map = arc_map.lock().unwrap();
                        parse_packet(packet, &mut map);

                    },
                    _ => {}
                }
            }

            println!("{}", "THREAD TERMINATO CORRETTAMENTE");

        });
        let arc_map_2 = Arc::clone(&self.report_map);
        let is_blocked_write = Arc::clone(&self.cv_m);
        let stop_capture_w = Arc::clone(&self.stop);
        let h_write = thread::spawn(move || {
            loop {
                {
                    let is_stopped = stop_capture_w.lock().unwrap();

                    if *is_stopped {
                        break;
                    }
                }
                {
                    let (cvar, lock) = &*is_blocked_write;
                    let mut is_b = lock.lock().unwrap();
                    while *is_b {
                        is_b = cvar.wait(is_b).unwrap();

                    }
                }
                thread::sleep(Duration::from_millis(interval));
                let mut map = arc_map_2.lock().unwrap();
                PacketCatcher::empty_report(&mut *map, &filename);
            }
        });
        self.h_write = Some(h_write);
        self.h_cap = Some(h);
        Ok(())
    }

    pub fn switch(&mut self, val: bool){
        let cv_m = Arc::clone(&self.cv_m);
        let (cvar, lock) = &*cv_m;
        let mut is_b = lock.lock().unwrap();
        *is_b = val;
        cvar.notify_all();
    }

    pub fn stop_capture(&mut self){
        let stop_capture = Arc::clone(&self.stop);
        let mut is_stopped = stop_capture.lock().unwrap();
        *is_stopped = true;
        let is_blocked = Arc::clone(&self.cv_m);
        let (cvar, lock) = &*is_blocked;
        let mut is_b = lock.lock().unwrap();
        *is_b = false;
        cvar.notify_all();
    }



    pub fn empty_report(map: &mut HashMap<AddressPortPair, Report>, filename: &str){

        //println!("fatto");
        write_file(filename, &*map);
        map.clear();
    }

    pub fn parse_network_adapter() -> Result<(Vec<String>), Errors> {
        let list = match Device::list() {
            Ok(list) => {list},
            Err(e) => {return Err(Errors::UnavailableDeviceList)}
        };

        let mut vettore = Vec::new();
        for (pos, d) in list.into_iter().enumerate() {
            let mut name = "".to_owned();
            name.push_str(&(pos+1).to_string());
            name.push_str(&") ");
            name.push_str(&d.name);
            println!("{}", name.replace("\\", "\\\\"));

            let mut name_vec = "".to_owned();
            name_vec.push_str(&d.name);
            name_vec.replace("\\", "\\\\");
            vettore.push(name_vec);

            let mut s1: String = "       -Description: ".to_owned();
            let s2: String = "       -Addresses: ".to_owned();
            let s3 = d.desc;
            let desc = match s3 {
                Some(des) => des,
                None => "No description available".to_string()
            };
            s1.push_str(&desc);
            println!("{}", s1); //Description
            print!("{}", s2); //Addresses
            print!(" ");

            let mut i = 0;
            while ( i<d.addresses.len() ) {
                println!("{:?}", d.addresses[i]);
                if  i != d.addresses.len() - 1 {
                    print!("                    ");
                }
                i+=1;
            }
            println!(" ");
        }
        Ok(vettore)
    }


}
fn parse_packet(packet: Packet, report_map: &mut HashMap<AddressPortPair, Report>) {


    match SlicedPacket::from_ethernet(&packet) {
        Err(value) => println!("Err {:?}", value),
        Ok(value) => {
            let transport_level = parse_transport(value.transport);
            let network_level = parse_network(value.ip);
            let link_level = parse_link(value.link);
            let mut dns_string = "".to_owned();

            if transport_level.is_some() && network_level.is_some() && link_level.is_some() {


                let tl = transport_level.unwrap();
                let nl = network_level.unwrap();
                let ll = link_level.unwrap();
                let first_port = match tl.source_port {
                    Some(port) => port,
                    None => "No port".to_string()
                };
                let second_port = match tl.destination_port {
                    Some(port) => port,
                    None => "No port".to_string()
                };


                if tl.protocol == "UDP" &&  (first_port == "53" || second_port=="53") {
                    match simple_dns::Packet::parse(&value.payload){
                        Err(value1) => {
                            if value1.to_string() != "Provided QType is invalid: 65" {
                                println!("{:?}", value1.to_string())
                            }
                        },
                        Ok(value1) => {
                            let application_level =  parse_dns(Some(value1));

                            dns_string = dns_info_to_string( application_level);
                        }
                    }
                }

                let pair = AddressPortPair::new(
                    nl.source_address,
                    first_port,
                    nl.destination_address,
                    second_port,
                );

                let icmp_string = match tl.icmp_type {
                    Some(icmp) => icmp,
                    None => "".to_string()
                };

                //let link_string = linkinfo_tostring(ll);

                let ts = packet.header.ts;
                let bytes: u32 = packet.header.len;
                let this_entry = report_map.entry(pair).or_insert(Report::new(
                    ts.tv_sec.unsigned_abs().into(),
                    bytes,
                    tl.protocol.clone(),
                    nl.protocol.clone(),
                    ll.clone(),
                    icmp_string.clone(),
                    dns_string.clone().to_string()

                ));
                this_entry.update_report(
                    ts.tv_sec.unsigned_abs().into(),
                    bytes,
                    tl.protocol.clone(),
                    nl.protocol.clone(),
                    ll.clone(),
                    icmp_string.clone(),
                    dns_string.clone().to_string()
                );
            }
        }
    }
}
/*pub fn filter(filter: String){

            let mut i = 0;
            while ( i<d.addresses.len() ) {
                println!("{:?}", d.addresses[i]);
                if ( i != d.addresses.len() - 1 ){
                    print!("                    ");
                }
                i+=1;
            }
            println!(" ");
        }
    }

}*/
