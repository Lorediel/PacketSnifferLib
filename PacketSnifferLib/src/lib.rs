//! Packet sniffer is a library useful in order to capture
//! and parse network packet of different type. It is able to capture
//! packets of level 2, level 3 and Dns packets, parsing and optionally writing them into a specific
//! text file.
//!
//! # Example on how to capture
//!
//! ```no_run
//! let mut p = PacketCatcher::new();
//! p.capture("en0", "filename.txt", 1000, Some("tcp or udp")).unwrap();
//! thread::sleep(time::Duration::from_millis(3000)); //sleep for 3 seconds
//! p.switch(true); //pause the capture
//! thread::sleep(time::Duration::from_millis(3000)); //sleep for 3 seconds
//! p.switch(false); //resume the capture
//! thread::sleep(time::Duration::from_millis(4000)); //sleep for 4 seconds
//! p.stop_capture(); //stop the capture
//! ```

/// Mod containing structs and functions useful in order to parse, format and write on file the informations
/// relative to a specific packet.
pub mod report;

/// Mod containing a struct to manage most common errors.
pub mod errors;


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
use crate::errors::PacketSnifferError;
use crate::PacketSnifferError::InvalidInterval;
///Struct useful to manage info about sniffed packages and to control the capture flow.
pub struct PacketCatcher{
    /// Arc that has a condition variable and a Mutex with the value to stop and resume the capture process
    cv_m: Arc<(Condvar,Mutex<bool>)>,
    /// Field that contains an ```Arc< Mutex<HashMap<AddressPortPair, Report>>>``` object used in order to contain packets informations.
    report_map: Arc< Mutex<HashMap<AddressPortPair, Report>>>,
    /// Arc that contains a mutex that has a value to stop the capturing process
    stop: Arc<Mutex<bool>>,
    /// `Option<JoinHandle<()>>` relative to capture process.
    pub h_cap: Option<JoinHandle<()>>,
    /// `Option<JoinHandle<()>>` relative to write on file process.
    pub h_write: Option<JoinHandle<()>>
}


impl PacketCatcher {
    /// Create a new  PacketCatcher struct.
    pub fn new() -> PacketCatcher {
        let report_map = Arc::new(Mutex::new(HashMap::new()));
        PacketCatcher{cv_m: Arc::new((Condvar::new(), Mutex::new(false))), report_map, stop: Arc::new(Mutex::new(false)), h_cap: None, h_write: None}
    }

    /// Performs packets capture packet by packet on a specific device. It takes as parameter also the name
    /// of the output file and the updating interval of the report.
    /// In case of successful catching, it call function `parse_packet` which update a `HashMap<AddressPortPair, Report>` struct.
    /// `device_name` Name of the device to be analyzed.
    /// `filename` file name of the file which will contain the report.
    /// `interval` Interval after which a new report is generated.
    /// `filter` Filter to be applied to the capture, following the Berkeley Packet Filter Syntax. Check guide at [link](https://biot.com/capstats/bpf.html).
    pub fn capture(
        &mut self,
        device_name: String,
        filename: String,
        interval: u64,
        filter: Option<String>,
    ) -> Result<(), PacketSnifferError> {
        if interval < 100 {
            return Err(PacketSnifferError::InvalidInterval(interval));
        }
        let mut cap =
            match Capture::from_device(device_name.as_str()) {
                Ok(capture_active) => {
                    match capture_active.promisc(true)
                        .immediate_mode(true)
                        .open() {
                        Ok(activated_cap) => {activated_cap},
                        Err(e) => {return Err(PacketSnifferError::InactivableCapture(device_name, e.to_string()))}
                    }
                },
                Err(e) => {
                    return Err(PacketSnifferError::InvalidCapture(device_name, e.to_string()));
                }};
        if filter.is_some() {
            match cap.filter(filter.as_ref().unwrap().as_str(), true) {
                Ok(()) => {},
                Err(e) => {return Err(PacketSnifferError::InvalidFilter(filter.unwrap(), e.to_string()))}
            };
        }
        let is_blocked = Arc::clone(&self.cv_m);
        let arc_map = Arc::clone(&self.report_map);
        let stop_capture = Arc::clone(&self.stop);
        let h = thread::spawn(move || {
            let _i = 0;
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

    ///Performs start and pause of the packet capture action. It takes as parameter a boolean value.
    /// If parameter `val: bool` is true, capturing will pause.
    /// If parameter `val: bool` is false, capturing will resume.
    pub fn switch(&mut self, val: bool){
        let cv_m = Arc::clone(&self.cv_m);
        let (cvar, lock) = &*cv_m;
        let mut is_b = lock.lock().unwrap();
        *is_b = val;
        cvar.notify_all();
    }

    /// The function stop definitely the packets capturing.
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


    /// The function is used in order to write on the text file the content of the parameter `map`.
    /// It also clears the parameter HashMap to create a new report `HashMap<AddressPortPair, Report>`.
    pub fn empty_report(map: &mut HashMap<AddressPortPair, Report>, filename: &str){
        //println!("fatto");
        write_file(filename, &*map).unwrap();
        map.clear();
    }
}

/// Writes the network adapters parsed in a human readable way
pub fn parse_network_adapter() -> Result<Vec<String>, PacketSnifferError> {
    let list = match Device::list() {
        Ok(list) => {list},
        Err(e) => {return Err(PacketSnifferError::UnavailableDeviceList(e.to_string()))}
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
        name_vec = name_vec.replace("\\", "\\\\");
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
        while  i<d.addresses.len()  {
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

/// Takes as argument the `packet` to parse and saves it inside the `report_map`
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
