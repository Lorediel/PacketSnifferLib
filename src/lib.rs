mod report;

use std::borrow::Borrow;
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp, Unknown};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::{Active, Capture, Device, Inactive, Packet};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, format, Formatter};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;
//use dns_message_parser::EncodeError::String;
use std::string::String;
use report::*;
use std::time::Duration;


pub struct PacketCatcher{
    cv_m: Arc<(Condvar,Mutex<bool>)>,
    report_map: Arc< Mutex<HashMap<AddressPortPair, Report>>>,
    pub h: Option<JoinHandle<()>>
}
impl PacketCatcher {

    pub fn new() -> PacketCatcher {
        let mut report_map = Arc::new(Mutex::new(HashMap::new()));
        PacketCatcher{cv_m: Arc::new((Condvar::new(), Mutex::new(false))), report_map, h: None}
    }

    pub fn capture(
        &mut self,
        device_name: &'static str,
        filename: &str,
        interval: u32,
        filter: Option<&str>,
    ) {

        let mut cap = Capture::from_device(device_name)
            .unwrap()
            .promisc(true)
            .immediate_mode(true)
            .open()
            .unwrap();
        //Applica il filtro nel caso ci sia, altrimenti non fare nulla
        match filter {
            Some(filter) => {
                cap.filter(filter, true);
            }
            None => {}
        }

        let is_blocked = Arc::clone(&self.cv_m);
        let mut arc_map = Arc::clone(&self.report_map);
        let h = thread::spawn(move || {
            let mut i = 0;
            while let Ok(packet) = cap.next() {
                let (cvar, lock) = &*is_blocked;

                let mut is_b = lock.lock().unwrap();
                while *is_b {
                    std::mem::drop(cap);
                    is_b = cvar.wait(is_b).unwrap();
                    //println!("uscito: {:?}", packet.header.ts.tv_sec.unsigned_abs());
                    cap = Capture::from_device(device_name)
                        .unwrap()
                        .promisc(true)
                        .immediate_mode(true)
                        .open()
                        .unwrap();
                }
                let x = cap.next();

                let packet = x.unwrap();
                //self.tx.send(packet);

                let mut map = arc_map.lock().unwrap();
                parse_packet(packet, &mut map);
                i+=1;
                //println!("new packet {}", i);
                /*
                for (key, value) in map.iter() {
                    println!("{:?}, {:?}", key, value);
                }*/
            }
        });

        self.h = Some(h);

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
                                    dns_string.push_str("Id: " );
                                    dns_string.push_str( application_level.as_ref().unwrap().id.to_string().as_str());
                                    let opcode = format!("{:?}", application_level.as_ref().unwrap().opcode);
                                    dns_string.push_str("; Opcode: ");
                                    dns_string.push_str(opcode.as_str());
                                    let response_code = format!("{:?}", application_level.as_ref().unwrap().response_code);
                                    dns_string.push_str("; Response code: ");
                                    dns_string.push_str(response_code.as_str());
                                    dns_string.push_str("; Questions name: " );
                                    dns_string.push_str( application_level.as_ref().unwrap().queries.concat().as_str());
                                    dns_string.push_str("; Responses name: " );
                                    dns_string.push_str( application_level.as_ref().unwrap().responses.concat().as_str());
                                }
                            }
                        }

                        let pair = AddressPortPair::new(
                            nl.source_address,
                            first_port,
                            nl.destination_address,
                            second_port,
                        );

                        let mut icmp_string = match tl.icmp_type {
                            Some(icmp) => icmp,
                            None => "".to_string()
                        };

                        let link_string = linkinfo_tostring(ll);

                        let ts = packet.header.ts;
                        let bytes: u32 = packet.header.len;
                        let this_entry = report_map.entry(pair).or_insert(Report::new(
                            ts.tv_sec.unsigned_abs().into(),
                            bytes,
                            tl.protocol.clone(),
                            nl.protocol.clone(),
                            link_string.clone(),
                            icmp_string.clone(),
                            dns_string.clone().to_string()

                        ));
                        this_entry.update_report(
                            ts.tv_sec.unsigned_abs().into(),
                            bytes,
                            tl.protocol.clone(),
                            nl.protocol.clone(),
                            link_string.clone(),
                            icmp_string.clone(),
                            dns_string.clone().to_string()

                        );
                    }
                }
            }

        }
    }

    pub fn switch(&mut self, val: bool){
        let cv_m = Arc::clone(&self.cv_m);
        let (cvar, lock) = &*cv_m;
        let mut is_b = lock.lock().unwrap();
        *is_b = val;
        cvar.notify_one();
    }

  /*  pub fn stop_capture(&mut self, val:bool){
        let cv_m = Arc::clone(&self.cv_m);
        let (cvar, lock)= &*cv_m;
        let mut stop= lock.lock().unwrap();
        thread::sleep(Duration::from_millis(500));
        cvar.notify_one();
    }
    */


    pub fn empty_report(&mut self){

        let mut arc_map = Arc::clone(&self.report_map);
        let mut map = arc_map.lock().unwrap();
        for (key, value) in map.iter() {
            println!("{:?}, {:?}", key, value);
        }
        map.clear();
        for (key, value) in map.iter() {
            println!("===");
        }
    }

    pub fn parse_network_adapter() {
        let list = Device::list().unwrap();
        println!("{:?}", list);
        for (pos, d) in list.into_iter().enumerate() {
            let mut name = "".to_owned();
            name.push_str(&(pos+1).to_string());
            name.push_str(&") ");
            name.push_str(&d.name);
            println!("{}", name);
            let mut s1: String = "       -Description: ".to_owned();
            let s2: String = "       -Addresses: ".to_owned();
            let s3 = d.desc;
            let desc = match s3 {
                Some(des) => des,
                None => "No description".to_string()
            };
            s1.push_str(&desc);
            println!("{}", s1); //Description
            print!("{}", s2); //Addresses
            print!(" ");

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
