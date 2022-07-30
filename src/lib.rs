use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp, Unknown};
use pcap::{Active, Capture, Inactive, Packet};

pub struct PacketCatcher{
    report_map: HashMap<AddressPortPair, Report>
}


impl PacketCatcher {

    pub fn new() -> PacketCatcher {

        PacketCatcher{ report_map: HashMap::new()}

    }
    pub fn capture(&mut self, device_name: &str, filename: &str, interval: u32, filter: Option<&str>) {


        let mut cap = Capture::from_device(device_name).unwrap().promisc(true).open().unwrap();
        //Applica il filtro nel caso ci sia, altrimenti non fare nulla
        match filter {
            Some(filter) => {
                cap.filter(filter, false);
            },
            None => {}
        }
        /* DA SCOMMENTARE
        while let Ok(packet) = cap.next() {
            self.parse_packet(packet);
        };*/

        for i in 1..5000 {
            let x = cap.next();
            let packet = x.unwrap();
            self.parse_packet(packet);
        };


        for (key, value) in &self.report_map {
            println!("{:?}, {:?}", key, value);
        }


    }


    pub fn parse_packet(&mut self, packet: Packet) {
        match SlicedPacket::from_ethernet(&packet) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                let transport_level = parse_transport(value.transport);
                let network_level = parse_network(value.ip);

                if transport_level.is_some() && network_level.is_some() {
                    let tl = transport_level.unwrap();
                    let nl = network_level.unwrap();
                    let pair = AddressPortPair::new(nl.source_address, tl.source_port.unwrap(),
                                                          nl.destination_address, tl.destination_port.unwrap());

                    let ts = packet.header.ts;
                    let bytes = packet.header.len;
                    let this_entry = self.report_map.entry(pair).or_insert(Report{n: 1});
                    *this_entry = Report{n: this_entry.n + 1};
                }

            }

        }

    }
}

#[derive(Debug)]
pub struct Report {
    n: i32
}


#[derive(Debug, Hash)]
pub struct AddressPortPair {
    first_pair: (String, String),
    second_pair: (String, String)
    /*
    first_address: String,
    first_port: String,
    second_address: String,
    second_port: String*/
}

impl PartialEq for AddressPortPair {
    fn eq(&self, other: &Self) -> bool {
        //Sorgente == Sorgente e Destinazione == Destinazione
        if self.first_pair == other.first_pair && self.second_pair == other.second_pair {
            return true;
        }
        //Sorgente = Destinazione e Destinazione == Sorgente
        if self.first_pair == other.second_pair && self.second_pair == other.first_pair {
            return true;
        }
        return false
    }
}

impl Eq for AddressPortPair {}


impl AddressPortPair {
    pub fn new(first_address: String, first_port: String, second_address: String, second_port: String) -> AddressPortPair {
        AddressPortPair{first_pair: (first_address, first_port), second_pair: (second_address, second_port)}
    }
}



#[derive(Debug)]
pub struct TransportInfo {
    protocol: String,
    source_port: Option<String>,
    destination_port: Option<String>
}

pub fn parse_transport(transport_value: Option<TransportSlice>) -> Option<TransportInfo> {
    if transport_value.is_some() {
        match transport_value.unwrap() {
            //Specificare dati Icmp con .icmp_type()
            //table type con .type_u8
            /*
            Icmpv4(i_slice) => {
                return Some(TransportInfo{protocol: "Icmpv4".to_string(), source_port: None, destination_port: None});
            },
            Icmpv6(i_slice) => {
                return Some(TransportInfo{protocol: "Icmpv6".to_string(), source_port: None, destination_port: None});
            },*/
            Udp(header) => {
                return Some(TransportInfo{protocol: "UDP".to_string(), source_port: Some(header.source_port().to_string()), destination_port: Some(header.destination_port().to_string())});
            },
            Tcp(header) => {
                return Some(TransportInfo{protocol: "TCP".to_string(), source_port: Some(header.source_port().to_string()), destination_port: Some(header.destination_port().to_string())});
            },
            //Unknown(ip_protocol_number) => {return Some(TransportInfo{protocol: "Unknown".to_string(), source_port: None, destination_port: None});}
            _ => {return None;}

        }
    }
    None
}
#[derive(Debug)]
pub struct NetworkInfo {
    protocol: String,
    source_address: String,
    destination_address: String
}

//Can also check extension headers
pub fn parse_network(ip_value: Option<InternetSlice>) -> Option<NetworkInfo> {
     if ip_value.is_some() {
         match ip_value.unwrap() {
             Ipv4(header, extension) => {
                 return Some(NetworkInfo{protocol: "IPv4".to_string(), source_address: header.source_addr().to_string(), destination_address: header.destination_addr().to_string()});
             }
             Ipv6(header, extenion) => {
                 return Some(NetworkInfo{protocol: "IPv6".to_string(), source_address: header.source_addr().to_string(), destination_address: header.destination_addr().to_string()});
             }
         }
     }
     None
}