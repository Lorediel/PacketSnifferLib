use std::collections::HashSet;
use dns_parser::Question;
use etherparse::{InternetSlice, TransportSlice};
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp};
use pcap::Packet;

#[derive(Debug)]
pub struct Report {
    first_ts: u64,
    last_ts: u64,
    total_bytes: u32,
    transport_layer_protocols: HashSet<String>,
    network_layer_protocols: HashSet<String>,
}

impl Report {
    pub fn new(ts: u64, bytes: u32, tlp: String, nlp: String) -> Report {
        let mut t_set = HashSet::new();
        let mut n_set = HashSet::new();
        t_set.insert(tlp);
        n_set.insert(nlp);
        Report{first_ts: ts, last_ts: ts, total_bytes: bytes, transport_layer_protocols: t_set, network_layer_protocols: n_set}
    }


    pub fn update_report(&mut self, ts: u64, bytes: u32, tlp: String, nlp: String) {
        self.last_ts = ts;
        self.total_bytes += bytes;
        self.transport_layer_protocols.insert(tlp);
        self.network_layer_protocols.insert(nlp);
    }

}


#[derive(Debug, Hash)]
pub struct AddressPortPair {
    pub first_pair: (String, String),
    pub second_pair: (String, String)
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
    pub protocol: String,
    pub source_port: Option<String>,
    pub destination_port: Option<String>
}

pub fn parse_transport(transport_value: Option<TransportSlice>) -> Option<TransportInfo> {
    if transport_value.is_some() {
        match transport_value.unwrap() {
            //Specificare dati Icmp con .icmp_type()
            //table type con .type_u8

            Icmpv4(i_slice) => {
                return Some(TransportInfo{protocol: "Icmpv4".to_string(), source_port: None, destination_port: None});
            },
            Icmpv6(i_slice) => {
                return Some(TransportInfo{protocol: "Icmpv6".to_string(), source_port: None, destination_port: None});
            },
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
    pub protocol: String,
    pub source_address: String,
    pub destination_address: String
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

#[derive(Debug)]
pub struct DnsInfo {
    pub id: u16,
    pub opcode: simple_dns::OPCODE,
    pub response_code: simple_dns::RCODE,
    pub queries: Vec<String>
}

pub fn parse_dns(dns_packet: Option< simple_dns::Packet>) -> Option<DnsInfo> {
    if dns_packet.is_some() {
                let dns = dns_packet.unwrap();
                return Some(DnsInfo{id: dns.header.id, opcode: dns.header.opcode, response_code: dns.header.response_code, queries : dns.questions.iter().map(|q| q.qname.to_string()).collect()});
    }
    None
}