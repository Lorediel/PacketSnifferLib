use std::collections::HashSet;

use std::hash::{Hash, Hasher};

use dns_parser::Question;
use etherparse::{Icmpv4Type, Icmpv6Type, InternetSlice, LinkSlice, TransportSlice};
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp};
use etherparse::Icmpv6Type::*;
use etherparse::Icmpv4Type::*;
use etherparse::LinkSlice::Ethernet2;
use pcap::Packet;
use std::str;
use hex::encode;
use tls_parser::nom::HexDisplay;
use std::fmt;
use dns_message_parser::question::{QClass, QType};
use simple_dns::{CLASS, QCLASS, QTYPE};
use simple_dns::rdata::RData;

#[derive(Debug)]
pub struct Report {
    first_ts: u64,
    last_ts: u64,
    total_bytes: u32,
    transport_layer_protocols: HashSet<String>,
    network_layer_protocols: HashSet<String>,
    link_layer_info: HashSet<String>,
    icmp_info: HashSet<String>,
    dns_info: HashSet<String>
}


impl Report {
    pub fn new(ts: u64, bytes: u32, tlp: String, nlp: String, llp: String, icmp_string: String, dns_string: String) -> Report {

        let mut t_set = HashSet::new();
        let mut n_set = HashSet::new();
        let mut l_set = HashSet::new();
        let mut icmp_set = HashSet::new();
        let mut dns_set = HashSet::new();
        t_set.insert(tlp);
        n_set.insert(nlp);
        l_set.insert(llp);
        Report{first_ts: ts, last_ts: ts, total_bytes: bytes, transport_layer_protocols: t_set, network_layer_protocols: n_set, link_layer_info: l_set, icmp_info: icmp_set, dns_info: dns_set}
    }


    pub fn update_report(&mut self, ts: u64, bytes: u32, tlp: String, nlp: String, llp: String, icmp_inf: String, dns_inf: String) {

        self.last_ts = ts;
        self.total_bytes += bytes;
        self.transport_layer_protocols.insert(tlp);
        self.network_layer_protocols.insert(nlp);
        self.link_layer_info.insert(llp);
        self.icmp_info.insert(icmp_inf);
        self.dns_info.insert(dns_inf);
    }

}


#[derive(Debug)]
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

impl Eq for AddressPortPair{}

impl Hash for AddressPortPair{
    fn hash<H: Hasher>(&self, state: &mut H) {
        let a1 = &self.first_pair.0;
        let p1 = &self.first_pair.1;
        let a2 = &self.second_pair.0;
        let p2 = &self.second_pair.1;
        let s = format!("{}{}{}{}",a1,p1,a2,p2);
        let mut l: Vec<char> = s.chars().collect();
        l.sort_unstable();
        let j: String = l.into_iter().collect();
        j.hash(state)
    }
}



impl AddressPortPair {
    pub fn new(first_address: String, first_port: String, second_address: String, second_port: String) -> AddressPortPair {
        AddressPortPair{first_pair: (first_address, first_port), second_pair: (second_address, second_port)}
    }
}



#[derive(Debug)]
pub struct TransportInfo {
    pub protocol: String,
    pub source_port: Option<String>,
    pub destination_port: Option<String>,
    pub icmp_type: Option<String>,
}


pub fn icmpv6_type_parser(icmp_type: Option<Icmpv6Type>) -> Option<String>{
    if icmp_type.is_none() {
        return None;
    }
    let icmp = icmp_type.unwrap();
    match icmp {
        // Unknown is used when further decoding is currently not supported for the icmp type & code.
        // You can still further decode the packet on your own by using the raw data in this enum
        // together with `headers.payload` (contains the packet data after the 8th byte)
        Icmpv6Type::Unknown{ type_u8, code_u8, bytes5to8 } => {
            return Some(format!("Unknown, type: {}, code: {}", type_u8, code_u8).to_string())
        },
        Icmpv6Type::DestinationUnreachable(header) => return Some(format!("code: {}-Destination Unreachable",header.code_u8()).to_string()),
        Icmpv6Type::PacketTooBig { mtu } => return Some(("code: 0-Packet too big").to_string()),
        Icmpv6Type::TimeExceeded(code) => return Some(format!("code: {}-Time exceeded",code.code_u8()).to_string()),
        Icmpv6Type::ParameterProblem(header) => return Some(format!("code: {}-Parameter problem",header.code.code_u8()).to_string()),
        Icmpv6Type::EchoRequest(header) => return Some("code: 0-Echo request".to_string()),
        Icmpv6Type::EchoReply(header) => return Some("code: 0-Echo reply".to_string()),
    }
}

pub fn icmpv4_type_parser(icmp_type: Option<Icmpv4Type>) -> Option<String> {
    if icmp_type.is_none() {
        return None;
    }
    let icmp = icmp_type.unwrap();
    match icmp {
        Icmpv4Type::Unknown {
            type_u8,
            code_u8,
            bytes5to8,
        } => return Some(format!("Unknown, type: {}, code: {}", type_u8, code_u8).to_string()),
        Icmpv4Type::EchoReply(header) => {return Some("code: 0-Echo Reply".to_string())},
        Icmpv4Type::DestinationUnreachable(header) => {return Some(format!("code: {}-Destination Unreachable", header.code_u8()).to_string())},
        Icmpv4Type::Redirect(header) => {return Some(format!("code: {}-Redirect", header.code.code_u8()).to_string())},
        Icmpv4Type::EchoRequest(header) => {return Some("code: 0-Echo Request".to_string())},
        Icmpv4Type::TimeExceeded(code)=> {return Some(format!("code: {}-Time Exceeded", code.code_u8()).to_string())},
        Icmpv4Type::ParameterProblem(header) => {return Some("Parameter Problem".to_string())},
        Icmpv4Type::TimestampRequest(tsMessage) => {return Some("code: 0-Timestamp Request".to_string())},
        Icmpv4Type::TimestampReply(tsMessage) => {return Some("code: 0-Timestamp Reply".to_string())},
    };
}
//icmp_type: Some(i_slice.type_u8()
pub fn parse_transport(transport_value: Option<TransportSlice>) -> Option<TransportInfo> {
    if transport_value.is_some() {
        match transport_value.unwrap() {
            //Specificare dati Icmp con .icmp_type()
            //table type con .type_u8

            Icmpv4(i_slice) => {
                return Some(TransportInfo{protocol: "Icmpv4".to_string(), source_port: None, destination_port: None, icmp_type: icmpv4_type_parser(Some(i_slice.icmp_type()))});
            },
            Icmpv6(i_slice) => {
                return Some(TransportInfo{protocol: "Icmpv6".to_string(), source_port: None, destination_port: None, icmp_type: icmpv6_type_parser(Some(i_slice.icmp_type()))});
            },
            Udp(header) => {
                return Some(TransportInfo{protocol: "UDP".to_string(), source_port: Some(header.source_port().to_string()), destination_port: Some(header.destination_port().to_string()), icmp_type: None});
            },
            Tcp(header) => {
                return Some(TransportInfo{protocol: "TCP".to_string(), source_port: Some(header.source_port().to_string()), destination_port: Some(header.destination_port().to_string()), icmp_type: None});
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
pub struct LinkInfo {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub ether_type: String
}

pub fn parse_link(link_value: Option<LinkSlice>) -> Option<LinkInfo> {
    if link_value.is_some() {
        match link_value.unwrap() {
            Ethernet2(header) => {
                return Some(LinkInfo{source_mac: header.source(), destination_mac: header.destination(), ether_type: header.ether_type().to_string()});
            }

        }
    }
    None
}

pub fn linkinfo_tostring(li: LinkInfo) -> String {
    let mut s = "".to_owned();
    let smac = li.source_mac;
    let dmac = li.destination_mac;
    let mut sstring = "".to_owned();
    let mut dstring = "".to_owned();

    let mut i = 0;
    let mut y = 0;

    while i < smac.len() {
        sstring.push_str(&smac[i].to_string());
        if (i != smac.len() - 1) {
            sstring.push_str(&":");
        }
        i+=1;
    }
    while y < dmac.len() {
        dstring.push_str(&dmac[y].to_string());
        if (y != dmac.len() - 1) {
            dstring.push_str(&":");
        }
        y+=1;
    }

    s.push_str(&"source mac: ");
    s.push_str(&sstring);
    s.push_str(&", destination mac: ");
    s.push_str(&dstring);
    s.push_str(&", ether type: ");
    s.push_str(&li.ether_type);
    s
}

#[derive(Debug)]
pub struct DnsInfo {
    pub id: u16,
    pub opcode: simple_dns::OPCODE,
    pub response_code: simple_dns::RCODE,
    pub queries: Vec<String>,
    pub query_type : Vec<QTYPE> ,
    pub query_class : Vec<QCLASS>,
    pub responses : Vec<String>,
    pub response_class : Vec<CLASS>
}

pub fn parse_dns(dns_packet: Option< simple_dns::Packet>) -> Option<DnsInfo> {
    if dns_packet.is_some() {
                let dns = dns_packet.unwrap();
                return Some(DnsInfo{
                    id: dns.header.id,
                    opcode: dns.header.opcode,
                    response_code: dns.header.response_code,
                    queries : dns.questions.iter().map(|q| q.qname.to_string()).collect(),
                    query_type : dns.questions.iter().map(|q| q.qtype).collect(),
                    query_class : dns.questions.iter().map(|q| q.qclass).collect(),
                    responses:dns.answers.iter().map(|q| q.name.to_string()).collect(),
                    response_class :dns.answers.iter().map(|q| q.class).collect(),
                });
    }
    None
}