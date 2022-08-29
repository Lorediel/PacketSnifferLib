use std::collections::{HashMap, HashSet};

use std::hash::{Hash, Hasher};

use dns_parser::Question;
use etherparse::{Icmpv4Type, Icmpv6Type, InternetSlice, LinkSlice, TransportSlice};
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp};
use etherparse::Icmpv6Type::*;
use etherparse::Icmpv4Type::*;
use etherparse::LinkSlice::Ethernet2;
use std::{str};
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use chrono::{DateTime, Local};
use simple_dns::{CLASS, QCLASS, QTYPE};
use crate::Errors;

#[derive(Debug)]
pub struct Report {
    first_ts: u64,
    last_ts: u64,
    total_bytes: u32,
    transport_layer_protocols: HashSet<String>,
    network_layer_protocols: String,
    link_layer_info: HashSet<LinkInfo>,
    icmp_info: HashSet<String>,
    dns_info: HashSet<String>
}

pub struct MacAddress {
    bytes: [u8; 6],
}

impl MacAddress {
    /// Creates a new `MacAddress` struct from the given bytes.
    pub fn new(bytes: [u8; 6]) -> MacAddress {
        MacAddress { bytes }
    }
}


impl Report {
    pub fn new(ts: u64, bytes: u32, tlp: String, nlp: String, llp: LinkInfo, icmp_string: String, dns_string: String) -> Report {

        let mut t_set = HashSet::new();
        let mut l_set = HashSet::new();
        let mut icmp_set = HashSet::new();
        let mut dns_set = HashSet::new();
        t_set.insert(tlp);
        l_set.insert(llp);
        icmp_set.insert(icmp_string);
        dns_set.insert(dns_string);

        Report{first_ts: ts, last_ts: ts, total_bytes: bytes, transport_layer_protocols: t_set, network_layer_protocols: nlp, link_layer_info: l_set, icmp_info: icmp_set, dns_info: dns_set}
    }


    pub fn update_report(&mut self, ts: u64, bytes: u32, tlp: String, nlp: String, llp: LinkInfo, icmp_inf: String, dns_inf: String) {

        self.last_ts = ts;
        self.total_bytes += bytes;
        self.transport_layer_protocols.insert(tlp);
        self.network_layer_protocols = nlp;
        self.link_layer_info.insert(llp);
        self.icmp_info.insert(icmp_inf);
        self.dns_info.insert(dns_inf);
    }

}


#[derive(Debug)]
pub struct AddressPortPair {
    pub first_pair: (String, String),
    pub second_pair: (String, String)

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
        Icmpv4Type::Redirect(header) => {
            let mut ip_addr = header.gateway_internet_address;
            let mut s = format!("{}.{}.{}.{}", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
            return Some(format!("code: {}-Redirect {}", header.code.code_u8(), s).to_string())},
        Icmpv4Type::EchoRequest(header) => {return Some("code: 0-Echo Request".to_string())},
        Icmpv4Type::TimeExceeded(code)=> {return Some(format!("code: {}-Time Exceeded", code.code_u8()).to_string())},
        Icmpv4Type::ParameterProblem(_) => {return Some("Parameter Problem".to_string())},
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
            TransportSlice::Unknown(ip_protocol_number) => {return Some(TransportInfo{protocol: format!("Unknown | IP protocol number: {}", ip_protocol_number).to_string(), source_port: None, destination_port: None, icmp_type: None});}
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
            Ipv4(header, _) => {
                return Some(NetworkInfo{protocol: "IPv4".to_string(), source_address: header.source_addr().to_string(), destination_address: header.destination_addr().to_string()});
            }
            Ipv6(header, _) => {
                return Some(NetworkInfo{protocol: "IPv6".to_string(), source_address: header.source_addr().to_string(), destination_address: header.destination_addr().to_string()});
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub ether_type: String
}

impl Display for LinkInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "first mac address: {:?} second mac address: {:?} ether type: {}", self.source_mac, self.destination_mac, self.ether_type)
    }
}

impl PartialEq for LinkInfo {
    fn eq(&self, other: &Self) -> bool {
        if (self.source_mac == other.source_mac && self.destination_mac == other.destination_mac && self.ether_type == other.ether_type) {
            return true
        }
        if (self.source_mac == other.destination_mac && self.destination_mac == other.source_mac && self.ether_type == other.ether_type) {
            return true
        }
        return false
    }
}
impl Eq for LinkInfo {}

impl Hash for LinkInfo{
    fn hash<H: Hasher>(&self, state: &mut H) {
        let sm = &self.source_mac;
        let dm = &self.destination_mac;
        let et = &self.ether_type;
        let s = format!("{:?}{:?}{}",sm,dm,et);
        let mut l: Vec<char> = s.chars().collect();
        l.sort_unstable();
        let j: String = l.into_iter().collect();
        j.hash(state)
    }
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

pub fn mac_address_to_string(mac: MacAddress) -> String{
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac.bytes[0], mac.bytes[1],mac.bytes[2],mac.bytes[3],mac.bytes[4],mac.bytes[5])
}

pub fn linkinfo_tostring(li: &LinkInfo) -> String {
    let mut s = "".to_owned();
    let smac = li.source_mac;
    let smacc = MacAddress::new(smac);
    let dmac = li.destination_mac;
    let dmacc = MacAddress::new(dmac);
    let mut sstring = "".to_owned();
    let mut dstring = "".to_owned();


    sstring.push_str(&mac_address_to_string(smacc));
    dstring.push_str(&mac_address_to_string(dmacc));

    s.push_str(&"first mac address: ");
    s.push_str(&sstring);
    s.push_str(&" - ");
    s.push_str(&"second mac address: ");
    s.push_str(&dstring);
    s.push_str(&" - ");
    s.push_str(&"ether type: ");
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

pub fn dns_info_to_string ( application_level: Option<DnsInfo>) -> String {
    if application_level.is_some() {
        let mut dns_string = "".to_owned();

        dns_string.push_str("Id: ");
        dns_string.push_str(application_level.as_ref().unwrap().id.to_string().as_str());

        let opcode = format!("{:?}", application_level.as_ref().unwrap().opcode);
        dns_string.push_str("; Opcode: ");
        dns_string.push_str(opcode.as_str());

        let response_code = format!("{:?}", application_level.as_ref().unwrap().response_code);
        dns_string.push_str("; Response code: ");
        dns_string.push_str(response_code.as_str());

        dns_string.push_str("; Questions name: ");
        for x in application_level.as_ref().unwrap().queries.iter() {
            dns_string.push_str(x.as_str());
            dns_string.push_str(" | ");
        }

        dns_string.push_str("; Questions type: ");
        let query_type = format!("{:?}", application_level.as_ref().unwrap().query_type);
        dns_string.push_str(query_type.as_str());

        dns_string.push_str("; Questions class: ");
        let query_class = format!("{:?}", application_level.as_ref().unwrap().query_class);
        dns_string.push_str(query_class.as_str());

        dns_string.push_str("; Responses name: ");
        for x in application_level.as_ref().unwrap().responses.iter() {
            dns_string.push_str(x.as_str());
            dns_string.push_str(" | ");
        }
        dns_string.push_str("; Responses class: ");
        let response_class = format!("{:?}", application_level.as_ref().unwrap().response_class);
        dns_string.push_str(response_class.as_str());

        dns_string
    }
    else {
        return "DNS packet not well formatted".to_string();
    }
}

pub fn write_file(filename: &str, report : &HashMap<AddressPortPair,Report>) -> Result<(), Errors>{


    let  file = match OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename) {
        Ok(f) => {f},
        Err(e) => {return Err(Errors::FileError("Cannot open file".to_string()))}
    };

    let mut file = BufWriter::new(file);

    let vec = Vec::from_iter(report.iter());
    let local: DateTime<Local> = Local::now();
    write!(file, "================================================\n");
    write!(file, "NEW REPORT: {}\n",local);
    write!(file, "================================================\n\n");
    for x in vec {
        let string_to_print = parse_report(x);
        write!(file, "{}", string_to_print).expect("unable to write to file");
    }

    Ok(())
}

pub fn parse_report(report : (&AddressPortPair,&Report)) -> String {
    let mut i;
    let mut string_report = "".to_owned();

    string_report.push_str("-----Packets info-----");
    string_report.push( '\n');

    string_report.push_str("First pair: ");
    string_report.push_str(report.0.first_pair.0.as_str());
    string_report.push_str("; ");
    string_report.push_str( report.0.first_pair.1.as_str());
    string_report.push( '\n');

    string_report.push_str("Second pair: ");
    string_report.push_str(report.0.second_pair.0.to_string().as_str());
    string_report.push_str("; ");
    string_report.push_str(report.0.second_pair.1.to_string().as_str());
    string_report.push( '\n');

    string_report.push_str("First timestamp: ");
    string_report.push_str(report.1.first_ts.to_string().as_str());
    string_report.push( '\n');

    string_report.push_str("Last timestamp: ");
    string_report.push_str(report.1.last_ts.to_string().as_str());
    string_report.push( '\n');

    string_report.push_str("Total bytes: ");
    string_report.push_str(report.1.total_bytes.to_string().as_str());
    string_report.push( '\n');

    string_report.push_str("Transport layer protocol: ");
    i = 0;
    let mut tl_info_len = report.1.transport_layer_protocols.len();
    for info in &report.1.transport_layer_protocols {
        string_report.push_str(info.as_str());
        if i != tl_info_len-1 {
            string_report.push_str(", ")
        }
        i+=1;
    }
    string_report.push_str("\n");

    string_report.push_str("Network layer protocol: ");
    string_report.push_str((report.1.network_layer_protocols.to_string()).as_str());
    string_report.push_str("\n");

    string_report.push_str("Link layer info:");
    string_report.push_str("\n");
    i = 0;
    let mut link_info_len = report.1.link_layer_info.len();
    for info in &report.1.link_layer_info {
        string_report.push_str(linkinfo_tostring(info).as_str());
        if i != link_info_len-1 {
            string_report.push_str(", ")
        }
        i+=1;
    }
    string_report.push_str("; \n");


    string_report.push_str("Icmp info:");
    string_report.push_str("\n");
    i = 0;
    let mut icmp_info_len = report.1.icmp_info.len();
    for info in &report.1.icmp_info {
        string_report.push_str(info.as_str());
        if i != icmp_info_len-1 {
            string_report.push_str(", ")
        }
        i+=1;
    }
    //string_report.push_str((report.1.icmp_info.to_string()).as_str());
    string_report.push_str("; \n");



    string_report.push_str("Dns info:");
    string_report.push_str("\n");
    i = 0;
    let mut dns_info_len = report.1.dns_info.len();
    for info in &report.1.dns_info {
        string_report.push_str(info.as_str());
        if i != dns_info_len-1 {
            string_report.push_str(", ")
        }
        i+=1;
    }
    string_report.push_str("; \n");

    string_report.push( '\n');
    string_report.push( '\n');

    string_report

}

