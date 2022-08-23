
pub struct Filter {
    host_src: Option<String>,
    port_src: Option<String>,
    host_dst: Option<String>,
    port_dst: Option<String>,
    application_protocol: Option<String>,
    transport_protocol: Option<String>,
    network_protocol: Option<String>,
    link_protocol: Option<String>,
}

impl Filter {
    pub fn new(host_src: Option<String>, port_src: Option<String>, host_dst: Option<String>, port_dst: Option<String>,
               application_protocol: Option<String>, transport_protocol: Option<String>,
                network_protocol: Option<String>, link_protocol: Option<String>) -> Filter {
        Filter{host_src, port_src, host_dst, port_dst, application_protocol, transport_protocol, network_protocol, link_protocol}
    }

    pub fn parse_filter(&self){
        let supported_tp = ["tcp".to_string(), "udp".to_string(), "icmp4".to_string(), "icmp6".to_string()];
        let mut bpf_filter =  "".to_string();
        match &self.host_src {
            Some(host_ip) => {
                bpf_filter.push_str(&format!("src host {}", host_ip))
            }
            None => {}
        }
        match &self.port_src {
            Some(port) => {
                bpf_filter.push_str(&format!("src port {}", port))
            }
            None => {}
        }
        match &self.host_dst {
            Some(host_ip) => {
                bpf_filter.push_str(&format!("dst host {}", host_ip))
            }
            None => {}
        }
        match &self.port_dst {
            Some(port) => {
                bpf_filter.push_str(&format!("dst port {}", port))
            }
            None => {}
        }
        match &self.transport_protocol {
            Some(proto) => {
                if supported_tp.contains(proto) {
                    bpf_filter.push_str(&format!("{}", proto))
                }
                else {
                    //ERRORE
                }
            }
            None => {}
        }



    }
}



