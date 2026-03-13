mod headers;
mod rules;
mod logger;
mod cli;
mod capture;

use std::net::{Ipv4Addr};
use std::sync::{Arc, Mutex};

use chrono::Local;

use headers::{
    PROTO_TCP, PROTO_UDP, // constants
    parse_ethernet, parse_ipv4, parse_tcp, parse_udp, // methods
    Transport, // enums
};

use rules::{
    load_rules, match_rules
};

use logger::{
    log_packet,
};

use capture::{open_raw_socket, capture_loop};

const RULES_FILE: &str = "rules.json";
const LOG_FILE: &str = "packets.log";

#[tokio::main]
async fn main() {
    println!("Welcome to the packet filter");

    let rules = Arc::new(Mutex::new(load_rules(RULES_FILE)));
    
    let cli_rules = Arc::clone(&rules);
    tokio::spawn(async move {
        cli::start_cli(cli_rules, 7878).await;
    });

    let fd = open_raw_socket();

    capture_loop(fd, move |data| {
        if let Some(ethernet_frame) = parse_ethernet(&data) {
            if ethernet_frame.ethertype == 0x0800 {
                if let Some(ipv4_packet) = parse_ipv4(&data[14..]) {
                    let src_ip = Ipv4Addr::from(ipv4_packet.src_ip); 
                    let dst_ip = Ipv4Addr::from(ipv4_packet.dst_ip);
    
                    let transport: Transport = match ipv4_packet.protocol {
                        PROTO_TCP => parse_tcp(&data[34..])
                            .map(|tcp| Transport::Tcp(tcp.src_port, tcp.dst_port))
                            .unwrap_or(Transport::Unknown),
                        PROTO_UDP => parse_udp(&data[34..])
                            .map(|udp| Transport::Udp(udp.src_port, udp.dst_port))
                            .unwrap_or(Transport::Unknown),
                        _ => Transport::Unknown,
                    };
    
                    let summary = match &transport {
                        Transport::Tcp(src_port, dst_port) => {
                            let ruleset = rules.lock().unwrap();
                            let matched = match_rules(&ruleset, &src_ip.to_string(), &dst_ip.to_string(), *dst_port, "tcp")
                                .map(|r| format!(" MATCH: {}", r.name))
                                .unwrap_or_default();
                            format!("[TCP] {}:{} -> {}:{}{}", src_ip, src_port, dst_ip, dst_port, matched)
                        }
                        Transport::Udp(src_port, dst_port) => {
                            format!("[UDP] {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port)
                        }
                        Transport::Unknown => {
                            format!("[UNK] {} -> {}", src_ip, dst_ip)
                        }
                    };
    
                    println!("{}", summary);
                    
                    // construct timestamp for outfile
                    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
                    let log_message = format!("{} {}", timestamp, summary);
                    log_packet(LOG_FILE, &log_message)
                }
            }   
        }
    })
}
