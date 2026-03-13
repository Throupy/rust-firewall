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
    EthernetFrame, Ipv4Packet, UdpHeader, TcpHeader, Packet, // impl
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
        // if the packet can be parsed
        if let Some(packet) = Packet::parse(data) {
            let ruleset = rules.lock().unwrap();

            let matched = match_rules(&ruleset, &packet)
                .map(|r| format!(" MATCH: {}", r.name))
                .unwrap_or_default();

            println!("{} {}", packet, matched);
            
            // construct timestamp for outfile
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            let log_message = format!("{} {}{}", timestamp, packet, matched);
            log_packet(LOG_FILE, &log_message)
        }
    })
}   

