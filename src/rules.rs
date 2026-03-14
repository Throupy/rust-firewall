use std::{fs::File, io::BufReader, path::Path};

use serde::{Deserialize, Serialize};

use crate::headers::Packet;

use crate::headers::Transport;

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Rule {
    pub name: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>, // TCP/UDP for human readable json
}

pub fn load_rules(path: &str) -> RuleSet {
    if !Path::new(path).exists() {
        // raw string literal in rust - # means you don't have to escape inner quotes
        let default = r#"{"rules": []}"#;
        std::fs::write(path, default).unwrap();
        println!("No rules.json found, created one.");
    }

    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).unwrap()
}

pub fn save_rule(path: &str, ruleset: &RuleSet) {
    let serialized = serde_json::to_string_pretty(ruleset).unwrap();
    std::fs::write(path, serialized).unwrap();
}

pub fn match_rules<'a>(ruleset: &'a RuleSet, packet: &Packet) -> Option<&'a Rule> {
    // unpack the union enum data
    let (dst_port, protocol): (Option<u16>, &str) = match packet.transport {
        Transport::Tcp(_, dst_port, _) => (Some(dst_port), "tcp"),
        Transport::Udp(_, dst_port) => (Some(dst_port), "udp"),
        Transport::Unknown => (None, "unknown"),
    };

    // extract values from the packet obj
    let src_ip = packet.src_ip.to_string();
    let dst_ip = packet.dst_ip.to_string();

    for rule in &ruleset.rules {

        if let Some(rule_dst_port) = &rule.dst_port {
            if Some(*rule_dst_port) != dst_port { continue; }
        }
        if let Some(rule_dst_ip) = &rule.dst_ip {
            if rule_dst_ip != &dst_ip { continue }
        }
        if let Some(rule_src_ip) = &rule.src_ip {
            if rule_src_ip != &src_ip { continue }
        }
        if let Some(rule_protocol) = &rule.protocol {
            if rule_protocol.as_str() != protocol { continue }
        }
        return Some(rule);
    }
    None
} 