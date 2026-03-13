# Rust Firewall
A primitive packet filter written in Rust, targeting Linux on AMD64. Built as an excuse for a learning exercise for low-level systems and network programming in Rust.

Doesn't actually block packets yet (which is mostly the point of a firewall.. but anyway).

### Features
Raw packet capture - uses raw Linux sockets via libc (AF_PACKET, SOCK_RAW) directly, no pcap dependency
Manual header parsing - Ethernet, IPv4, TCP/UDP parsed by hand into Rust structs
Rule engine - JSON-based rules supporting filtering by source IP, destination IP, destination port, and protocol
Persistent rules - rules are saved back to disk on modification
Timestamped logging - rule matches written to packets.log
Runtime CLI - TCP server on port 7878 accepting live commands while capture runs (yay async)
