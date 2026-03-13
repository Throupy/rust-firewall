use std::net::Ipv4Addr;
use std::fmt;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// like a c# tagged union, for all intents + purposes
// enum but each variant can carry data
pub enum Transport {
    Tcp(u16, u16), // src_port, dst_port
    Udp(u16, u16),
    Unknown,
}

pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthernetFrame {
    pub fn parse(data: &[u8]) -> Option<EthernetFrame> {
        if data.len() < 14 { return None; }
    
        //            This type annotation is not needed, but linter puts it in
        let dst_mac: [u8; 6] = data[0..6].try_into().unwrap();
        let src_mac: [u8; 6] = data[6..12].try_into().unwrap();
        let ethertype: u16 = u16::from_be_bytes([data[12], data[13]]);
    
        // Instead of using 'return' keyword, you can just put the below
        // Notice the missing semi-colon - this indicates a retval.
        Some(EthernetFrame {
            dst_mac, src_mac, ethertype
        })
    }
}

pub struct Ipv4Packet {
    pub protocol: u8,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

impl Ipv4Packet {
    pub fn parse(data: &[u8]) -> Option<Ipv4Packet> {
        if data.len() < 20 { return None; }
    
        let protocol: u8 = data[9];
        let src_ip: [u8; 4] = data[12..16].try_into().unwrap();
        let dst_ip: [u8; 4] = data[16..20].try_into().unwrap();
    
        Some(Ipv4Packet { protocol, src_ip, dst_ip })
    }
}

pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}

impl TcpHeader {
    pub fn parse(data: &[u8]) -> Option<TcpHeader> {
        if data.len() < 20 { return None; }
    
        let src_port = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let dst_port = u16::from_be_bytes(data[2..4].try_into().unwrap());
        let flags = data[13].try_into().unwrap();
    
        Some(TcpHeader { src_port, dst_port, flags })
    }
}

pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

impl UdpHeader {
    pub fn parse(data: &[u8]) -> Option<UdpHeader> {
        if data.len() < 8 { return None; }
    
        let src_port = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let dst_port = u16::from_be_bytes(data[2..4].try_into().unwrap());
    
        return Some(UdpHeader { src_port, dst_port })
    }
}

pub struct Packet {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub transport: Transport,
}

impl Packet {
    pub fn parse(data: &[u8]) -> Option<Packet> {
        let ethernet_frame = EthernetFrame::parse(&data)?; // the ? means 'if this is None, return None from the func'
        if ethernet_frame.ethertype != 0x0800 { return None; }

        let ipv4_packet = Ipv4Packet::parse(&data[14..])?; // same ? here
        let src_ip = Ipv4Addr::from(ipv4_packet.src_ip); 
        let dst_ip = Ipv4Addr::from(ipv4_packet.dst_ip);
    
        let transport: Transport = match ipv4_packet.protocol {
            PROTO_TCP => TcpHeader::parse(&data[34..])
                .map(|tcp| Transport::Tcp(tcp.src_port, tcp.dst_port))
                .unwrap_or(Transport::Unknown),
            PROTO_UDP => UdpHeader::parse(&data[34..])
                .map(|udp| Transport::Udp(udp.src_port, udp.dst_port))
                .unwrap_or(Transport::Unknown),
            _ => Transport::Unknown,
        };

        Some(Packet{ src_ip, dst_ip, transport })
    }
}

// display 'trait' for the Packet struct
// think of trait like interface. fmt::Display is an interface, we are implementing
// the interface specifically for Packet
// like __str__ in python - controls how it's displayed
impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // [PROTO] SRC_IP:SRC_PORT -> DST_IP:DST_PORT 
        match &self.transport {
            Transport::Tcp(src_port, dst_port) => 
                write!(f, "[TCP] {}:{} -> {}:{}", self.src_ip, src_port, self.dst_ip, dst_port),
            
            Transport::Udp(src_port, dst_port) => 
                write!(f, "[UDP] {}:{} -> {}:{}", self.src_ip, src_port, self.dst_ip, dst_port),
            
            Transport::Unknown => 
                write!(f, "[UNK] {} -> {}", self.src_ip, self.dst_ip),
        }
    }
}