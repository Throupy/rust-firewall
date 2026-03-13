pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

pub struct Ipv4Packet {
    pub protocol: u8,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}

pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

// like a c# tagged union, for all intents + purposes
// enum but each variant can carry data
pub enum Transport {
    Tcp(u16, u16), // src_port, dst_port
    Udp(u16, u16),
    Unknown,
}

pub fn parse_ethernet(data: &[u8]) -> Option<EthernetFrame> {
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

pub fn parse_ipv4(data: &[u8]) -> Option<Ipv4Packet> {
    if data.len() < 20 { return None; }

    let protocol: u8 = data[9];
    let src_ip: [u8; 4] = data[12..16].try_into().unwrap();
    let dst_ip: [u8; 4] = data[16..20].try_into().unwrap();

    Some(Ipv4Packet { protocol, src_ip, dst_ip })
}

pub fn parse_tcp(data: &[u8]) -> Option<TcpHeader> {
    if data.len() < 20 { return None; }

    let src_port = u16::from_be_bytes(data[0..2].try_into().unwrap());
    let dst_port = u16::from_be_bytes(data[2..4].try_into().unwrap());
    let flags = data[13].try_into().unwrap();

    Some(TcpHeader { src_port, dst_port, flags })
}

pub fn parse_udp(data: &[u8]) -> Option<UdpHeader> {
    if data.len() < 8 { return None; }

    let src_port = u16::from_be_bytes(data[0..2].try_into().unwrap());
    let dst_port = u16::from_be_bytes(data[2..4].try_into().unwrap());

    return Some(UdpHeader { src_port, dst_port })
}