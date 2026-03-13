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