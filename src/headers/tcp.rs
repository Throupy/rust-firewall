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
