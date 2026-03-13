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