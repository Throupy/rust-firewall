// like a c# tagged union, for all intents + purposes
// enum but each variant can carry data
pub enum Transport {
    Tcp(u16, u16), // src_port, dst_port
    Udp(u16, u16),
    Unknown,
}