// there are wrappers, but trying to keep it low level
// will b more invovled than the raw socket work from before (capture.rs)
// because libnetfilter_queue has a callback-based C API which looks... awkward
// https://github.com/fqrouter/libnetfilter_queue/blob/master/src/libnetfilter_queue.c

// import primitive C types - rust and C have different type systems, so need to match C func sigs EXACTLY
use libc::{c_int, c_void, uint32_t};

// TODO: constants file?
use crate::capture::{MAX_ETHERNET_FRAME_SIZE};

// libnetfilter_queue has internal structs like nfq_handle that you never actually have to look inside
// you just pass pointers to them between C functions. The _private attr is a zero-size
// field that basically has unknown contents. #[repr(C)] ensures that rust lays it out
// (in memory) the same way C would.
// they are a bit like file descriptors - but as a pointer.
#[repr(C)] 
pub struct NetFilterConnectionHandle { _private: [u8; 0] }

#[repr(C)] 
pub struct NetFilterQueueHandle { _private: [u8; 0] }

#[repr(C)]
pub struct QueuedPacket { _private: [u8; 0] }

#[repr(C)]
pub struct QueuedPacketHeader {
    pub packet_id: u32,
    pub hw_protocol: u16,
    pub hook: u8,
}

// mitigate 'cannoot be sent between threads safely' error.. TODO: look into this
pub struct SendableHandle(pub *mut NetFilterConnectionHandle);
unsafe impl Send for SendableHandle {}

// effectively tell rust that these functions exists in C, and this is how they are defined in rust
// it's up to me (the developer) to ensure that the signatures match - the 'unsafe' block means that the 
// compiler will trust that they match the actual library sigs
unsafe extern "C" {
    // https://github.com/fqrouter/libnetfilter_queue/blob/master/src/libnetfilter_queue.c
    // the function names have to match exactly, for the reasons above.
    // you could wrap them in rust functions, but not really much point.
    
    // raw mutable pointer - C's struct 'nfq_handle*'
    fn nfq_open() -> *mut NetFilterConnectionHandle;
    fn nfq_close(handle: *mut NetFilterConnectionHandle) -> c_int;

    // bind the handle of the queue to a protocol family (pf).
    // AF_INET is for IPv4. 
    fn nfq_bind_pf(handle: *mut NetFilterConnectionHandle, pf: u16) -> c_int;

    // create queue number 'num' and registers 'cb' as the callback function.
    // every packet that arrives on the queue will trigger 'cb'.
    // data is the raw ptr to anything to be passed through to the callback
    fn nfq_create_queue(handle: *mut NetFilterConnectionHandle, num: u16, cb: extern "C" fn(*mut NetFilterQueueHandle, *mut c_void, *mut QueuedPacket, *mut c_void) -> c_int, data: *mut c_void) -> *mut NetFilterQueueHandle;
    
    // issue the 'verdict' of a packet (i.e. NF_ACCEPT, NF_DROP).
    // data_len and buf are for if you want to modify the packet (I think?) - pass 0 and null to just accept/drop unmodified
    fn nfq_set_verdict(handle: *mut NetFilterQueueHandle, id: u32, verdict: u32, data_len: u32, buf: *const u8) -> c_int;
    fn nfq_fd(handle: *mut NetFilterConnectionHandle) -> c_int;
    /*
    from: https://github.com/fqrouter/libnetfilter_queue/blob/master/src/libnetfilter_queue.c#907
    struct nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(struct nfq_data *nfad)
    {
        return nfnl_get_pointer_to_data(nfad->data, NFQA_PACKET_HDR,
                        struct nfqnl_msg_packet_hdr);
    }
     */
    // struct here is the difficult one... nfq_data refers to...
    // i have created a new struct QueuedPacket for this, unsure if required.
    fn nfq_get_msg_packet_hdr(nfad: *mut QueuedPacket) -> *mut QueuedPacketHeader;

    fn nfq_handle_packet(handle: *mut NetFilterConnectionHandle, buf: *mut c_void, len: c_int) -> c_int;
}

// this is the callback ('cb') function to be called against every packet
// that arrives on the queue/
// extern "C" because C is calling it
extern "C" fn callback(
    queue_handler: *mut NetFilterQueueHandle, // queue handler - used to call nfq_set_verdict to issue a verdict for a pkt.
    _raw_message: *mut c_void,
    packet_data: *mut QueuedPacket, // pakcet data
    _data: *mut c_void,
) -> c_int {
    unsafe {
        // in the callback, get the packet hdr first
        let packet_header = nfq_get_msg_packet_hdr(packet_data);
        if packet_header.is_null() { return 0; }
        let packet_id = u32::from_be((*packet_header).packet_id); // endian-ness conversion
        nfq_set_verdict(
            queue_handler, 
            packet_id, 
            NF_ACCEPT,
            0,
            std::ptr::null()
        );
    }
    0
}

pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

// ret a tuple of: main handle, queue handle, and filter descriptor
// need all of em: handles for issuing verdicts, fd for reading packets in a loop
pub fn open_queue() -> (*mut NetFilterConnectionHandle, *mut NetFilterQueueHandle, c_int) {
    unsafe { // 'unsafe' feels bad... TODO: is this not rust best practice or just something to accept? 
        let connection_handle = nfq_open();
        if connection_handle.is_null() { panic!("nfq_open() failed for some reason..."); }

        if nfq_bind_pf(connection_handle, libc::AF_INET as u16) < 0 {
            panic!("nfq_bind_pf() failed for some reason...");
        }

        // create the queue itself
        let queue_handle: *mut NetFilterQueueHandle = nfq_create_queue(
            connection_handle, 0, callback, std::ptr::null_mut()
        );
        if queue_handle.is_null() { panic!("nfq_create_queue() failed for some reason - couldn't get queue_handle"); }

        // get the file descriptor so we can recv() 
        let file_descriptor: i32 = nfq_fd(connection_handle);

        // return all three - conn handle, queue handle, and fd
        (connection_handle, queue_handle, file_descriptor)
    }
}

// read loop, similar to capture.rs but reading from the nfqeue fs instead of the raw socket fd
pub fn run_queue_loop(connection_handle: SendableHandle, queue_fd: c_int) {
    let mut buf = [0u8; MAX_ETHERNET_FRAME_SIZE];
    loop {
        unsafe {
            let retval: isize = libc::recv(
                queue_fd, // file desc of sock (from open_raw_socket)
                buf.as_mut_ptr() as *mut libc::c_void, // raw ptr to the buffer memory
                buf.len(),  // buffer size - no buf overflows here
                0 // 0 - blocking - recv will wait til a packet arrives
            ) as isize;
            if retval == -1 { panic!("Recv() failed"); }
            nfq_handle_packet(
                connection_handle.0, 
                buf.as_mut_ptr() as *mut c_void,
                retval as c_int
            );
        }
    }
}