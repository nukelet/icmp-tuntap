use nom::bytes;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    RedirectMessage = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    BadIpHeader = 12,
    Timestamp = 13,
    TimestampReply = 14,
    Unimplemented(u8),
}

#[derive(Debug, Copy, Clone)]
struct IcmpHeader {
    icmp_type: IcmpType,
    code: u8,
    checksum: u16,
    rest: u32,
}

// #[derive(Debug, Copy, Clone)]
// struct IcmpPacket {
//     header: IcmpHeader,
// }

trait IcmpPacket {
    fn new(header: IcmpHeader) -> Self {
        
    }   
}

struct IcmpPacket
