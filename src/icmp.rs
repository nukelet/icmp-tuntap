use nom::IResult;
use nom::bytes;
use nom::number;
use nom::sequence;

use crate::ipv4::{Ipv4Address, Ipv4Header};
use crate::ipv4::parse_ipv4_header;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum IcmpType {
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

impl From<u8> for IcmpType {
    fn from(orig: u8) -> Self {
        match orig {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            5 => IcmpType::RedirectMessage,
            8 => IcmpType::EchoRequest,
            9 => IcmpType::RouterAdvertisement,
            10 => IcmpType::RouterSolicitation,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::BadIpHeader,
            13 => IcmpType::Timestamp,
            14 => IcmpType::TimestampReply,
            _ => IcmpType::Unimplemented(orig),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum IcmpHeaderData {
    Redirect {
        ip_addr: Ipv4Address,
        // ip header and first 8 bytes of the original datagram
        ip_header: Ipv4Header,
        data: [u8; 8],
    },

    TimeExceeded {
        ip_header: Ipv4Header,
        data: [u8; 8],
    },

    Timestamp {
        id: u16,
        seq: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },

    TimestampReply {
        id: u16,
        seq: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },

    DestinationUnreachable {
        next_hop_mtu: u16,
        ip_header: Ipv4Header,
        data: [u8; 8],
    },
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub data: Option<IcmpHeaderData>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct IcmpPacket {
    pub header: IcmpHeader,
    pub data: Vec<u8>,
}

impl IcmpPacket {
    fn description(&self) -> &'static str {
        let icmp_type = self.header.icmp_type;
        let code = self.header.code;
        match icmp_type {
            IcmpType::EchoReply => {
                match code {
                    0 => "Echo reply",
                    _ => "",
                }
            },

            IcmpType::DestinationUnreachable => {
                match code {
                    0 => "Destination network unreachable",
                    1 => "Destination host unreachable",
                    2 => "Destination protocol unreachable",
                    3 => "Destination port unreachable",
                    4 => "Fragmentation required",
                    5 => "Source route failed",
                    6 => "Destination network unknown",
                    7 => "Destination host unknown",
                    8 => "Source host isolated",
                    9 => "Network administratively prohibited",
                    10 => "Host administratively prohibited",
                    11 => "Network unreachable for ToS",
                    12 => "Host unreachable for ToS",
                    13 => "Communication administratively prohibited",
                    14 => "Host precedence violation",
                    15 => "Precedence cutoff in effect",
                    _ => "",
                }
            }

            IcmpType::RedirectMessage => {
                match code {
                    0 => "Redirect Datagram for the Network",
                    1 => "Redirect Datagram for the Host",
                    2 => "Redirect Datagram for the ToS and Network",
                    3 => "Redirect Datagram for the ToS and Host",
                    _ => "",
                }
            },

            IcmpType::EchoRequest => {
                match code {
                    0 => "Echo request",
                    _ => "",
                }
            },
            
            IcmpType::RouterAdvertisement => {
                match code {
                    0 => "Router Advertisement",
                    _ => "",
                }
            },
            
            IcmpType::RouterSolicitation => {
                match code {
                    0 => "Router Solicitation",
                    _ => "",
                }
            },

            IcmpType::TimeExceeded => {
                match code {
                    0 => "TTL expired in transit",
                    1 => "Fragment reassembly time exceeded",
                    _ => "",
                }
            },

            IcmpType::BadIpHeader => {
                match code {
                    0 => "Pointer indicates the error",
                    1 => "Missing a required option",
                    2 => "Bad length",
                    _ => "",
                }
            },

            IcmpType::Timestamp => {
                match code {
                    0 => "Timestamp",
                    _ => "",
                }
            },

            IcmpType::TimestampReply => {
                match code {
                    0 => "Timestamp reply",
                    _ => "",
                }
            },

            IcmpType::Unimplemented(_) => "Unimplemented",
        }
    }
}

fn parse_ip_header_and_data(input: &[u8]) -> IResult<&[u8], (Ipv4Header, [u8; 8])> {
    let (input, header) = parse_ipv4_header(input)?;
    let (input, data) = bytes::complete::take(8u8)(input)?;
    // SAFETY: unwrapping here is safe because if we
    // can't take 8 bytes from the input above, we'll error
    // before reaching the return
    Ok((input, (header, data.try_into().unwrap())))
}

fn parse_redirect_data(input: &[u8]) -> IResult<&[u8], IcmpHeaderData> {
    let (input, ip_addr) = number::complete::be_u32(input)?;
    let (input, (ip_header, data)) = parse_ip_header_and_data(input)?;
    let data = IcmpHeaderData::Redirect {
        ip_addr: Ipv4Address(ip_addr),
        ip_header,
        data,
    };

    Ok((input, data))
}

fn parse_time_exceeded_data(input: &[u8]) -> IResult<&[u8], IcmpHeaderData> {
    let (input, (ip_header, data)) = parse_ip_header_and_data(input)?;
    let data = IcmpHeaderData::TimeExceeded { ip_header, data };
    Ok((input, data))
}

fn parse_timestamp_data(input: &[u8]) -> IResult<&[u8], (u16, u16, u32, u32, u32)> {
    let (input, id) = number::complete::be_u16(input)?;
    let (input, seq) = number::complete::be_u16(input)?;
    let (input, originate) = number::complete::be_u32(input)?;
    let (input, receive) = number::complete::be_u32(input)?;
    let (input, transmit) = number::complete::be_u32(input)?;
    Ok((input, (id, seq, originate, receive, transmit)))
}

fn parse_timestamp(input: &[u8]) -> IResult<&[u8], IcmpHeaderData> {
    let (input, (id, seq, originate, receive, transmit)) = parse_timestamp_data(input)?;
    let data = IcmpHeaderData::Timestamp { id, seq, originate, receive, transmit };
    Ok((input, data))
}

fn parse_timestamp_reply(input: &[u8]) -> IResult<&[u8], IcmpHeaderData> {
    let (input, (id, seq, originate, receive, transmit)) = parse_timestamp_data(input)?;
    let data = IcmpHeaderData::TimestampReply { id, seq, originate, receive, transmit };
    Ok((input, data))
}

fn parse_destination_unreachable(input: &[u8]) -> IResult<&[u8], IcmpHeaderData> {
    let (input, _) = number::complete::be_u16(input)?;
    let (input, next_hop_mtu) = number::complete::be_u16(input)?;
    let (input, (ip_header, data)) = parse_ip_header_and_data(input)?;
    let data = IcmpHeaderData::DestinationUnreachable { next_hop_mtu, ip_header, data };
    Ok((input, data))
}

fn parse_icmp_header_type_code_and_checksum(input: &[u8])
    -> IResult<&[u8], (IcmpType, u8, u16)> {
    let (input, icmp_type) = number::complete::be_u8(input)?;
    let (input, code) = number::complete::be_u8(input)?;
    let (input, checksum) = number::complete::be_u16(input)?;

    Ok((input, (IcmpType::from(icmp_type), code, checksum)))
} 

fn parse_icmp_header_data<'a>(input: &[u8], icmp_type: IcmpType) -> IResult<&[u8], Option<IcmpHeaderData>> {
    let (input, data) = match icmp_type {
        IcmpType::RedirectMessage => {
            let (input, data) = parse_redirect_data(input)?;
            (input, Some(data))
        },

        IcmpType::TimeExceeded => {
            let (input, data) = parse_time_exceeded_data(input)?;
            (input, Some(data))
        },

        IcmpType::Timestamp => {
            let (input, data) = parse_timestamp(input)?;
            (input, Some(data))
        },

        IcmpType::TimestampReply => {
            let (input, data) = parse_timestamp_reply(input)?;
            (input, Some(data))
        }

        IcmpType::DestinationUnreachable => {
            let (input, data) = parse_destination_unreachable(input)?;
            (input, Some(data))
        }

        _ => (input, None), 
    };

    Ok((input, data))
}

pub fn parse_icmp_packet(input: &[u8]) -> IResult<&[u8], IcmpPacket> {
    let (input, (icmp_type, code, checksum)) = parse_icmp_header_type_code_and_checksum(input)?;
    let (input, header_data) = parse_icmp_header_data(input, icmp_type)?;
    let header = IcmpHeader { icmp_type, code, checksum, data: header_data };
    let (input, data) = nom::combinator::rest(input)?;
    let packet = IcmpPacket {
        header,
        data: Vec::from(data),
    };
    Ok((input, packet))
}
