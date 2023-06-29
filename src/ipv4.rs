use std::fmt;
use std::cmp::max;

use nom::IResult;
use nom::bytes;
use nom::error::Error;
use nom::bits;
use nom::number;
use nom::sequence;

use crate::util::Serialize;
use crate::util::checksum_16;

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub struct Ipv4HeaderPrelude {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
}

impl Serialize for Ipv4HeaderPrelude {
    fn serialize(&self) -> Vec<u8> {
        let version_ihl = (self.version << 4) | self.header_length;
        let dscp_ecn = (self.dscp << 2) | self.ecn;
        vec![version_ihl, dscp_ecn]
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub struct Ipv4HeaderFragmentationInfo {
    pub flags: u8,
    pub offset: u16,
}

impl Serialize for Ipv4HeaderFragmentationInfo {
    fn serialize(&self) -> Vec<u8> {
        let flags_offset = ((self.flags as u16) << 13) | self.offset;
        return Vec::from(flags_offset.to_be_bytes())
    }
}

// There are several others, but these are the most common
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Ipv4HeaderProtocol {
    Icmp = 1u8,
    Igmp = 2u8,
    Tcp = 6u8,
    Udp = 17u8,
    Encap = 41u8,
    Ospf = 89u8,
    Sctp = 132u8,
    Unknown,
}

impl Ipv4HeaderProtocol {
    fn from_u8(protocol: u8) -> Ipv4HeaderProtocol {
        match protocol {
            1u8 => Ipv4HeaderProtocol::Icmp,
            2u8 => Ipv4HeaderProtocol::Igmp,
            6u8 => Ipv4HeaderProtocol::Tcp,
            17u8 => Ipv4HeaderProtocol::Udp,
            41u8 => Ipv4HeaderProtocol::Encap,
            89u8 => Ipv4HeaderProtocol::Ospf,
            132u8 => Ipv4HeaderProtocol::Sctp,
            _ => Ipv4HeaderProtocol::Unknown,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Copy)]
pub struct Ipv4Address(pub u32);

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_be_bytes();
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_be_bytes();
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Ipv4Header {
    pub prelude: Ipv4HeaderPrelude,    
    pub total_length: u16,
    pub identification: u16,
    pub frag_info: Ipv4HeaderFragmentationInfo,
    pub ttl: u8,
    pub protocol: Ipv4HeaderProtocol,
    pub checksum: u16,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub options: Vec<u8>,
}

fn parse_version_and_header_length(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
    // basically consume two nibbles from the first byte
    bits::bits::<_, _, Error<_>, _, _>(sequence::pair(
        bits::streaming::take(4u8),
        bits::streaming::take(4u8),
    ))(input)
}

fn parse_flags_and_fragment_offset(input: &[u8])
    -> IResult<&[u8], (u8, u16)> {
    // the flags field is 3 bits long, the fragment offset is 13 bits long
    bits::bits::<_, _, Error<_>, _, _>(sequence::pair(
        bits::streaming::take(3u8),
        bits::streaming::take(13u16),
    ))(input)
}

fn parse_header_fragmentation_info(input: &[u8])
    -> IResult<&[u8], Ipv4HeaderFragmentationInfo> {
    let (input, (flags, offset)) = parse_flags_and_fragment_offset(input)?;
    Ok((input, 
        Ipv4HeaderFragmentationInfo {
            flags,
            offset,
    }))
}

fn parse_dscp_and_ecn(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
    // dscp is 6 bits long, ecn is 2 bits long
    bits::bits::<_, _, Error<_>, _, _>(sequence::pair(
        bits::streaming::take(6u8),
        bits::streaming::take(2u8),
    ))(input)
}

fn parse_header_prelude(input: &[u8]) -> IResult<&[u8], Ipv4HeaderPrelude> {
    let (input, (version, header_length)) = parse_version_and_header_length(input)?;
    let (input, (dscp, ecn)) = parse_dscp_and_ecn(input)?;
    Ok((input,
        Ipv4HeaderPrelude {
        version,
        header_length,
        dscp,
        ecn
    }))
}

pub fn parse_ipv4_header(input: &[u8]) -> IResult<&[u8], Ipv4Header> {
    let (input, prelude) = parse_header_prelude(input)?;
    // big endian fields
    let (input, total_length) = number::streaming::be_u16(input)?;
    let (input, identification) = number::streaming::be_u16(input)?;
    let (input, frag_info) = parse_header_fragmentation_info(input)?;
    let (input, ttl) = number::streaming::be_u8(input)?;
    let (input, protocol) = number::streaming::be_u8(input)?;
    let (input, checksum) = number::streaming::be_u16(input)?;
    let (input, source) = number::streaming::be_u32(input)?;
    let (input, destination) = number::streaming::be_u32(input)?;

    // options field is not empty
    let options_bytecount = max(0, (prelude.header_length - 5) * 4);
    let (input, options) = bytes::streaming::take(options_bytecount)(input)?;

    // TODO: we purposefully ignore the options field for now
    Ok((input, Ipv4Header {
        prelude,
        total_length,
        identification,
        frag_info,
        ttl,
        protocol: Ipv4HeaderProtocol::from_u8(protocol),
        checksum,
        source: Ipv4Address(source),
        destination: Ipv4Address(destination),
        options: Vec::from(options),
    }))
}

impl Serialize for Ipv4Header {
    fn serialize(&self) -> Vec<u8> {
        let mut s: Vec<u8> = Vec::new();

        let version_ihl = self.prelude.serialize();
        let frag_info = self.frag_info.serialize();

        s.extend(version_ihl);
        s.extend(self.total_length.to_be_bytes());
        s.extend(self.identification.to_be_bytes());
        s.extend(frag_info);
        s.push(self.ttl);
        s.push(self.protocol as u8);
        s.extend(self.checksum.to_be_bytes());
        s.extend(self.source.0.to_be_bytes());
        s.extend(self.destination.0.to_be_bytes());
        s.extend(&self.options);

        s
    }
}

#[test]
fn test_ip_header_serialization() {
    let raw = [
        69,                 // Version number and IHL
        0,                  // DSCP, ECN
        0, 102,             // Total length
        133, 153,           // Identification
        0, 0,               // Flags, Fragment Offset
        255,                // TTL
        17,                 // Protocol
        74, 242,            // Header checksum
        10, 0, 0, 0,        // Source IP
        224, 0, 0, 251      // Destination IP
    ];

    let (_, header) = parse_ipv4_header(&raw).unwrap();
    assert_eq!(raw, header.serialize().as_slice());
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub data: Vec<u8>,
}

pub fn parse_ipv4_packet(input: &[u8]) -> IResult<&[u8], Ipv4Packet>
{
    let (rest, header) = parse_ipv4_header(input)?;
    let packet = Ipv4Packet {
        header,
        data: Vec::from(rest),
    };

    Ok((&[], packet))
}

#[allow(dead_code)]
impl Ipv4Packet {
    pub fn update_checksum(&mut self) {
        self.header.checksum = 0;
        let raw_data: Vec<u8> = self.header.serialize().to_vec();
        self.header.checksum = checksum_16(&raw_data);
    }
}

#[test]
fn test_ipv4_packet_checksum() {
    // random ICMP packet from a linux ping
    let bytes = [
        8, 0, 69, 0, 0, 84, 98, 13, 64, 0, 64, 1, 196, 155, 10, 0, 0, 0, 10, 0, 0, 1, 8, 0, 96, 221, 0, 4, 0, 2, 214, 16, 157, 100, 0, 0, 0, 0, 86, 212, 14, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55
    ];

    let (_, mut packet) = parse_ipv4_packet(&bytes).unwrap();
    let checksum = packet.header.checksum;
    packet.update_checksum();
    let sum = checksum as u32 + packet.header.checksum as u32;
    eprintln!("original: {:#06x}, calculated: {:#06x}, sum: {:#010x}", checksum, packet.header.checksum, sum);
    assert_eq!(checksum, packet.header.checksum);
}
