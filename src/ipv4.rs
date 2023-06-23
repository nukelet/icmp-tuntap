use std::fmt;
use std::cmp::max;

use nom::IResult;
use nom::bytes;
use nom::error::Error;
use nom::bits;
use nom::number;
use nom::sequence;


// https://en.wikipedia.org/wiki/Internet_Protocol_version_4

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Ipv4HeaderPrelude {
    version: u8,
    header_length: u8,
    dscp: u8,
    ecn: u8,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Ipv4HeaderFragmentationInfo {
    flags: u8,
    offset: u16,
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

pub struct Ipv4Address(u32);

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

#[derive(Debug)]
pub struct Ipv4Header {
    prelude: Ipv4HeaderPrelude,    
    total_length: u16,
    identification: u16,
    frag_info: Ipv4HeaderFragmentationInfo,
    ttl: u8,
    protocol: Ipv4HeaderProtocol,
    checksum: u16,
    source: Ipv4Address,
    destination: Ipv4Address,
    options: Vec<u8>,
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

