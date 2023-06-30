use tun_tap::{Iface, Mode};

use crate::ipv4::{Ipv4HeaderProtocol, Ipv4HeaderPrelude, Ipv4Header, Ipv4Packet, Ipv4HeaderFragmentationInfo};
use crate::icmp::{parse_icmp_packet, IcmpType, IcmpPacket, IcmpHeader};
use crate::util::Serialize;

mod util;
mod ipv4;
mod icmp;

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("unable to create TUN/TAP device");
    loop {
        let mut buf = [0u8; 128];
        let read = iface.recv(&mut buf).unwrap();
        eprintln!("read {read} bytes");
        // eprintln!("raw: {:?}", &buf[0..read]);

        // the TUN frames are as follows:
        // Flags: 2 bytes (usually 0x0000)
        // Protocol (layer 3): 2 bytes (0x0800 for IPv4)
        // Payload
        let protocol = &buf[2..4];
        let data = &buf[4..read];
        eprintln!("protocol: {:?}", protocol);

        if protocol != [0x08, 0x00] {
            eprintln!("Not an IPv4 packet, discarding");
            continue;
        }

        let (_, ip_packet) = ipv4::parse_ipv4_packet(data).unwrap();
        eprintln!("header: {:?}", ip_packet.header);

        if ip_packet.header.protocol != Ipv4HeaderProtocol::Icmp {
            eprintln!("Not an ICMP packet; discarding");
        }

        eprintln!("ICMP packet; trying to parse...");
        let (_, icmp_packet) = match parse_icmp_packet(&ip_packet.data) {
            Ok((offset, packet)) => (offset, packet),
            Err(_) => { eprintln!("Failed to parse packet"); continue; },
        };

        eprintln!("{:?}", icmp_packet);

        if icmp_packet.header.icmp_type == IcmpType::EchoRequest {

            let mut icmp_reply = IcmpPacket {
                header: IcmpHeader {
                    checksum: 0,
                    icmp_type: IcmpType::EchoReply,
                    code: 0,
                    data: None,
                },
                data: icmp_packet.data,
            };
            icmp_reply.update_checksum();
            let icmp_reply_bytes = icmp_reply.serialize();
            eprintln!("ICMP reply: {:?}", icmp_reply);

            // TODO: this is the perfect use case for the builder pattern...
            //       doing it manually is very ugly
            let mut ip_packet_reply = Ipv4Packet {
                header: Ipv4Header {
                    prelude: Ipv4HeaderPrelude {
                        version:4,
                        header_length: 5,
                        dscp: 0,
                        ecn: 0,
                    },
                    total_length: 20 + icmp_reply_bytes.len() as u16,
                    identification: 0,
                    frag_info: Ipv4HeaderFragmentationInfo { flags: 0, offset: 0 },
                    ttl: 255,
                    protocol: Ipv4HeaderProtocol::Icmp,
                    checksum: 0,
                    source: ip_packet.header.destination,
                    destination: ip_packet.header.source,
                    options: Vec::new(),
                },
                data: icmp_reply_bytes,
            };
            ip_packet_reply.update_checksum();

            // Insert the TUN "header" at the beginning (flags+protocol)
            let mut reply = vec![0x00, 0x00, 0x08, 0x00];
            reply.extend(ip_packet_reply.serialize());

            eprintln!("Sending echo reply: {:?}, {:?}", ip_packet_reply, icmp_reply);
            iface.send(&reply).unwrap();
        }
    }
}
