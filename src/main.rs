use tun_tap::{Iface, Mode};

use crate::{ipv4::Ipv4HeaderProtocol, icmp::{parse_icmp_packet, IcmpType, IcmpPacket, IcmpHeader}};

mod util;
mod ipv4;
mod icmp;

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("unable to create TUN/TAP device");
    loop {
        let mut buf = [0u8; 128];
        let read = iface.recv(&mut buf).unwrap();
        eprintln!("read {read} bytes");
        eprintln!("raw: {:?}", &buf[0..read]);
        // the TUN frames are as follows:
        // Flags: 2 bytes
        // Protocol: 2 bytes (0x0800 for IPv4)
        // Data
        eprintln!("protocol: {:?}", &buf[2..4]);
        if buf[2..4] == [0x08, 0x00] {
            eprintln!("IPv4 packet");
            let (offset, header) = ipv4::parse_ipv4_header(&buf[4..]).unwrap();
            eprintln!("header: {:?}", header);
            if header.protocol == Ipv4HeaderProtocol::Icmp {
                eprintln!("ICMP packet; trying to parse...");
                let payload_len: usize =
                    (header.total_length - header.prelude.header_length as u16 * 5) as usize;
                let payload = &offset[0..payload_len];
                eprintln!("raw ICMP packet (offset={payload_len}): {:?}", payload);
                let (offset, packet) = match parse_icmp_packet(payload) {
                    Ok((offset, packet)) => (offset, packet),
                    Err(_) => { eprintln!("Failed to parse packet"); continue; },
                };

                eprintln!("{:?}", packet);
                eprintln!("remaining: {:?}", offset);
            }
        }
    }
}
