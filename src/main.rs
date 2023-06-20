use tun_tap::{Iface, Mode};

mod ipv4;

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("unable to create TUN/TAP device");
    loop {
        let mut buf = [0u8; 1024];
        let read = iface.recv(&mut buf).unwrap();
        eprintln!("read {read} bytes: {buf:?}");
        // the TUN frames are as follows:
        // Flags: 2 bytes
        // Protocol: 2 bytes (0x0800 for IPv4)
        // Data
        eprintln!("protocol: {:?}", &buf[2..4]);
        if buf[2..4] == [0x08, 0x00] {
            eprintln!("IPv4 packet");
            let (_, header) = ipv4::parse_ipv4_header(&buf[4..]).unwrap();
            eprintln!("header: {:?}", header);
        }
    }
}
