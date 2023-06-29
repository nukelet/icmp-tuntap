// crude attempt at implementing serialization capabilities
// since using Serde would be too much work
pub trait Serialize {
    fn serialize(&self) -> Vec<u8>;
}

impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> {
        self.clone()
    }
}

pub fn checksum_16(data: &[u8]) -> u16 {
    eprintln!("calculating checksum for {:?}", data);
    let mut sum = 0;
    for bytes in data.chunks(2) {
        let t = (bytes[0] as u32) << 8 | bytes[1] as u32;
        eprintln!("{:#04x}, {:#04x} -> {:#010x}", bytes[0], bytes[1], t);
        sum += t;
    }

    eprintln!("total checksum: {:#010x}", sum);
    let carry = sum >> 16;
    sum &= 0x0000_FFFF;
    eprintln!("carry 1: {carry:#010x}");
    sum += carry;
    let carry = sum >> 16;
    sum &= 0x0000_FFFF;
    eprintln!("carry 2: {carry:#010x}");
    sum += carry;

    !(sum & 0xFFFF) as u16
}

