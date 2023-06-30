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
    let mut sum = 0;
    for bytes in data.chunks(2) {
        let high = bytes[0];

        // handle misaligned buffers
        let low: u8 = match bytes.get(1) {
            Some(&b) => b,
            None => 0x0,
        };

        let t = (high as u32) << 8 | low as u32;
        sum += t;
    }

    let carry = sum >> 16;
    sum &= 0x0000_FFFF;
    sum += carry;
    let carry = sum >> 16;
    sum &= 0x0000_FFFF;
    sum += carry;

    !(sum & 0xFFFF) as u16
}

