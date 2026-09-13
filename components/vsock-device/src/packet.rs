//! Virtio-vsock header encoding and validation.

pub const VSOCK_HEADER_BYTES: usize = 44;
const HDR_BYTES: usize = VSOCK_HEADER_BYTES;

/// One parsed header. Field order and widths are the kernel ABI;
/// offsets are pinned by test, not by a foreign struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockHeader {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub type_: u16,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    TooShort,
}

fn le<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap_or([0; N])
}

impl VsockHeader {
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), HeaderError> {
        if bytes.len() < HDR_BYTES {
            return Err(HeaderError::TooShort);
        }
        Ok((
            Self {
                src_cid: u64::from_le_bytes(le(bytes, 0)),
                dst_cid: u64::from_le_bytes(le(bytes, 8)),
                src_port: u32::from_le_bytes(le(bytes, 16)),
                dst_port: u32::from_le_bytes(le(bytes, 20)),
                len: u32::from_le_bytes(le(bytes, 24)),
                type_: u16::from_le_bytes(le(bytes, 28)),
                op: u16::from_le_bytes(le(bytes, 30)),
                flags: u32::from_le_bytes(le(bytes, 32)),
                buf_alloc: u32::from_le_bytes(le(bytes, 36)),
                fwd_cnt: u32::from_le_bytes(le(bytes, 40)),
            },
            &bytes[HDR_BYTES..],
        ))
    }

    #[must_use]
    pub fn encode(&self) -> [u8; HDR_BYTES] {
        let mut out = [0u8; HDR_BYTES];
        out[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        out[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        out[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        out[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        out[24..28].copy_from_slice(&self.len.to_le_bytes());
        out[28..30].copy_from_slice(&self.type_.to_le_bytes());
        out[30..32].copy_from_slice(&self.op.to_le_bytes());
        out[32..36].copy_from_slice(&self.flags.to_le_bytes());
        out[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        out[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::VsockHeader;

    #[test]
    fn header_uses_the_virtio_vsock_wire_layout() {
        let header = VsockHeader {
            src_cid: 0x0807_0605_0403_0201,
            dst_cid: 0x1817_1615_1413_1211,
            src_port: 0x2423_2221,
            dst_port: 0x3433_3231,
            len: 0x4443_4241,
            type_: 0x5251,
            op: 0x6261,
            flags: 0x7473_7271,
            buf_alloc: 0x8483_8281,
            fwd_cnt: 0x9493_9291,
        };
        assert_eq!(
            header.encode(),
            [
                1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24, 33, 34, 35, 36, 49, 50, 51,
                52, 65, 66, 67, 68, 81, 82, 97, 98, 113, 114, 115, 116, 129, 130, 131, 132, 145,
                146, 147, 148,
            ]
        );
    }
}
