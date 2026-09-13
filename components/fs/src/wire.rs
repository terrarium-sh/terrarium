//! FUSE wire layout adapted from `containers/libkrun` (`src/devices/src/virtio/fs/fuse.rs`).

pub const HEADER: usize = 40;
pub const OUT_HEADER: usize = 16;
pub const INIT: u32 = 26;
pub const FORGET: u32 = 2;
pub const LOOKUP: u32 = 1;
pub const GETATTR: u32 = 3;
pub const SETATTR: u32 = 4;
pub const READLINK: u32 = 5;
pub const SYMLINK: u32 = 6;
pub const MKDIR: u32 = 9;
pub const UNLINK: u32 = 10;
pub const RMDIR: u32 = 11;
pub const RENAME: u32 = 12;
pub const LINK: u32 = 13;
pub const OPEN: u32 = 14;
pub const READ: u32 = 15;
pub const WRITE: u32 = 16;
pub const STATFS: u32 = 17;
pub const RELEASE: u32 = 18;
pub const FSYNC: u32 = 20;
pub const FLUSH: u32 = 25;
pub const OPENDIR: u32 = 27;
pub const READDIR: u32 = 28;
pub const RELEASEDIR: u32 = 29;
pub const FSYNCDIR: u32 = 30;
pub const CREATE: u32 = 35;
pub const FORGET_MULTI: u32 = 42;
pub const RENAME2: u32 = 45;
pub const INIT_OUT: usize = 64;
pub const ENOSYS: i32 = 38;
pub const EINVAL: i32 = 22;
pub const INIT_EXT: u32 = 1 << 30;

#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub opcode: u32,
    pub unique: u64,
    pub node: u64,
    pub body: &'a [u8],
}

fn u32_at(bytes: &[u8], start: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(start..start + 4)?.try_into().ok()?,
    ))
}
fn u64_at(bytes: &[u8], start: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(start..start + 8)?.try_into().ok()?,
    ))
}

pub fn request(bytes: &[u8]) -> Result<Request<'_>, i32> {
    if bytes.len() < HEADER {
        return Err(EINVAL);
    }
    let len = u32_at(bytes, 0).ok_or(EINVAL)?;
    let len = usize::try_from(len).map_err(|_| EINVAL)?;
    if len < HEADER || len > bytes.len() {
        return Err(EINVAL);
    }
    Ok(Request {
        opcode: u32_at(bytes, 4).ok_or(EINVAL)?,
        unique: u64_at(bytes, 8).ok_or(EINVAL)?,
        node: u64_at(bytes, 16).ok_or(EINVAL)?,
        body: &bytes[HEADER..len],
    })
}

#[must_use]
pub fn reply(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
    let len = OUT_HEADER.saturating_add(body.len());
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&(-error).to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
    out.extend_from_slice(body);
    out
}

pub fn init(body: &[u8]) -> Result<Vec<u8>, i32> {
    if body.len() < 16 {
        return Err(EINVAL);
    }
    let major = u32_at(body, 0).ok_or(EINVAL)?;
    if major != 7 {
        return Err(EINVAL);
    }
    let minor = u32_at(body, 4).ok_or(EINVAL)?;
    let flags = u32_at(body, 12).ok_or(EINVAL)?;
    let extended = flags & INIT_EXT != 0;
    let mut out = vec![0; INIT_OUT];
    out[0..4].copy_from_slice(&7_u32.to_le_bytes());
    out[4..8].copy_from_slice(&minor.min(40).to_le_bytes());
    out[8..12].copy_from_slice(&(64 * 1024_u32).to_le_bytes());
    out[12..16].copy_from_slice(&(if extended { INIT_EXT } else { 0 }).to_le_bytes());
    out[16..18].copy_from_slice(&64_u16.to_le_bytes());
    out[18..20].copy_from_slice(&48_u16.to_le_bytes());
    out[20..24].copy_from_slice(&(64 * 1024_u32).to_le_bytes());
    out[24..28].copy_from_slice(&1_u32.to_le_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_or_inconsistent_request() {
        assert_eq!(request(&[]), Err(EINVAL));
        let mut bytes = vec![0; HEADER];
        bytes[..4].copy_from_slice(&u32::try_from(HEADER + 1).unwrap().to_le_bytes());
        assert_eq!(request(&bytes), Err(EINVAL));
    }

    #[test]
    fn init_does_not_advertise_unsupported_idmap() {
        let mut body = vec![0; 20];
        body[..4].copy_from_slice(&7_u32.to_le_bytes());
        body[4..8].copy_from_slice(&40_u32.to_le_bytes());
        body[12..16].copy_from_slice(&(INIT_EXT | (1 << 10)).to_le_bytes());
        body[16..20].copy_from_slice(&(1_u32 << 8).to_le_bytes());
        let reply = init(&body).unwrap();
        assert_eq!(reply.len(), INIT_OUT);
        assert_eq!(u32_at(&reply, 12), Some(INIT_EXT));
        assert_eq!(u32_at(&reply, 32), Some(0));
        assert_eq!(u16::from_le_bytes(reply[16..18].try_into().unwrap()), 64);
        assert_eq!(u16::from_le_bytes(reply[18..20].try_into().unwrap()), 48);
        assert_eq!(u32_at(&reply, 20), Some(64 * 1024));
    }

    #[test]
    fn init_does_not_advertise_unrequested_locks() {
        let mut body = vec![0; 16];
        body[..4].copy_from_slice(&7_u32.to_le_bytes());
        body[4..8].copy_from_slice(&40_u32.to_le_bytes());
        let reply = init(&body).unwrap();
        assert_eq!(u32_at(&reply, 12), Some(0));
    }

    #[test]
    fn advertised_write_leaves_room_for_the_fuse_header() {
        let max_write = 64 * 1024_usize;
        assert!(HEADER + 40 + max_write < 128 * 1024);
    }

    #[test]
    fn error_reply_keeps_request_identity() {
        let reply = reply(17, ENOSYS, &[]);
        assert_eq!(u32_at(&reply, 0), Some(u32::try_from(OUT_HEADER).unwrap()));
        assert_eq!(i32::from_le_bytes(reply[4..8].try_into().unwrap()), -ENOSYS);
        assert_eq!(u64_at(&reply, 8), Some(17));
    }
}
