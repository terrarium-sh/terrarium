//! FUSE wire layout adapted from `containers/libkrun` (`src/devices/src/virtio/fs/fuse.rs`).

pub const HEADER: usize = 40;
pub const OUT_HEADER: usize = 16;
pub const INIT: u32 = 26;
pub const RECEIVE_EVENT: u32 = 4096;
pub const CANCEL_EVENTS: u32 = 4097;
pub const EVENT_SAME_INODE: u32 = 0x200;
pub const FILE_EVENTS: u32 = 1 << 31;
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
pub const SETXATTR: u32 = 21;
pub const REMOVEXATTR: u32 = 24;
pub const FLUSH: u32 = 25;
pub const OPENDIR: u32 = 27;
pub const READDIR: u32 = 28;
pub const RELEASEDIR: u32 = 29;
pub const FSYNCDIR: u32 = 30;
pub const GETLK: u32 = 31;
pub const SETLKW: u32 = 33;
pub const CREATE: u32 = 35;
pub const FORGET_MULTI: u32 = 42;
pub const FALLOCATE: u32 = 43;
pub const RENAME2: u32 = 45;
pub const LSEEK: u32 = 46;
pub const SYNCFS: u32 = 50;
pub const INIT_OUT: usize = 64;
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const ETXTBSY: i32 = 26;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const EPIPE: i32 = 32;
pub const EDEADLK: i32 = 35;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOLCK: i32 = 37;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const EOVERFLOW: i32 = 75;
pub const EILSEQ: i32 = 84;
pub const EMSGSIZE: i32 = 90;
pub const EOPNOTSUPP: i32 = 95;
pub const EALREADY: i32 = 114;
pub const EINPROGRESS: i32 = 115;
pub const EDQUOT: i32 = 122;
pub const ENOTRECOVERABLE: i32 = 131;
pub const INIT_EXT: u32 = 1 << 30;
const BIG_WRITES: u32 = 1 << 5;

#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub opcode: u32,
    pub unique: u64,
    pub node: u64,
    pub body: &'a [u8],
}

pub(crate) fn u32_at(bytes: &[u8], start: usize) -> Result<u32, i32> {
    bytes
        .get(start..start + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(EINVAL)
}

pub(crate) fn u64_at(bytes: &[u8], start: usize) -> Result<u64, i32> {
    bytes
        .get(start..start + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(EINVAL)
}

pub fn request(bytes: &[u8]) -> Result<Request<'_>, i32> {
    if bytes.len() < HEADER {
        return Err(EINVAL);
    }
    let len = u32_at(bytes, 0)?;
    let len = usize::try_from(len).map_err(|_| EINVAL)?;
    if len < HEADER || len > bytes.len() {
        return Err(EINVAL);
    }
    Ok(Request {
        opcode: u32_at(bytes, 4)?,
        unique: u64_at(bytes, 8)?,
        node: u64_at(bytes, 16)?,
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
    let major = u32_at(body, 0)?;
    if major != 7 {
        return Err(EINVAL);
    }
    let minor = u32_at(body, 4)?;
    let flags = u32_at(body, 12)?;
    let extended = flags & INIT_EXT != 0;
    let mut out = vec![0; INIT_OUT];
    out[0..4].copy_from_slice(&7_u32.to_le_bytes());
    out[4..8].copy_from_slice(&minor.min(40).to_le_bytes());
    out[8..12].copy_from_slice(&(64 * 1024_u32).to_le_bytes());
    out[12..16].copy_from_slice(&(flags & (INIT_EXT | BIG_WRITES)).to_le_bytes());
    out[16..18].copy_from_slice(&64_u16.to_le_bytes());
    out[18..20].copy_from_slice(&48_u16.to_le_bytes());
    out[20..24].copy_from_slice(&(64 * 1024_u32).to_le_bytes());
    out[24..28].copy_from_slice(&1_u32.to_le_bytes());
    if extended {
        out[32..36].copy_from_slice(&(u32_at(body, 16).unwrap_or(0) & FILE_EVENTS).to_le_bytes());
    }
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
    fn big_writes_require_negotiation_and_keep_the_write_limit() {
        let mut body = vec![0; 16];
        body[..4].copy_from_slice(&7_u32.to_le_bytes());
        body[4..8].copy_from_slice(&40_u32.to_le_bytes());
        for flags in [0, BIG_WRITES, INIT_EXT, INIT_EXT | BIG_WRITES] {
            body[12..16].copy_from_slice(&flags.to_le_bytes());
            let reply = init(&body).unwrap();
            assert_eq!(u32_at(&reply, 12), Ok(flags));
            assert_eq!(u32_at(&reply, 20), Ok(64 * 1024));
        }
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
        assert_eq!(u32_at(&reply, 12), Ok(INIT_EXT));
        assert_eq!(u32_at(&reply, 32), Ok(0));
        assert_eq!(u16::from_le_bytes(reply[16..18].try_into().unwrap()), 64);
        assert_eq!(u16::from_le_bytes(reply[18..20].try_into().unwrap()), 48);
        assert_eq!(u32_at(&reply, 20), Ok(64 * 1024));
    }

    #[test]
    fn events_require_explicit_extended_negotiation() {
        let mut body = vec![0; 20];
        body[..4].copy_from_slice(&7_u32.to_le_bytes());
        body[4..8].copy_from_slice(&40_u32.to_le_bytes());
        body[16..20].copy_from_slice(&FILE_EVENTS.to_le_bytes());
        assert_eq!(u32_at(&init(&body).unwrap(), 32), Ok(0));
        body[12..16].copy_from_slice(&INIT_EXT.to_le_bytes());
        assert_eq!(u32_at(&init(&body).unwrap(), 32), Ok(FILE_EVENTS));
        assert_eq!(u32_at(&init(&body[..16]).unwrap(), 32), Ok(0));
    }

    #[test]
    fn init_does_not_advertise_unrequested_locks() {
        let mut body = vec![0; 16];
        body[..4].copy_from_slice(&7_u32.to_le_bytes());
        body[4..8].copy_from_slice(&40_u32.to_le_bytes());
        let reply = init(&body).unwrap();
        assert_eq!(u32_at(&reply, 12), Ok(0));
    }

    #[test]
    fn advertised_write_leaves_room_for_the_fuse_header() {
        let max_write = 64 * 1024_usize;
        assert!(HEADER + 40 + max_write < 128 * 1024);
    }

    #[test]
    fn error_reply_keeps_request_identity() {
        let reply = reply(17, ENOSYS, &[]);
        assert_eq!(u32_at(&reply, 0), Ok(u32::try_from(OUT_HEADER).unwrap()));
        assert_eq!(i32::from_le_bytes(reply[4..8].try_into().unwrap()), -ENOSYS);
        assert_eq!(u64_at(&reply, 8), Ok(17));
    }
}
