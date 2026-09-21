use crate::component::block::backing::{DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, Descriptor};
use crate::memory::{BoundedMemory, GuestRam};

#[test]
fn descriptor_flags_match_bindings() {
    use virtio_bindings::bindings::virtio_ring::{
        VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
    };
    assert_eq!(u32::from(DESC_F_NEXT), VRING_DESC_F_NEXT);
    assert_eq!(u32::from(DESC_F_WRITE), VRING_DESC_F_WRITE);
    assert_eq!(u32::from(DESC_F_INDIRECT), VRING_DESC_F_INDIRECT);
}

use crate::component::block::backing::{
    BlkError, BlockDevice, ID_BYTES, SECTOR_BYTES, STATUS_FAILED, STATUS_IOERR, STATUS_OK,
    STATUS_UNSUPP, StatusError, device_features, drive_status, negotiate,
};
use virtio_bindings::bindings::{
    virtio_blk as blk, virtio_config as transport, virtio_ring as ring,
};

const BLK_HDR: u64 = 0x1000;
const BLK_DATA: u64 = 0x2000;
const BLK_STATUS: u64 = 0x3000;

fn blk_ram() -> GuestRam {
    GuestRam::new(256 * 1024).expect("256 KiB RAM")
}

fn write_blk_hdr(mem: &BoundedMemory, request_type: u32, sector: u64) {
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&request_type.to_le_bytes());
    hdr[8..16].copy_from_slice(&sector.to_le_bytes());
    mem.write(BLK_HDR, &hdr).expect("header fits");
}

fn out_chain_1sector() -> Vec<Descriptor> {
    vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ]
}

fn in_chain_1sector() -> Vec<Descriptor> {
    vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::writable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ]
}

fn status_byte(mem: &BoundedMemory) -> u8 {
    mem.read(BLK_STATUS, 1).expect("status readable")[0]
}

#[test]
fn block_constants_match_bindings() {
    assert_eq!(u32::from(STATUS_OK), blk::VIRTIO_BLK_S_OK);
    assert_eq!(u32::from(STATUS_IOERR), blk::VIRTIO_BLK_S_IOERR);
    assert_eq!(u32::from(STATUS_UNSUPP), blk::VIRTIO_BLK_S_UNSUPP);
    assert_eq!(
        u32::try_from(ID_BYTES).expect("fits"),
        blk::VIRTIO_BLK_ID_BYTES
    );
    assert_eq!(SECTOR_BYTES, 512);
    assert_eq!(
        STATUS_FAILED,
        u8::try_from(transport::VIRTIO_CONFIG_S_FAILED).expect("fits")
    );
    assert_ne!(
        device_features(false) & (1u64 << blk::VIRTIO_BLK_F_FLUSH),
        0
    );
    assert_eq!(device_features(false) & (1u64 << blk::VIRTIO_BLK_F_RO), 0);
    assert_ne!(device_features(true) & (1u64 << blk::VIRTIO_BLK_F_RO), 0);
}

#[test]
fn block_features_mask_to_implemented() {
    let rw = negotiate(u64::MAX, false);
    assert_eq!(rw, device_features(false));
    assert_eq!(rw & (1u64 << blk::VIRTIO_BLK_F_DISCARD), 0);
    assert_eq!(rw & (1u64 << blk::VIRTIO_BLK_F_WRITE_ZEROES), 0);
    assert_eq!(rw & (1u64 << blk::VIRTIO_BLK_F_MQ), 0);
    assert_eq!(rw & (1u64 << ring::VIRTIO_RING_F_INDIRECT_DESC), 0);
    assert_eq!(rw & (1u64 << ring::VIRTIO_RING_F_EVENT_IDX), 0);
    assert_ne!(rw & (1u64 << transport::VIRTIO_F_VERSION_1), 0);
    assert_ne!(
        negotiate(u64::MAX, true) & (1u64 << blk::VIRTIO_BLK_F_RO),
        0
    );
    assert_eq!(negotiate(0, false), 0);
}

#[test]
fn block_status_sequence_and_reset() {
    assert_eq!(drive_status(0, 1), Ok(1));
    assert_eq!(drive_status(0, 2), Err(StatusError::BadSequence));
    assert_eq!(drive_status(1, 3), Ok(3));
    assert_eq!(drive_status(3, 3), Ok(3));
    assert_eq!(drive_status(3, 15), Err(StatusError::BadSequence));
    assert_eq!(drive_status(3, 11), Ok(11));
    assert_eq!(drive_status(11, 15), Ok(15));
    assert_eq!(drive_status(15, 0), Ok(0));
    assert_eq!(drive_status(0, 0), Ok(0));
    assert_eq!(drive_status(1, 1 | 64), Err(StatusError::BadSequence));
    assert_eq!(drive_status(1, 1 | 128), Ok(1 | 128));
    assert_eq!(drive_status(1 | 128, 3), Err(StatusError::BadSequence));
    assert_eq!(drive_status(1 | 128, 1 | 128), Ok(1 | 128));
    assert_eq!(drive_status(1 | 128, 0), Ok(0));
    assert_eq!(drive_status(1, 2), Err(StatusError::BadSequence));
}

#[test]
fn block_read_write_round_trip() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 3);
    let written = dev
        .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
        .expect("write completes");
    assert_eq!(written.status, STATUS_OK);
    assert_eq!(written.used_len, 1);
    assert_eq!(status_byte(&mem), STATUS_OK);
    mem.write(BLK_DATA, &[0u8; 512]).expect("clear buffer");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 3);
    let read = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("read completes");
    assert_eq!(read.status, STATUS_OK);
    assert_eq!(read.used_len, 512 + 1);
    assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0xABu8; 512]);
}

#[test]
fn block_readonly_rejects_writes() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, true, b"terra-vda");
    mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let written = dev
        .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
        .expect("well-formed request still completes");
    assert_eq!(written.status, STATUS_IOERR);
    assert_eq!(status_byte(&mem), STATUS_IOERR);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
    dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("read completes");
    assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0u8; 512]);
}

#[test]
fn block_oob_and_overflow_are_ioerr_not_panic() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 8);
    let past_end = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("completes with error status");
    assert_eq!(past_end.status, STATUS_IOERR);
    assert_eq!(status_byte(&mem), STATUS_IOERR);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, u64::MAX);
    let overflow = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("sector overflow completes");
    assert_eq!(overflow.status, STATUS_IOERR);
}

#[test]
fn block_unsupported_types_get_unsupp() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    mem.write(BLK_DATA, &[0x5Au8; 512]).expect("pattern fits");
    for request_type in [
        blk::VIRTIO_BLK_T_SCSI_CMD,
        blk::VIRTIO_BLK_T_DISCARD,
        blk::VIRTIO_BLK_T_WRITE_ZEROES,
        0xFFFF,
    ] {
        write_blk_hdr(&mem, request_type, 0);
        let completion = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("unsupported still completes");
        assert_eq!(completion.status, STATUS_UNSUPP);
        assert_eq!(status_byte(&mem), STATUS_UNSUPP);
    }
    assert_eq!(mem.read(BLK_DATA, 512).expect("untouched"), [0x5Au8; 512]);
}

#[test]
fn block_flush_and_identify() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda-01");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
    let bare = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    let flushed = dev
        .execute(&mem, &bare, 0, ram.size(), 0)
        .expect("flush completes");
    assert_eq!(flushed.status, STATUS_OK);
    assert_eq!(flushed.used_len, 1);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
    assert_eq!(
        dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_GET_ID, 0);
    let identified = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("identify completes");
    assert_eq!(identified.status, STATUS_OK);
    assert_eq!(
        identified.used_len,
        u32::try_from(ID_BYTES).expect("id length fits") + 1
    );
    let mut expected = [0u8; 512];
    expected[..12].copy_from_slice(b"terra-vda-01");
    assert_eq!(mem.read(BLK_DATA, 512).expect("id back"), expected);
}

#[test]
fn block_malformed_chains_write_no_completion() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let short_hdr = vec![
        Descriptor::readable(BLK_HDR, 15, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    assert_eq!(
        dev.execute(&mem, &short_hdr, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    let no_status = vec![Descriptor::readable(BLK_HDR, 16, None)];
    assert_eq!(
        dev.execute(&mem, &no_status, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    let mixed = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_DATA + 512, 512, Some(3)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    assert_eq!(
        dev.execute(&mem, &mixed, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    let wrong_dir = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
    assert_eq!(
        dev.execute(&mem, &wrong_dir, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    assert_eq!(status_byte(&mem), 0);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let ragged = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 100, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    let partial = dev
        .execute(&mem, &ragged, 0, ram.size(), 0)
        .expect("ragged length still completes");
    assert_eq!(partial.status, STATUS_IOERR);
    assert_eq!(status_byte(&mem), STATUS_IOERR);
}

#[test]
fn block_oversized_transfers_rejected() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let mut flood = vec![Descriptor::readable(BLK_HDR, 16, Some(1))];
    for i in 0..5u16 {
        flood.push(Descriptor::readable(
            BLK_DATA + u64::from(i) * 0x4000,
            16 * 1024,
            Some(2 + i),
        ));
    }
    flood.push(Descriptor::writable(BLK_STATUS, 1, None));
    assert_eq!(
        dev.execute(&mem, &flood, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let wide = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 32 * 1024, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    assert_eq!(
        dev.execute(&mem, &wide, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
}

#[test]
fn block_reset_fences_stale_completions() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
        .expect("write completes");
    dev.reset();
    assert_eq!(dev.epoch(), 1);
    mem.write(BLK_STATUS, &[0u8; 1]).expect("clear status");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 1);
    mem.write(BLK_DATA, &[0xCDu8; 512])
        .expect("new payload fits");
    assert_eq!(
        dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 0),
        Err(BlkError::Stale)
    );
    assert_eq!(status_byte(&mem), 0);
    dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 1)
        .expect("current epoch works");
    assert_eq!(status_byte(&mem), STATUS_OK);
    mem.write(BLK_DATA, &[0u8; 512]).expect("clear buffer");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
    dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 1)
        .expect("read completes");
    assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0xABu8; 512]);
}

mod file_backend {
    use super::{
        BLK_DATA, BLK_HDR, BLK_STATUS, blk_ram, in_chain_1sector, out_chain_1sector, status_byte,
        write_blk_hdr,
    };

    use super::BoundedMemory;
    use super::blk;
    use crate::component::block::backing::{
        BackingError, BlockBacking, BlockDevice, FileDisk, STATUS_IOERR, STATUS_OK,
    };
    use std::io::Write as _;

    fn backing_file(sectors: u64) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.as_file_mut()
            .set_len(sectors * 512)
            .expect("pre-grown");
        file.as_file_mut().write_all(&[0u8; 512]).expect("zeroed");
        file
    }

    fn file_device(path: &std::path::Path, readonly: bool) -> BlockDevice<FileDisk> {
        BlockDevice::with_backing(
            FileDisk::open(path, readonly).expect("disk opens"),
            b"terra-vda",
        )
    }

    #[test]
    fn file_round_trip_persists_across_reopen() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let file = backing_file(8);
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 3);
        {
            let mut dev = file_device(file.path(), false);
            let written = dev
                .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
                .expect("write completes");
            assert_eq!(written.status, STATUS_OK);
            assert_eq!(status_byte(&mem), STATUS_OK);
            write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
            let bare = vec![
                super::Descriptor::readable(BLK_HDR, 16, Some(1)),
                super::Descriptor::writable(BLK_STATUS, 1, None),
            ];
            dev.execute(&mem, &bare, 0, ram.size(), 0)
                .expect("flush completes");
        }
        let mut dev = file_device(file.path(), false);
        mem.write(BLK_DATA, &[0u8; 512]).expect("clear buffer");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 3);
        dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
            .expect("read completes");
        assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0xABu8; 512]);
    }

    #[test]
    fn file_capacity_is_fixed_at_open() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let file = backing_file(4);
        let mut dev = file_device(file.path(), false);
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 4);
        let past_end = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("completes with error status");
        assert_eq!(past_end.status, STATUS_IOERR);
        assert_eq!(
            std::fs::metadata(file.path()).expect("stat").len(),
            4 * 512,
            "rejected writes never extend the image"
        );
    }

    #[test]
    fn file_readonly_resists_writes() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let file = backing_file(4);
        let mut dev = file_device(file.path(), true);
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
        let written = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("well-formed request still completes");
        assert_eq!(written.status, STATUS_IOERR);
        let raw = std::fs::read(file.path()).expect("image readable");
        assert_eq!(&raw[..512], &[0u8; 512]);
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
        dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
            .expect("read completes");
    }

    struct FailDisk;

    impl BlockBacking for FailDisk {
        fn capacity(&self) -> u64 {
            8 * 512
        }

        fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
            buf.fill(0);
            Ok(())
        }

        fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<(), BackingError> {
            Err(BackingError::Io)
        }

        fn discard(&mut self, _offset: u64, _len: u64) -> Result<(), BackingError> {
            Err(BackingError::Io)
        }

        fn sync(&self) -> Result<(), BackingError> {
            Err(BackingError::Io)
        }
    }

    #[test]
    fn host_io_errors_complete_as_ioerr() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let mut dev = BlockDevice::with_backing(FailDisk, b"terra-vda");
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
        let written = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("completes with error status");
        assert_eq!(written.status, STATUS_IOERR);
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
        let bare = vec![
            super::Descriptor::readable(BLK_HDR, 16, Some(1)),
            super::Descriptor::writable(BLK_STATUS, 1, None),
        ];
        let flushed = dev
            .execute(&mem, &bare, 0, ram.size(), 0)
            .expect("flush completes");
        assert_eq!(flushed.status, STATUS_IOERR);
    }
}

/// Differential oracle against `virtio-blk::Request::parse` at pinned
/// rev `87bf424`. Same hostile corpus through both parsers: `Accept`
/// demands identical fields, `RejectBoth` demands two rejections, and
/// `TerraStricter` marks our policy bounds beyond the spec MUSTs
/// (chain/byte caps, no indirect, uniform direction, exact framing).
/// There is deliberately no fourth arm: anything upstream rejects
/// that we accept is a bug in our walk, and fails loudly.
#[cfg(all(test, unix))]
mod blk_oracle {
    use crate::component::block::backing::ParsedRequest;
    use virtio_blk::request::{Request, RequestType};

    const RAM: u64 = 128 * 1024;
    const HDR: u64 = 0x4000;
    const STATUS: u64 = 0x8000;
    const RD: u16 = 0;
    const WR: u16 = 2;
    const NEXT: u16 = 1;
    const INDIRECT: u16 = 4;

    const T_IN: u32 = 0;
    const T_OUT: u32 = 1;
    const T_FLUSH: u32 = 4;
    const T_GET_ID: u32 = 8;

    enum Expect {
        Accept,
        RejectBoth,
        TerraStricter,
    }

    struct Case {
        descs: Vec<(u64, u32, u16, u16)>,
        req_type: u32,
        sector: u64,
        expect: Expect,
    }

    fn out_data(n: usize) -> Vec<(u64, u32, u16, u16)> {
        let mut descs = vec![(HDR, 16, RD | NEXT, 1)];
        for i in 0..n {
            descs.push((0x5000 + i as u64 * 0x4000, 512, RD | NEXT, 0));
        }
        descs.push((STATUS, 1, WR, 0));
        for i in 0..descs.len() - 1 {
            descs[i].3 = u16::try_from(i + 1).expect("short chain");
        }
        descs
    }

    fn upstream_type(request_type: RequestType) -> u32 {
        match request_type {
            RequestType::In => T_IN,
            RequestType::Out => T_OUT,
            RequestType::Flush => T_FLUSH,
            RequestType::GetDeviceID => T_GET_ID,
            RequestType::Discard => 11,
            RequestType::WriteZeroes => 13,
            RequestType::Unsupported(t) => t,
        }
    }

    fn corpus() -> Vec<Case> {
        let mut cases = accept_cases();
        cases.extend(reject_cases());
        cases.extend(stricter_cases());
        cases
    }

    fn accept_cases() -> Vec<Case> {
        vec![
            Case {
                descs: out_data(1),
                req_type: T_OUT,
                sector: 3,
                expect: Expect::Accept,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, WR | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_IN,
                sector: 9,
                expect: Expect::Accept,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (STATUS, 1, WR, 0)],
                req_type: T_FLUSH,
                sector: 0,
                expect: Expect::Accept,
            },
            Case {
                descs: out_data(1),
                req_type: 2,
                sector: 0,
                expect: Expect::Accept,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, WR | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_GET_ID,
                sector: 0,
                expect: Expect::Accept,
            },
        ]
    }

    fn reject_cases() -> Vec<Case> {
        vec![
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (STATUS, 1, WR, 0)],
                req_type: T_FLUSH,
                sector: 7,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, WR | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 1, RD, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 0, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (0x5000, 512, RD | NEXT, 0)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (0xFFFF_FFFF, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 99)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![(HDR, 16, RD, 0)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
        ]
    }

    fn stricter_cases() -> Vec<Case> {
        let mut wide = out_data(5);
        for desc in wide.iter_mut().skip(1).take(5) {
            desc.1 = 16 * 1024;
        }
        let mut long = vec![(HDR, 16, RD | NEXT, 1)];
        for i in 0..15u16 {
            long.push((0x5000 + u64::from(i) * 0x1000, 512, RD | NEXT, i + 2));
        }
        long.push((STATUS, 1, WR, 0));

        vec![
            Case {
                descs: vec![
                    (HDR, 15, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 2, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: long,
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: wide,
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (0x9000, 32, INDIRECT, 0)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (0x6000, 512, WR | NEXT, 3),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0xFFFF_FFFF, 512, RD | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
        ]
    }
    fn check_case(index: usize, case: &Case) {
        use virtio_queue_git::Queue;
        use virtio_queue_git::QueueOwnedT as _;
        use virtio_queue_git::desc::{RawDescriptor, split::Descriptor as SplitDescriptor};
        use virtio_queue_git::mock::MockSplitQueue;
        use vm_memory::{Bytes as _, GuestAddress, GuestMemoryMmap};

        let ram = usize::try_from(RAM).expect("test RAM fits");
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), ram)]).expect("test RAM maps");
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&case.req_type.to_le_bytes());
        header[8..16].copy_from_slice(&case.sector.to_le_bytes());
        mem.write_slice(&header, GuestAddress(HDR))
            .expect("header fits");
        if case.descs.iter().any(|desc| desc.2 & INDIRECT != 0) {
            let mut table = [0u8; 32];
            table[0..8].copy_from_slice(&0x5000u64.to_le_bytes());
            table[8..12].copy_from_slice(&512u32.to_le_bytes());
            table[12..14].copy_from_slice(&(RD | NEXT).to_le_bytes());
            table[14..16].copy_from_slice(&1u16.to_le_bytes());
            table[16..24].copy_from_slice(&STATUS.to_le_bytes());
            table[24..28].copy_from_slice(&1u32.to_le_bytes());
            table[28..30].copy_from_slice(&WR.to_le_bytes());
            mem.write_slice(&table, GuestAddress(0x9000))
                .expect("table fits");
        }
        let raws: Vec<RawDescriptor> = case
            .descs
            .iter()
            .map(|desc| RawDescriptor::from(SplitDescriptor::new(desc.0, desc.1, desc.2, desc.3)))
            .collect();
        let queue = MockSplitQueue::new(&mem, 32);
        queue.add_desc_chains(&raws, 0).expect("chains stage");
        let mut device_queue = queue.create_queue::<Queue>().expect("queue params");
        let mut chain = device_queue
            .iter(&mem)
            .expect("avail iterates")
            .next()
            .expect("chain present");
        let upstream = Request::parse(&mut chain);

        let snapshots: Vec<super::Descriptor> = case
            .descs
            .iter()
            .map(|desc| super::Descriptor {
                addr: desc.0,
                len: desc.1,
                flags: desc.2,
                next: desc.3,
            })
            .collect();
        let ours = ParsedRequest::walk(&snapshots, 0, RAM);
        // Mirror `execute`'s sector rule: the walk validates framing
        // only, while upstream folds the flush-sector MUST into
        // parsing. Behavior matches (no completion either way).
        let ours = match (&ours, case.req_type, case.sector) {
            (Ok(_), T_FLUSH, sector) if sector != 0 => None,
            (Ok(parsed), _, _) => Some(parsed.clone()),
            (Err(_), _, _) => None,
        };

        match (&ours, &upstream, &case.expect) {
            (Some(parsed), Ok(request), Expect::Accept) => {
                assert_eq!(upstream_type(request.request_type()), case.req_type);
                assert_eq!(request.sector(), case.sector);
                assert_eq!(request.total_data_len(), parsed.total);
                assert_eq!(request.status_addr().0, parsed.status_addr);
                let up_data: Vec<(u64, u32)> = request
                    .data()
                    .iter()
                    .map(|(addr, len)| (addr.0, *len))
                    .collect();
                let our_data: Vec<(u64, u32)> = parsed.data.clone();
                assert_eq!(up_data, our_data);
            }
            (None, Err(_), Expect::RejectBoth) | (None, Ok(_), Expect::TerraStricter) => {}
            (Some(_), Err(_), _) => {
                panic!("case {index}: upstream rejects what we accept (adopt the rule)");
            }
            _ => panic!("case {index}: wrong expectation annotation"),
        }
    }

    #[test]
    fn parsers_agree_up_to_policy_bounds() {
        for (index, case) in corpus().iter().enumerate() {
            check_case(index, case);
        }
    }
}
