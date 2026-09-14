use crate::SyntheticRam;
use crate::engine::DeviceHost;
#[cfg(unix)]
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryRegion, MemoryRegionAddress};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::DiscardVirtualMemory;
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/mem/wit",
    debug: false,
    with: {
        "terra:host/memory@0.1.0": crate::engine::terra::host::memory,
        "terra:host/interrupt@0.1.0": crate::engine::terra::host::interrupt,
    },
});

pub use terra::mmio::types::DeviceError as MemDeviceError;

const PAGE_BYTES: u64 = 4096;
const MAX_RANGES: usize = 32;
const MAX_DISCARD_BYTES: u64 = 128 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclaimRange {
    pub addr: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimError {
    Invalid,
    Unsupported,
    TooLarge,
    Io,
}

pub struct MemHost {
    pub device: DeviceHost,
}

impl MemHost {
    #[must_use]
    pub fn new(device: DeviceHost) -> Self {
        Self { device }
    }

    pub fn discard(&mut self, ranges: &[ReclaimRange]) -> Result<(), ReclaimError> {
        validate_ranges(self.device.guest_ram(), ranges)?;
        for &range in ranges {
            discard_range(self.device.guest_ram(), range)?;
        }
        Ok(())
    }
}

fn validate_ranges(ram: &SyntheticRam, ranges: &[ReclaimRange]) -> Result<(), ReclaimError> {
    if ranges.len() > MAX_RANGES {
        return Err(ReclaimError::TooLarge);
    }

    let mut total: u64 = 0;
    for &range in ranges {
        if range.len == 0 || range.addr % PAGE_BYTES != 0 || range.len % PAGE_BYTES != 0 {
            return Err(ReclaimError::Invalid);
        }
        total = total.checked_add(range.len).ok_or(ReclaimError::TooLarge)?;
        if total > MAX_DISCARD_BYTES {
            return Err(ReclaimError::TooLarge);
        }

        let end = range
            .addr
            .checked_add(range.len)
            .ok_or(ReclaimError::Invalid)?;
        if end > ram.size() {
            return Err(ReclaimError::Invalid);
        }
        #[cfg(unix)]
        {
            let length = usize::try_from(range.len).map_err(|_| ReclaimError::TooLarge)?;
            if !ram.mem.check_range(GuestAddress(range.addr), length) {
                return Err(ReclaimError::Invalid);
            }
            let region = ram
                .mem
                .find_region(GuestAddress(range.addr))
                .ok_or(ReclaimError::Invalid)?;
            let offset = range.addr - region.start_addr().0;
            let address = region
                .get_host_address(MemoryRegionAddress(offset))
                .map_err(|_| ReclaimError::Invalid)?;
            if full_host_pages(address as usize, length, host_page_bytes()).is_none() {
                return Err(ReclaimError::Invalid);
            }
            if end
                > region
                    .last_addr()
                    .0
                    .checked_add(1)
                    .ok_or(ReclaimError::Invalid)?
            {
                return Err(ReclaimError::Invalid);
            }
        }
        #[cfg(windows)]
        if range.addr < ram.mem.guest_base() {
            return Err(ReclaimError::Invalid);
        }
    }
    Ok(())
}

fn discard_range(ram: &SyntheticRam, range: ReclaimRange) -> Result<(), ReclaimError> {
    #[cfg(windows)]
    {
        let offset = usize::try_from(range.addr - ram.mem.guest_base())
            .map_err(|_| ReclaimError::TooLarge)?;
        let length = usize::try_from(range.len).map_err(|_| ReclaimError::TooLarge)?;
        let Some((address, length)) = full_host_pages(
            ram.mem.address().wrapping_add(offset) as usize,
            length,
            host_page_bytes(),
        ) else {
            return Err(ReclaimError::Invalid);
        };
        #[allow(unsafe_code)]
        // SAFETY: validation confines this full host-page range to WindowsRam.
        let result = unsafe { DiscardVirtualMemory(address as *mut _, length) };
        if result != 0 {
            return Err(ReclaimError::Io);
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        let region = ram
            .mem
            .find_region(GuestAddress(range.addr))
            .ok_or(ReclaimError::Invalid)?;
        let offset = range
            .addr
            .checked_sub(region.start_addr().0)
            .ok_or(ReclaimError::Invalid)?;
        let offset = usize::try_from(offset).map_err(|_| ReclaimError::TooLarge)?;
        let length = usize::try_from(range.len).map_err(|_| ReclaimError::TooLarge)?;
        let address = region
            .get_host_address(MemoryRegionAddress(offset as u64))
            .map_err(|_| ReclaimError::Invalid)?;
        let Some((address, length)) = full_host_pages(address as usize, length, host_page_bytes())
        else {
            return Err(ReclaimError::Invalid);
        };
        // SAFETY: validation proves the page-aligned range remains in this mapped RAM region.
        #[allow(unsafe_code)]
        let result = unsafe {
            libc::madvise(
                address as *mut _,
                length,
                #[cfg(target_os = "macos")]
                libc::MADV_ZERO,
                #[cfg(not(target_os = "macos"))]
                libc::MADV_DONTNEED,
            )
        };
        #[cfg(target_os = "macos")]
        if result != 0
            && matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOTSUP | libc::EINVAL)
            )
        {
            return Err(ReclaimError::Unsupported);
        }
        (result == 0).then_some(()).ok_or(ReclaimError::Io)
    }
}

fn full_host_pages(address: usize, len: usize, page: usize) -> Option<(usize, usize)> {
    if page == 0 {
        return None;
    }
    let end = address.checked_add(len)?;
    let start = address.checked_add(page.checked_sub(1)?)? / page * page;
    let end = end / page * page;
    (end > start).then(|| (start, end - start))
}

fn host_page_bytes() -> usize {
    #[cfg(unix)]
    {
        rustix::param::page_size()
    }
    #[cfg(windows)]
    {
        let mut info = core::mem::MaybeUninit::<SYSTEM_INFO>::zeroed();
        #[allow(unsafe_code)]
        unsafe {
            // SAFETY: GetSystemInfo initializes SYSTEM_INFO at this valid pointer.
            GetSystemInfo(info.as_mut_ptr());
            info.assume_init().dwPageSize as usize
        }
    }
}

struct MemMemoryHost;

impl wasmtime::component::HasData for MemMemoryHost {
    type Data<'a> = &'a mut MemHost;
}

struct MemInterruptHost;

impl wasmtime::component::HasData for MemInterruptHost {
    type Data<'a> = &'a mut MemHost;
}

struct MemNativeHost;

impl wasmtime::component::HasData for MemNativeHost {
    type Data<'a> = &'a mut MemHost;
}

impl wasmtime_wasi::WasiView for MemHost {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiView::ctx(&mut self.device)
    }
}

impl terra::host::memory::Host for MemHost {
    fn read(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, terra::host::memory::MemoryError> {
        terra::host::memory::Host::read(&mut self.device, offset, len)
    }

    fn write(
        &mut self,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<(), terra::host::memory::MemoryError> {
        terra::host::memory::Host::write(&mut self.device, offset, data)
    }

    fn ram_bytes(&mut self) -> u64 {
        terra::host::memory::Host::ram_bytes(&mut self.device)
    }
}

impl terra::host::interrupt::Host for MemHost {
    fn set_level(&mut self, level: bool) {
        terra::host::interrupt::Host::set_level(&mut self.device, level);
    }

    fn signal(&mut self) {
        terra::host::interrupt::Host::signal(&mut self.device);
    }
}

fn reclaim_error(error: ReclaimError) -> terra::mem::host::Error {
    match error {
        ReclaimError::Invalid => terra::mem::host::Error::Invalid,
        ReclaimError::TooLarge => terra::mem::host::Error::TooLarge,
        ReclaimError::Io | ReclaimError::Unsupported => terra::mem::host::Error::Io,
    }
}

impl terra::mem::host::Host for MemHost {
    fn discard(
        &mut self,
        ranges: Vec<terra::mem::host::Range>,
    ) -> Result<(), terra::mem::host::Error> {
        let ranges = ranges
            .into_iter()
            .map(|range| ReclaimRange {
                addr: range.addr,
                len: range.len,
            })
            .collect::<Vec<_>>();
        self.discard(&ranges).map_err(reclaim_error)
    }
}

pub fn mem_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<MemHost>> {
    let mut linker = crate::engine::device_component_linker(engine)?;
    crate::engine::terra::host::memory::add_to_linker::<MemHost, MemMemoryHost>(
        &mut linker,
        |host| host,
    )?;
    crate::engine::terra::host::interrupt::add_to_linker::<MemHost, MemInterruptHost>(
        &mut linker,
        |host| host,
    )?;
    terra::mem::host::add_to_linker::<MemHost, MemNativeHost>(&mut linker, |host| host)?;
    Ok(linker)
}

fn shared_memory(host: &mut crate::box_runtime::BoxHost) -> &mut MemHost {
    &mut host.memory[0]
}

fn shared_memory_cli(
    host: &mut crate::box_runtime::BoxHost,
) -> wasmtime_wasi::cli::WasiCliCtxView<'_> {
    use wasmtime_wasi::cli::WasiCliView;

    shared_memory(host).device.cli()
}

fn shared_memory_clocks(
    host: &mut crate::box_runtime::BoxHost,
) -> wasmtime_wasi::clocks::WasiClocksCtxView<'_> {
    use wasmtime_wasi::clocks::WasiClocksView;

    shared_memory(host).device.clocks()
}

pub fn shared_mem_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<crate::box_runtime::BoxHost>> {
    let mut linker = crate::engine::device_component_linker_with_wasi(
        engine,
        crate::engine::DeviceWasiGetters {
            cli: shared_memory_cli,
            clocks: shared_memory_clocks,
        },
    )?;
    crate::engine::terra::host::memory::add_to_linker::<crate::box_runtime::BoxHost, MemMemoryHost>(
        &mut linker,
        shared_memory,
    )?;
    crate::engine::terra::host::interrupt::add_to_linker::<
        crate::box_runtime::BoxHost,
        MemInterruptHost,
    >(&mut linker, shared_memory)?;
    terra::mem::host::add_to_linker::<crate::box_runtime::BoxHost, MemNativeHost>(
        &mut linker,
        shared_memory,
    )?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoundedMemory;

    fn host() -> (MemHost, SyntheticRam) {
        let ram = SyntheticRam::new(16 * 1024).expect("RAM");
        (MemHost::new(DeviceHost::with_ram(ram.clone())), ram)
    }

    #[test]
    fn legal_reclaim_batches_are_not_limited_by_a_worker_lifetime_total() {
        let ram = SyntheticRam::new(256 << 20).unwrap();
        let mut host = MemHost::new(DeviceHost::with_ram(ram));
        let result = host.discard(&[ReclaimRange {
            addr: 0,
            len: MAX_DISCARD_BYTES,
        }]);
        #[cfg(target_os = "macos")]
        if result == Err(ReclaimError::Unsupported) {
            return;
        }
        result.unwrap();
        host.discard(&[ReclaimRange {
            addr: MAX_DISCARD_BYTES,
            len: MAX_DISCARD_BYTES,
        }])
        .unwrap();
    }

    #[test]
    fn sub_host_page_reclaim_is_rejected_without_modifying_memory() {
        let page = host_page_bytes();
        let guest_page = usize::try_from(PAGE_BYTES).unwrap();
        if page <= guest_page {
            return;
        }
        let ram = SyntheticRam::new((page * 2) as u64).expect("RAM");
        let mut host = MemHost::new(DeviceHost::with_ram(ram));
        host.device
            .guest_write(0, &vec![0x5a; guest_page])
            .expect("write RAM");
        assert_eq!(
            host.discard(&[ReclaimRange {
                addr: 0,
                len: PAGE_BYTES
            }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            host.device.guest_read(0, PAGE_BYTES).expect("read RAM"),
            vec![0x5a; guest_page]
        );
    }

    #[cfg(unix)]
    #[test]
    fn discard_zeroes_this_vm_page() {
        let page = host_page_bytes();
        let ram = SyntheticRam::new((page * 2) as u64).expect("RAM");
        let mut host = MemHost::new(DeviceHost::with_ram(ram.clone()));
        host.device
            .guest_write(page as u64, &vec![0x5a; page])
            .expect("write RAM");
        let result = host.discard(&[ReclaimRange {
            addr: page as u64,
            len: page as u64,
        }]);
        #[cfg(target_os = "macos")]
        if result == Err(ReclaimError::Unsupported) {
            assert_eq!(
                host.device
                    .guest_read(page as u64, page as u64)
                    .expect("read RAM"),
                vec![0x5a; page]
            );
            return;
        }
        result.expect("discard page");
        assert_eq!(
            host.device
                .guest_read(page as u64, page as u64)
                .expect("read RAM"),
            vec![0; page]
        );
        assert_eq!(
            BoundedMemory::new(&ram)
                .read(page as u64, page as u64)
                .expect("shared RAM"),
            vec![0; page]
        );
    }

    #[test]
    fn invalid_batch_does_not_discard_an_earlier_page() {
        let (mut host, ram) = host();
        BoundedMemory::new(&ram)
            .write(0, &[0x5a; 4096])
            .expect("write RAM");
        assert_eq!(
            host.discard(&[
                ReclaimRange { addr: 0, len: 4096 },
                ReclaimRange {
                    addr: 15 * 1024,
                    len: 4096,
                },
            ]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            BoundedMemory::new(&ram).read(0, 4096).expect("read RAM"),
            vec![0x5a; 4096]
        );
    }

    #[test]
    fn reject_unaligned_overflow_and_too_many_ranges() {
        let (mut host, _) = host();
        assert_eq!(
            host.discard(&[ReclaimRange { addr: 1, len: 4096 }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            host.discard(&[ReclaimRange {
                addr: u64::MAX - 4095,
                len: 4096,
            }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            host.discard(&vec![ReclaimRange { addr: 0, len: 4096 }; MAX_RANGES + 1]),
            Err(ReclaimError::TooLarge)
        );
    }

    #[cfg(unix)]
    #[test]
    fn reject_ranges_that_cross_a_guest_ram_hole() {
        use std::sync::Arc;
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let mapping = Arc::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(8192), 4096)])
                .expect("RAM with a hole"),
        );
        let ram = SyntheticRam::from_shared(mapping).expect("RAM alias");
        let mut host = MemHost::new(DeviceHost::with_ram(ram.clone()));
        BoundedMemory::new(&ram)
            .write(0, &[0x5a; 4096])
            .expect("write first region");
        assert_eq!(
            host.discard(&[ReclaimRange { addr: 0, len: 8192 }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            BoundedMemory::new(&ram)
                .read(0, 4096)
                .expect("read first region"),
            vec![0x5a; 4096]
        );
    }

    #[test]
    fn discard_does_not_touch_another_mapping() {
        let first_ram = SyntheticRam::new(64 * 1024).expect("RAM");
        let mut first = MemHost::new(DeviceHost::with_ram(first_ram.clone()));
        let (_second, second_ram) = host();
        BoundedMemory::new(&first_ram)
            .write(0, &[0x5a; 4096])
            .expect("write first RAM");
        BoundedMemory::new(&second_ram)
            .write(0, &[0xa5; 4096])
            .expect("write second RAM");
        let result = first.discard(&[ReclaimRange {
            addr: 0,
            len: 64 * 1024,
        }]);
        assert!(
            result.is_ok()
                || (cfg!(target_os = "macos") && result == Err(ReclaimError::Unsupported))
        );
        assert_eq!(
            BoundedMemory::new(&second_ram)
                .read(0, 4096)
                .expect("read second RAM"),
            vec![0xa5; 4096]
        );
    }

    #[test]
    fn discard_keeps_only_complete_host_pages() {
        assert_eq!(full_host_pages(0x1000, 0x1000, 0x4000), None);
        assert_eq!(
            full_host_pages(0x1000, 0x8000, 0x4000),
            Some((0x4000, 0x4000))
        );
        assert_eq!(
            full_host_pages(0x4000, 0x8000, 0x4000),
            Some((0x4000, 0x8000))
        );
    }
}
