use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

pub struct WindowsRam {
    address: core::ptr::NonNull<u8>,
    size: usize,
    guest_base: u64,
}

// SAFETY: WindowsRam owns stable VirtualAlloc storage; BoundedMemory uses atomic byte accesses.
#[allow(unsafe_code)]
unsafe impl Send for WindowsRam {}

// SAFETY: WindowsRam exposes no Rust references into the allocation.
#[allow(unsafe_code)]
unsafe impl Sync for WindowsRam {}

impl WindowsRam {
    #[must_use]
    pub fn allocate(size: u64) -> Option<std::sync::Arc<Self>> {
        Self::allocate_at(size, 0)
    }

    #[must_use]
    pub fn allocate_at(size: u64, guest_base: u64) -> Option<std::sync::Arc<Self>> {
        let size = usize::try_from(size).ok()?;
        if size == 0 || guest_base.checked_add(u64::try_from(size).ok()?).is_none() {
            return None;
        }
        #[allow(unsafe_code)]
        let address = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        Some(std::sync::Arc::new(Self {
            address: core::ptr::NonNull::new(address.cast())?,
            size,
            guest_base,
        }))
    }

    #[must_use]
    pub const fn address(&self) -> *mut u8 {
        self.address.as_ptr()
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    #[must_use]
    pub const fn guest_base(&self) -> u64 {
        self.guest_base
    }
}

impl Drop for WindowsRam {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            // SAFETY: WindowsRam owns this VirtualAlloc allocation.
            VirtualFree(self.address.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}
