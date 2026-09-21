use super::super::{Partition, PartitionError, WhpError, result};
use std::ffi::c_void;
use windows_sys::Win32::System::Hypervisor::{
    WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_IO_ACCESS_INFO, WHV_EMULATOR_MEMORY_ACCESS_INFO,
    WHV_EMULATOR_STATUS, WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT,
    WHV_TRANSLATE_GVA_FLAGS, WHV_TRANSLATE_GVA_RESULT, WHV_TRANSLATE_GVA_RESULT_CODE,
    WHvEmulatorCreateEmulator, WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation,
    WHvEmulatorTryMmioEmulation, WHvTranslateGva,
};

const E_FAIL: i32 = 0x8000_4005u32 as i32;

pub struct Emulator {
    handle: *mut c_void,
}

impl Emulator {
    pub fn new() -> Result<Self, WhpError> {
        let callbacks = WHV_EMULATOR_CALLBACKS {
            Size: size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
            Reserved: 0,
            WHvEmulatorIoPortCallback: Some(emulate_io_port),
            WHvEmulatorMemoryCallback: Some(emulate_memory),
            WHvEmulatorGetVirtualProcessorRegisters: Some(emulate_get_registers),
            WHvEmulatorSetVirtualProcessorRegisters: Some(emulate_set_registers),
            WHvEmulatorTranslateGvaPage: Some(emulate_translate_gva_page),
        };
        let mut handle = std::ptr::null_mut();
        // SAFETY: callbacks lives for the creation call and all entries are valid functions.
        result(unsafe { WHvEmulatorCreateEmulator(&raw const callbacks, &raw mut handle) })?;
        Ok(Self { handle })
    }

    pub fn emulate_mmio(
        &self,
        context: &mut EmulationContext<'_>,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
    ) -> Result<(), PartitionError> {
        // SAFETY: MemoryAccess is active for the caller's memory-access exit.
        let memory_access = unsafe { exit.Anonymous.MemoryAccess };
        let mut status = WHV_EMULATOR_STATUS::default();
        // SAFETY: context remains valid throughout this synchronous call and its callbacks.
        result(unsafe {
            WHvEmulatorTryMmioEmulation(
                self.handle,
                std::ptr::from_mut(context).cast(),
                &raw const exit.VpContext,
                &raw const memory_access,
                &raw mut status,
            )
        })
        .map_err(PartitionError::Api)?;
        // SAFETY: WHvEmulatorTryMmioEmulation initialized the status union.
        complete_emulation(context, unsafe { status.AsUINT32 })
    }

    pub fn emulate_io(
        &self,
        context: &mut EmulationContext<'_>,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
    ) -> Result<(), PartitionError> {
        // SAFETY: IoPortAccess is active for the caller's I/O-port exit.
        let io_access = unsafe { exit.Anonymous.IoPortAccess };
        let mut status = WHV_EMULATOR_STATUS::default();
        // SAFETY: context remains valid throughout this synchronous call and its callbacks.
        result(unsafe {
            WHvEmulatorTryIoEmulation(
                self.handle,
                std::ptr::from_mut(context).cast(),
                &raw const exit.VpContext,
                &raw const io_access,
                &raw mut status,
            )
        })
        .map_err(PartitionError::Api)?;
        // SAFETY: WHvEmulatorTryIoEmulation initialized the status union.
        complete_emulation(context, unsafe { status.AsUINT32 })
    }
}

fn complete_emulation(
    context: &mut EmulationContext<'_>,
    status: u32,
) -> Result<(), PartitionError> {
    const SUCCESS: u32 = 1;
    const INTERNAL_FAILURE: u32 = 1 << 1;
    const INTERRUPT_CAUSED_INTERCEPT: u32 = 1 << 8;
    const GUEST_CANNOT_BE_FAULTED: u32 = 1 << 9;
    if status & SUCCESS != 0 {
        return context.error.take().map_or(Ok(()), Err);
    }
    if let Some(error) = context.error.take() {
        return Err(error);
    }
    if status & GUEST_CANNOT_BE_FAULTED != 0 {
        return Err(PartitionError::Api(WhpError(E_FAIL)));
    }
    if status & INTERNAL_FAILURE != 0 {
        context.partition.inject_invalid_opcode(context.vcpu)?;
        return Ok(());
    }
    if status & INTERRUPT_CAUSED_INTERCEPT != 0 {
        return Ok(());
    }
    Err(PartitionError::Api(WhpError(E_FAIL)))
}

impl Drop for Emulator {
    fn drop(&mut self) {
        // SAFETY: handle was returned by WHvEmulatorCreateEmulator and is dropped once.
        unsafe { WHvEmulatorDestroyEmulator(self.handle) };
    }
}

pub struct EmulationContext<'a> {
    partition: &'a Partition,
    vcpu: u32,
    memory: &'a mut MmioCallback<'a>,
    io: &'a mut PioCallback<'a>,
    error: Option<PartitionError>,
}

impl<'a> EmulationContext<'a> {
    pub fn new(
        partition: &'a Partition,
        vcpu: u32,
        memory: &'a mut MmioCallback<'a>,
        io: &'a mut PioCallback<'a>,
    ) -> Self {
        Self {
            partition,
            vcpu,
            memory,
            io,
            error: None,
        }
    }
}

type MmioCallback<'a> = dyn FnMut(u64, bool, &mut [u8]) -> Result<(), PartitionError> + 'a;

type PioCallback<'a> = dyn FnMut(u16, bool, u8, &mut u32) -> Result<(), PartitionError> + 'a;

unsafe extern "system" fn emulate_memory(
    context: *const c_void,
    access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies one initialized memory-access descriptor.
    let access = unsafe { &mut *access };
    let length = usize::from(access.AccessSize);
    if length > access.Data.len() {
        context.error = Some(PartitionError::Api(WhpError(E_FAIL)));
        return E_FAIL;
    }
    let bytes = &mut access.Data[..length];
    match (context.memory)(access.GpaAddress, access.Direction != 0, bytes) {
        Ok(()) => 0,
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

unsafe extern "system" fn emulate_io_port(
    context: *const c_void,
    access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_io.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies one initialized I/O-port descriptor.
    let access = unsafe { &mut *access };
    let width = match access.AccessSize {
        1 => 1,
        2 => 2,
        4 => 4,
        _ => {
            context.error = Some(PartitionError::Api(WhpError(E_FAIL)));
            return E_FAIL;
        }
    };
    match (context.io)(access.Port, access.Direction != 0, width, &mut access.Data) {
        Ok(()) => 0,
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

unsafe extern "system" fn emulate_get_registers(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *mut WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies count valid register names and output slots.
    let names = unsafe { std::slice::from_raw_parts(names, count as usize) };
    match context.partition.registers(context.vcpu, names) {
        Ok(registers) => {
            // SAFETY: WHP allocated count output slots; registers has the same length.
            unsafe { values.copy_from_nonoverlapping(registers.as_ptr(), registers.len()) };
            0
        }
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

unsafe extern "system" fn emulate_set_registers(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *const WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies count valid register names and values.
    let names = unsafe { std::slice::from_raw_parts(names, count as usize) };
    // SAFETY: WHP supplies count valid register names and values.
    let values = unsafe { std::slice::from_raw_parts(values, count as usize) };
    match context.partition.set_registers(context.vcpu, names, values) {
        Ok(()) => 0,
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

unsafe extern "system" fn emulate_translate_gva_page(
    context: *const c_void,
    gva: u64,
    flags: WHV_TRANSLATE_GVA_FLAGS,
    result_code: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
    gpa: *mut u64,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    let mut translation = WHV_TRANSLATE_GVA_RESULT::default();
    // SAFETY: result_code and gpa are WHP-provided output pointers for this callback.
    match result(unsafe {
        WHvTranslateGva(
            context.partition.handle,
            context.vcpu,
            gva,
            flags,
            &raw mut translation,
            gpa,
        )
    }) {
        Ok(()) => {
            // SAFETY: result_code is a valid WHP output pointer.
            unsafe { result_code.write(translation.ResultCode) };
            0
        }
        Err(error) => {
            context.error = Some(PartitionError::Api(error));
            E_FAIL
        }
    }
}
