//! Darwin process-generation-bound termination.

use crate::sys::SignalResult;
use std::io;

const PROC_PIDT_BSDINFOWITHUNIQID: i32 = 18;

#[repr(C)]
struct ProcessGeneration {
    executable_uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    version: i32,
    reserved: u32,
    reserved_tail: [u64; 2],
}

#[repr(C)]
struct ProcessInfo {
    bsd: libc::proc_bsdinfo,
    generation: ProcessGeneration,
}

#[repr(C)]
struct AuditToken {
    values: [u32; 8],
}

const _: () = assert!(std::mem::size_of::<ProcessGeneration>() == 56);
const _: () = assert!(std::mem::size_of::<ProcessInfo>() == 192);
const _: () = assert!(std::mem::size_of::<AuditToken>() == 32);

#[allow(unsafe_code)]
unsafe extern "C" {
    fn proc_signal_with_audittoken(token: *mut AuditToken, signal: libc::c_int) -> libc::c_int;
}

#[allow(unsafe_code)]
fn read_verified_token(pid: i32, published_start_time: Option<u64>) -> Option<AuditToken> {
    let published = published_start_time?;
    let mut info = std::mem::MaybeUninit::<ProcessInfo>::uninit();
    let size = i32::try_from(std::mem::size_of::<ProcessInfo>()).ok()?;
    // SAFETY: the C layout and buffer size match PROC_PIDT_BSDINFOWITHUNIQID.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDT_BSDINFOWITHUNIQID,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo initialized the complete buffer.
    let info = unsafe { info.assume_init() };
    let started = info
        .bsd
        .pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.bsd.pbi_start_tvusec)?;
    if started != published || info.bsd.pbi_pid != pid.cast_unsigned() {
        return None;
    }
    let mut token = AuditToken { values: [0; 8] };
    token.values[5] = info.bsd.pbi_pid;
    token.values[7] = info.generation.version.cast_unsigned();
    Some(token)
}

#[allow(unsafe_code)]
fn terminate_token(mut token: AuditToken) -> io::Result<SignalResult> {
    // SAFETY: the token is initialized; Darwin validates its PID and generation before signalling.
    match unsafe { proc_signal_with_audittoken(&raw mut token, libc::SIGKILL) } {
        0 => Ok(SignalResult::Sent),
        libc::ESRCH => Ok(SignalResult::IdentityUnknown),
        error => Err(io::Error::from_raw_os_error(error)),
    }
}

pub(super) fn terminate_process(
    pid: i32,
    published_start_time: Option<u64>,
) -> io::Result<SignalResult> {
    let Some(token) = read_verified_token(pid, published_start_time) else {
        return Ok(SignalResult::IdentityUnknown);
    };
    terminate_token(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A token for a previous process generation must not kill the live process
    /// now using that PID, even after userspace identity verification succeeded.
    #[test]
    fn a_replaced_process_generation_is_not_signalled() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let identity = crate::sys::read_process_start_time(pid);
        let mut token = read_verified_token(i32::try_from(pid).unwrap(), identity).unwrap();
        token.values[7] = token.values[7].wrapping_add(1);
        let result = terminate_token(token).unwrap();
        let survived = child.try_wait().unwrap().is_none();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(result, SignalResult::IdentityUnknown);
        assert!(survived);
    }

    #[test]
    fn an_exit_after_verification_invalidates_the_token() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let token = read_verified_token(
            i32::try_from(pid).unwrap(),
            crate::sys::read_process_start_time(pid),
        )
        .unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            terminate_token(token).unwrap(),
            SignalResult::IdentityUnknown
        );
    }
}
