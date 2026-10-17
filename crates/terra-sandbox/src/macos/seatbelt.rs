//! Applies a rendered Seatbelt profile to the calling process.

use super::policy::Profile;
use anyhow::{Context, Result, bail};
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;

#[allow(unsafe_code)]
unsafe extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

#[allow(unsafe_code)]
pub(super) fn apply(profile: &Profile) -> Result<()> {
    let text = CString::new(profile.text.as_str()).context("the sandbox profile contains NUL")?;
    let mut owned = Vec::with_capacity(profile.parameters.len() * 2);
    for (key, value) in &profile.parameters {
        owned.push(CString::new(key.as_str()).context("a sandbox parameter name contains NUL")?);
        owned.push(CString::new(value.as_str()).context("a sandbox parameter value contains NUL")?);
    }
    let mut parameters: Vec<*const c_char> = owned.iter().map(|text| text.as_ptr()).collect();
    parameters.push(ptr::null());
    let mut error: *mut c_char = ptr::null_mut();
    // SAFETY: `text` and every parameter are NUL-terminated and outlive the call, the parameter
    // array ends in NULL, and `error` is a valid out-pointer.
    let status = unsafe {
        sandbox_init_with_parameters(text.as_ptr(), 0, parameters.as_ptr(), &raw mut error)
    };
    if status == 0 {
        return Ok(());
    }
    let message = if error.is_null() {
        "no error message".to_owned()
    } else {
        // SAFETY: on failure libsandbox sets `error` to a NUL-terminated string that it owns until
        // sandbox_free_error.
        let message = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `error` came from sandbox_init_with_parameters and is freed exactly once.
        unsafe { sandbox_free_error(error) };
        message
    };
    bail!("applying the macOS sandbox profile: {message}")
}
