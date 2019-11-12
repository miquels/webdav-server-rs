use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use crate::{FsQuota, FqError, Mtab};

extern "C" {
    fn fs_quota_nfs(
        host: *const c_char,
        path: *const c_char,
        nfsvers: *const c_char,
        id: c_int,
        do_group: c_int,
        bytes_used: *mut u64,
        bytes_limit: *mut u64,
        files_used: *mut u64,
        files_limit: *mut u64,
    ) -> c_int;
}

mod ffi {
    use super::*;
    extern "C" {
        pub(crate) fn clnt_sperrno(e: c_int) -> *const c_char;
    }
}

// The rpcsvc clnt_sperrno function.
fn clnt_sperrno(e: c_int) -> &'static str {
    unsafe {
        let msg = ffi::clnt_sperrno(e);
        std::str::from_utf8(CStr::from_ptr(msg).to_bytes()).unwrap()
    }
}

pub(crate) fn get_quota(entry: &Mtab, uid: u32) -> Result<FsQuota, FqError> {

    let host = CString::new(entry.host.as_ref().unwrap().as_bytes())?;
    let path = CString::new(entry.device.as_bytes())?;
    let fstype = CString::new(entry.fstype.as_bytes())?;

    let mut bytes_used = 0u64;
    let mut bytes_limit = 0u64;
    let mut files_used = 0u64;
    let mut files_limit = 0u64;

    let rc = unsafe {
        fs_quota_nfs(
            host.as_ptr(),
            path.as_ptr(),
            fstype.as_ptr(),
            uid as c_int,
            0,
            &mut bytes_used as *mut u64,
            &mut bytes_limit as *mut u64,
            &mut files_used as *mut u64,
            &mut files_limit as *mut u64,
        )
    };

    // Error mapping.
    match rc {
        0 => {},
        0x00000001 => {
            debug!("nfs: clnt_create error");
            return Err(FqError::Other);
        },
        0x00000002 => {
            return Err(FqError::NoQuota);
        },
        0x00000003 => {
            debug!("nfs: permission denied");
            return Err(FqError::PermissionDenied);
        },
        c @ 0x00100000..=0x001fffff => {
            let e = c & 0x000fffff;
            debug!("nfs: clnt_call error: {}", clnt_sperrno(e));
            return Err(FqError::Other);
        },
        e => {
            debug!("nfs: unknown error {}", e);
            return Err(FqError::Other);
        }
    }

    let m = |v| if v == 0xffffffffffffffff { None } else { Some(v) };
    let res = FsQuota {
        bytes_used:  bytes_used,
        bytes_limit: m(bytes_limit),
        files_used:  files_used,
        files_limit: m(files_limit),
    };
    return Ok(res);
}

