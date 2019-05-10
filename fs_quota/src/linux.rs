//
// Linux specific systemcalls for quota.
//
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::{FsQuota, FqError, Mtab};

// The actual implementation is done in C, and imported here.
extern "C" {
    fn fs_quota_linux(
        device: *const c_char,
        id: c_int,
        do_group: c_int,
        bytes_used: *mut u64,
        bytes_limit: *mut u64,
        files_used: *mut u64,
        files_limit: *mut u64,
    ) -> c_int;
}

// wrapper for the C functions.
pub(crate) fn get_quota(device: impl AsRef<Path>, uid: u32) -> Result<FsQuota, FqError> {
    let id = uid as c_int;
    let device = device.as_ref();

    let mut bytes_used = 0u64;
    let mut bytes_limit = 0u64;
    let mut files_used = 0u64;
    let mut files_limit = 0u64;

    let path = CString::new(device.as_os_str().as_bytes())?;
    let rc = unsafe { 
        fs_quota_linux(
            path.as_ptr(),
            id,
            0,
            &mut bytes_used as *mut u64,
            &mut bytes_limit as *mut u64,
            &mut files_used as *mut u64,
            &mut files_limit as *mut u64,
        )
    };

    // Error mapping.
    match rc {
        0 => {
            let m = |v| if v == 0xffffffffffffffff { None } else { Some(v) };
            Ok(FsQuota {
                bytes_used:  bytes_used,
                bytes_limit: m(bytes_limit),
                files_used:  files_used,
                files_limit: m(files_limit),
            })
        },
        1 => Err(FqError::NoQuota),
        _ => Err(FqError::IoError(io::Error::last_os_error())),
    }
}

// read /etc/mtab.
pub(crate) fn read_mtab() -> io::Result<Vec<Mtab>> {
    let f = File::open("/etc/mtab")?;
    let reader = BufReader::new(f);
    let mut result = Vec::new();
    for l in reader.lines() {
        let l2 = l?;
        let line = l2.trim();
        if line.len() == 0 || line.starts_with("#") {
            continue;
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.len() < 3 {
            continue;
        }
        let (host, device) = if words[2].starts_with("nfs") {
            if !words[0].contains(":") {
                continue;
            }
            let mut s = words[0].splitn(2, ':');
            let host = s.next().unwrap();
            let path = s.next().unwrap();
            (Some(host.to_string()), path)
        } else {
            (None, words[2])
        };
        result.push(Mtab {
            host:      host,
            device:    device.to_string(),
            directory: words[1].to_string(),
            fstype:    words[2].to_string(),
        });
    }
    Ok(result)
}

