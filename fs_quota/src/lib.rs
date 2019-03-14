#[macro_use]
extern crate log;
extern crate libc;

use std::ffi::OsStr;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::os::linux::fs::MetadataExt;
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct FsQuota {
    pub bytes_used:  u64,
    pub bytes_limit: Option<u64>,
    pub files_used:  u64,
    pub files_limit: Option<u64>,
}

#[derive(Debug)]
pub enum FqError {
    PermissionDenied,
    NoQuota,
    IoError(io::Error),
    Other,
}

#[derive(Debug, Default)]
#[repr(C)]
struct StatVfs {
    f_bsize:   usize,
    f_frsize:  usize,
    f_blocks:  usize,
    f_bfree:   usize,
    f_bavail:  usize,
    f_files:   usize,
    f_ffree:   usize,
    f_favail:  usize,
    f_fsid:    usize,
    f_flag:    usize,
    f_namemax: usize,
}

extern "C" {
    fn fs_quota_linux_ext(
        device: *const c_char,
        id: c_int,
        do_group: c_int,
        bytes_used: *mut u64,
        bytes_limit: *mut u64,
        files_used: *mut u64,
        files_limit: *mut u64,
    ) -> c_int;
    fn fs_quota_linux_xfs(
        device: *const c_char,
        id: c_int,
        do_group: c_int,
        bytes_used: *mut u64,
        bytes_limit: *mut u64,
        files_used: *mut u64,
        files_limit: *mut u64,
    ) -> c_int;
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
        pub(crate) fn statvfs(path: *const c_char, buf: *mut StatVfs) -> c_int;
        pub(crate) fn realpath(path: *const c_char, rpath: *const c_char) -> *const c_char;
        pub(crate) fn free(ptr: *const c_char);
        pub(crate) fn clnt_sperrno(e: c_int) -> *const c_char;
        pub(crate) fn getuid() -> u32;
    }
}

// The libc statvfs() function.
fn statvfs<P: AsRef<Path>>(path: P) -> io::Result<StatVfs> {
    let cpath = CString::new(path.as_ref().as_os_str().as_bytes())?;
    let mut sv: StatVfs = Default::default();
    let rc = unsafe { ffi::statvfs(cpath.as_ptr(), &mut sv) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sv)
    }
}

// The libc realpath() function.
fn realpath<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
    let cpath = CString::new(path.as_ref().as_os_str().as_bytes())?;
    let nullptr: *const c_char = std::ptr::null();
    unsafe {
        let r = ffi::realpath(cpath.as_ptr(), nullptr);
        if r == nullptr {
            Err(io::Error::last_os_error())
        } else {
            let osstr = OsStr::from_bytes(CStr::from_ptr(r).to_bytes());
            let p = PathBuf::from(osstr);
            ffi::free(r);
            Ok(p)
        }
    }
}

// The rpcsvc clnt_sperrno function.
fn clnt_sperrno(e: c_int) -> &'static str {
    unsafe {
        let msg = ffi::clnt_sperrno(e);
        std::str::from_utf8(CStr::from_ptr(msg).to_bytes()).unwrap()
    }
}

#[derive(Debug, Clone)]
struct Mtab {
    host:      Option<String>,
    device:    String,
    directory: String,
    fstype:    String,
}

// read /etc/mtab.
fn read_mtab() -> io::Result<Vec<Mtab>> {
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

#[derive(Debug, PartialEq)]
enum FsType {
    LinuxExt,
    LinuxXfs,
    Nfs,
    Other,
}

// return filesystem major type.
fn fstype(tp: &str) -> FsType {
    match tp {
        "ext2" | "ext3" | "ext4" => FsType::LinuxExt,
        "xfs" => FsType::LinuxXfs,
        "nfs" | "nfs4" => FsType::Nfs,
        _ => FsType::Other,
    }
}

// helper
fn u32_to_c_int(u: u32) -> c_int {
    let mut tmp: i64 = u as i64;
    if tmp >= 0x80000000 {
        tmp -= 0x100000000;
    }
    tmp as c_int
}

impl FsQuota {
    /// Get the used and available space for a specific user.
    pub fn user<P: AsRef<Path>>(uid: u32, path: P) -> Result<FsQuota, FqError> {
        let id = u32_to_c_int(uid);
        let path = path.as_ref();
        let meta = std::fs::symlink_metadata(path)?;

        // get all eligible entries.
        let ents = read_mtab()?
            .into_iter()
            .filter(|e| fstype(&e.fstype) != FsType::Other)
            .filter(|e| {
                match std::fs::metadata(&e.directory) {
                    Ok(ref m) => m.st_dev() == meta.st_dev(),
                    Err(_) => false,
                }
            })
            .collect::<Vec<Mtab>>();

        // 0 matches, error. 1 match, fine. >1 match, need to look closer.
        let entry = match ents.len() {
            0 => return Err(FqError::NoQuota),
            1 => ents[0].clone(),
            _ => {
                // multiple matching entries.. happens on NFS.

                // get "realpath" of the path that was passed in.
                let rp = match realpath(path) {
                    Ok(p) => p,
                    Err(e) => return Err(e.into()),
                };

                // realpath the remaining entries as well..
                let mut v = Vec::new();
                for mut e in ents.into_iter() {
                    match realpath(&e.directory) {
                        Ok(p) => {
                            let c = String::from_utf8_lossy(p.as_os_str().as_bytes());
                            e.directory = c.to_string();
                            v.push(e);
                        },
                        Err(_) => {},
                    }
                }
                if v.len() == 0 {
                    return Err(FqError::NoQuota);
                }

                // find longest match.
                v.sort_by_key(|e| e.directory.clone());
                v.reverse();
                match v.iter().position(|ref x| rp.starts_with(&x.directory)) {
                    Some(p) => v[p].clone(),
                    None => {
                        return Err(FqError::NoQuota);
                    },
                }
            },
        };

        let mut bytes_used = 0u64;
        let mut bytes_limit = 0u64;
        let mut files_used = 0u64;
        let mut files_limit = 0u64;

        // now do the filesystem-specific quota call.
        let fst = fstype(&entry.fstype);
        let rc = match fst {
            FsType::LinuxExt => {
                let path = CString::new(entry.device.as_bytes())?;
                unsafe {
                    fs_quota_linux_ext(
                        path.as_ptr(),
                        id,
                        0,
                        &mut bytes_used as *mut u64,
                        &mut bytes_limit as *mut u64,
                        &mut files_used as *mut u64,
                        &mut files_limit as *mut u64,
                    )
                }
            },
            FsType::LinuxXfs => {
                let path = CString::new(entry.device.as_bytes())?;
                unsafe {
                    fs_quota_linux_xfs(
                        path.as_ptr(),
                        id,
                        0,
                        &mut bytes_used as *mut u64,
                        &mut bytes_limit as *mut u64,
                        &mut files_used as *mut u64,
                        &mut files_limit as *mut u64,
                    )
                }
            },
            FsType::Nfs => {
                let host = CString::new(entry.host.unwrap().as_bytes())?;
                let path = CString::new(entry.device.as_bytes())?;
                let fstype = CString::new(entry.fstype.as_bytes())?;
                unsafe {
                    fs_quota_nfs(
                        host.as_ptr(),
                        path.as_ptr(),
                        fstype.as_ptr(),
                        id,
                        0,
                        &mut bytes_used as *mut u64,
                        &mut bytes_limit as *mut u64,
                        &mut files_used as *mut u64,
                        &mut files_limit as *mut u64,
                    )
                }
            },
            _ => unreachable!(),
        };

        // Error mapping.
        if rc != 0 {
            match fst {
                FsType::Nfs => {
                    match rc {
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
                        c @ 0x00100000...0x001fffff => {
                            let e = c & 0x000fffff;
                            debug!("nfs: clnt_call error: {}", clnt_sperrno(e));
                            return Err(FqError::Other);
                        },
                        e => {
                            debug!("nfs: unknown error {}", e);
                            return Err(FqError::Other);
                        },
                    }
                },
                _ => {
                    match rc {
                        1 => return Err(FqError::NoQuota),
                        _ => return Err(FqError::IoError(io::Error::last_os_error())),
                    }
                },
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

    /// Get used and available space for the user-id of the caller.
    pub fn check<P: AsRef<Path>>(path: P) -> Result<FsQuota, FqError> {
        let uid = unsafe { ffi::getuid() };
        FsQuota::user(uid, path)
    }

    /// Get used and available space systemwide. Usually one first tries
    /// to get the user-specific quota. If there isn't any then
    /// report the system-wide disk usage.
    ///
    /// FsQuota::check(path)
    ///     .or_else(|e| if e == FqError::NoQuota { FsQuota::system(path) } else { Err(e) })
    ///
    pub fn system<P: AsRef<Path>>(path: P) -> Result<FsQuota, FqError> {
        let vfs = statvfs(path).map_err(|e| FqError::IoError(e))?;
        Ok(FsQuota {
            bytes_used:  ((vfs.f_blocks - vfs.f_bfree) * vfs.f_bsize) as u64,
            bytes_limit: Some(((vfs.f_blocks - (vfs.f_bfree - vfs.f_bavail)) * vfs.f_bsize) as u64),
            files_used:  (vfs.f_files - vfs.f_ffree) as u64,
            files_limit: Some((vfs.f_files - (vfs.f_ffree - vfs.f_favail)) as u64),
        })
    }
}

impl From<io::Error> for FqError {
    fn from(e: io::Error) -> Self {
        FqError::IoError(e)
    }
}

impl From<std::ffi::NulError> for FqError {
    fn from(e: std::ffi::NulError) -> Self {
        FqError::IoError(e.into())
    }
}

fn to_num(e: &FqError) -> u32 {
    match e {
        &FqError::PermissionDenied => 1,
        &FqError::NoQuota => 2,
        &FqError::IoError(_) => 3,
        &FqError::Other => 4,
    }
}

impl PartialEq for FqError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            &FqError::IoError(ref e) => {
                if let &FqError::IoError(ref o) = other {
                    e.kind() == o.kind()
                } else {
                    false
                }
            },
            e => to_num(e) == to_num(other),
        }
    }
}
