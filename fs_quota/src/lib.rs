#![doc(html_root_url = "https://docs.rs/fs-quota/0.1.0")]
//! Get filesystem disk space used and available for a unix user.
//!
//! This crate has support for:
//!
//! - Linux ext2/ext3/ext4 quotas
//! - Linux XFS quotas
//! - NFS quotas (via SUNRPC).
//! - `libc::vfsstat` lookups (like `df`).
//!
//! The linux ext2/ext3/ext4/xfs quota support only works on linux, not
//! on non-linux systems with ext4 or xfs support. The `vfsstat` is also
//! system dependant and, at the moment, only implemented for linux.
//!
//! NFS quota support can be left out by disabling the `nfs` feature.
//!
//! Example application:
//! ```no_run
//! use fs_quota::*;
//!
//! fn main() {
//!     let args: Vec<String> = std::env::args().collect();
//!     if args.len() < 2 {
//!         println!("usage: fs_quota <path>");
//!         return;
//!     }
//!     println!("{:#?}", FsQuota::check(&args[1], None));
//! }
//! ```
#[macro_use]
extern crate log;
extern crate libc;

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[cfg(feature = "nfs")]
mod quota_nfs;

// Linux specific code lives in linux.rs.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::{get_quota, read_mtab, statvfs};

// Unsupported OS.
#[cfg(not(target_os = "linux"))]
mod generic_os;
#[cfg(not(target_os = "linux"))]
use generic_os::{get_quota, read_mtab, statvfs};

#[derive(Debug, PartialEq)]
pub(crate) enum FsType {
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

/// quota / vfsstat lookup result.
#[derive(Debug)]
pub struct FsQuota {
    /// number of bytes used.
    pub bytes_used:  u64,
    /// maximum number of bytes (available - used).
    pub bytes_limit: Option<u64>,
    /// number of files (inodes) in use.
    pub files_used:  u64,
    /// maximum number of files (available - used).
    pub files_limit: Option<u64>,
}

/// Error result.
#[derive(Debug)]
pub enum FqError {
    /// Permission denied.
    PermissionDenied,
    /// Filesystem does not have quotas enabled.
    NoQuota,
    /// An I/O error occured.
    IoError(io::Error),
    /// Some other error.
    Other,
}

impl FsQuota {
    /// Get the filesystem quota for a `uid` on the filesystem where `path` is on.
    ///
    /// If `uid` is `None`, get it for the current real user-id.
    pub fn user(path: impl AsRef<Path>, uid: Option<u32>) -> Result<FsQuota, FqError> {
        let id = uid.unwrap_or(unsafe { libc::getuid() as u32 });
        let entry = get_mtab_entry(path)?;

        #[cfg(feature = "nfs")]
        {
            let fst = fstype(&entry.fstype);
            if fst == FsType::Nfs {
                return quota_nfs::get_quota(&entry, id);
            }
        }

        get_quota(&entry.device, id)
    }

    /// Get used and available disk space of the filesystem indicated by `path`.
    ///
    /// This is not really a quota call; it simply calls `libc::vfsstat` (`df`).
    pub fn system(path: impl AsRef<Path>) -> Result<FsQuota, FqError> {
        statvfs(path)
    }

    /// Lookup used and available disk space for a `uid`. First check user's quota,
    /// if quotas are not enabled check the filesystem disk space usage.
    ///
    /// This is the equivalent of
    ///
    /// ```no_run
    /// # let path = "/";
    /// # let uid = None;
    /// # use fs_quota::*;
    /// FsQuota::user(path, uid)
    ///     .or_else(|e| if e == FqError::NoQuota { FsQuota::system(path) } else { Err(e) })
    /// # ;
    /// ```
    ///
    pub fn check(path: impl AsRef<Path>, uid: Option<u32>) -> Result<FsQuota, FqError> {
        let path = path.as_ref();
        FsQuota::user(path, uid)
            .or_else(|e| if e == FqError::NoQuota { FsQuota::system(path) } else { Err(e) })
    }

}

// The libc realpath() function.
fn realpath<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
    let cpath = CString::new(path.as_ref().as_os_str().as_bytes())?;
    let nullptr: *mut c_char = std::ptr::null_mut();
    unsafe {
        let r = libc::realpath(cpath.as_ptr(), nullptr);
        if r == nullptr {
            Err(io::Error::last_os_error())
        } else {
            let osstr = OsStr::from_bytes(CStr::from_ptr(r).to_bytes());
            let p = PathBuf::from(osstr);
            libc::free(r as *mut libc::c_void);
            Ok(p)
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Mtab {
    host:      Option<String>,
    device:    String,
    directory: String,
    fstype:    String,
}

// find an entry in the mtab.
fn get_mtab_entry(path: impl AsRef<Path>) -> Result<Mtab, FqError> {
    let path = path.as_ref();
    let meta = std::fs::symlink_metadata(path)?;

    // get all eligible entries.
    let ents = read_mtab()?
        .into_iter()
        .filter(|e| fstype(&e.fstype) != FsType::Other)
        .filter(|e| {
            match std::fs::metadata(&e.directory) {
                Ok(ref m) => m.dev() == meta.dev(),
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
    Ok(entry)
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
