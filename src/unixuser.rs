
use libc;
use libc::{getpwnam_r,getpwuid_r,c_char};
pub use libc::{uid_t,gid_t};

use std;
use std::path::{Path,PathBuf};
use std::ffi::{CStr,OsStr,OsString};
use std::os::unix::ffi::OsStrExt;

#[derive(Debug)]
pub struct Passwd {
    pub name:   String,
    pub passwd: OsString,
    pub gecos:  String,
    pub uid:    uid_t,
    pub gid:    gid_t,
    pub dir:    PathBuf,
    pub shell:  PathBuf,
}

unsafe fn cptr_to_osstr<'a>(c: *const c_char) -> &'a OsStr {
    let bytes = CStr::from_ptr(c).to_bytes();
    OsStr::from_bytes(&bytes)
}

unsafe fn cptr_to_path<'a>(c: *const c_char) -> &'a Path {
    Path::new(cptr_to_osstr(c))
}

unsafe fn to_passwd(pwd: &libc::passwd) -> Passwd {
    // turn into (unsafe!) rust slices
    let cs_name = CStr::from_ptr(pwd.pw_name);
    let cs_passwd = cptr_to_osstr(pwd.pw_passwd);
    let cs_gecos = CStr::from_ptr(pwd.pw_gecos);
    let cs_dir = cptr_to_path(pwd.pw_dir);
    let cs_shell = cptr_to_path(pwd.pw_shell);

    // then turn the slices into safe owned values.
    Passwd{
        name:   cs_name.to_string_lossy().into_owned(),
        passwd: cs_passwd.to_os_string(),
        gecos:  cs_gecos.to_string_lossy().into_owned(),
        dir:    cs_dir.to_path_buf(),
        shell:  cs_shell.to_path_buf(),
        uid:    pwd.pw_uid,
        gid:    pwd.pw_gid,
    }
}

pub fn getpwnam(name: &str) -> Result<Passwd, std::io::Error> {
    let mut buf = [0; 1024];
    let mut pwd: libc::passwd = unsafe {std::mem::zeroed()};
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let cname = match std::ffi::CString::new(name) {
        Ok(un) => un,
        Err(_) => return Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
    };
    let ret = unsafe {
        getpwnam_r(cname.as_ptr(), &mut pwd as *mut _,
                   buf.as_mut_ptr(),
                   buf.len() as libc::size_t,
                   &mut result as *mut _)
    };
    if ret == 0 {
        if result.is_null() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
        }
        let p = unsafe { to_passwd(&pwd) };
        Ok(p)
    } else {
        Err(std::io::Error::from_raw_os_error(ret))
    }
}

#[allow(dead_code)]
pub fn getpwuid(uid: uid_t) -> Result<Passwd, std::io::Error> {
    let mut buf = [0; 1024];
    let mut pwd: libc::passwd = unsafe {std::mem::zeroed()};
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let ret = unsafe {
        getpwuid_r(uid, &mut pwd as *mut _,
                   buf.as_mut_ptr(),
                   buf.len() as libc::size_t,
                   &mut result as *mut _)
    };
    if ret == 0 {
        if result.is_null() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
        }
        let p = unsafe { to_passwd(&pwd) };
        Ok(p)
    } else {
        Err(std::io::Error::from_raw_os_error(ret))
    }
}

