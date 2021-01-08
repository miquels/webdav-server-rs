#![cfg_attr(target_os = "windows", allow(unused_imports))]
use std;
use std::ffi::{CStr, OsStr};
use std::io;
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use {std::ffi::OsString, std::os::windows::prelude::*};
use std::path::{Path, PathBuf};

use tokio::task::block_in_place;

#[derive(Debug)]
pub struct User {
    pub name:   String,
    pub passwd: String,
    pub gecos:  String,
    pub uid:    u32,
    pub gid:    u32,
    pub groups: Vec<u32>,
    pub dir:    PathBuf,
    pub shell:  PathBuf,
}

#[cfg(not(target_os = "windows"))]
unsafe fn cptr_to_osstr<'a>(c: *const libc::c_char) -> &'a OsStr {
    let bytes = CStr::from_ptr(c).to_bytes();
    OsStr::from_bytes(&bytes)
}
#[cfg(target_os = "windows")]
unsafe fn cptr_to_osstr(c: *const libc::c_char) -> OsString {
    let bytes = CStr::from_ptr(c).to_bytes();
    OsString::from(String::from_utf8(bytes.to_vec()).unwrap())
}

#[cfg(not(target_os = "windows"))]
unsafe fn cptr_to_path<'a>(c: *const libc::c_char) -> &'a Path {
    Path::new(cptr_to_osstr(c))
}
#[cfg(target_os = "windows")]
unsafe fn cptr_to_path(c: *const libc::c_char) -> PathBuf {
    PathBuf::from(cptr_to_osstr(c))
}

#[cfg(not(target_os = "windows"))]
unsafe fn to_user(pwd: &libc::passwd) -> User {
    // turn into (unsafe!) rust slices
    let cs_name = CStr::from_ptr(pwd.pw_name);
    let cs_passwd = CStr::from_ptr(pwd.pw_passwd);
    let cs_gecos = CStr::from_ptr(pwd.pw_gecos);
    let cs_dir = cptr_to_path(pwd.pw_dir);
    let cs_shell = cptr_to_path(pwd.pw_shell);

    // then turn the slices into safe owned values.
    User {
        name:   cs_name.to_string_lossy().into_owned(),
        passwd: cs_passwd.to_string_lossy().into_owned(),
        gecos:  cs_gecos.to_string_lossy().into_owned(),
        dir:    cs_dir.to_path_buf(),
        shell:  cs_shell.to_path_buf(),
        uid:    pwd.pw_uid,
        gid:    pwd.pw_gid,
        groups: Vec::new(),
    }
}

#[cfg(not(target_os = "windows"))]
impl User {
    pub fn by_name(name: &str, with_groups: bool) -> Result<User, io::Error> {
        let mut buf = [0u8; 1024];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let cname = match std::ffi::CString::new(name) {
            Ok(un) => un,
            Err(_) => return Err(io::Error::from_raw_os_error(libc::ENOENT)),
        };
        let ret = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd as *mut _,
                buf.as_mut_ptr() as *mut _,
                buf.len() as libc::size_t,
                &mut result as *mut _,
            )
        };

        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret));
        }
        if result.is_null() {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let mut user = unsafe { to_user(&pwd) };

        if with_groups {
            let mut ngroups = (buf.len() / std::mem::size_of::<libc::gid_t>()) as libc::c_int;
            let ret = unsafe {
                libc::getgrouplist(
                    cname.as_ptr(),
                    user.gid as i32 /* as libc::gid_t */,
                    buf.as_mut_ptr() as *mut _,
                    &mut ngroups as *mut _,
                )
            };
            if ret >= 0 && ngroups > 0 {
                let mut groups_vec = Vec::with_capacity(ngroups as usize);
                let groups = unsafe {
                    std::slice::from_raw_parts(buf.as_ptr() as *const libc::gid_t, ngroups as usize)
                };
                //
                // Only supplementary or auxilary groups, filter out primary.
                //
                groups_vec.extend(groups.iter().map(|&g| g as u32).filter(|&g| g != user.gid));
                user.groups = groups_vec;
            }
        }

        Ok(user)
    }

    /*
    pub fn by_uid(uid: u32) -> Result<User, io::Error> {
        let mut buf = [0; 1024];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let ret = unsafe {
            getpwuid_r(
                uid,
                &mut pwd as *mut _,
                buf.as_mut_ptr(),
                buf.len() as libc::size_t,
                &mut result as *mut _,
            )
        };
        if ret == 0 {
            if result.is_null() {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            let p = unsafe { to_user(&pwd) };
            Ok(p)
        } else {
            Err(io::Error::from_raw_os_error(ret))
        }
    }
    */

    pub async fn by_name_async(name: &str, with_groups: bool) -> Result<User, io::Error> {
        block_in_place(move || User::by_name(name, with_groups))
    }
}
