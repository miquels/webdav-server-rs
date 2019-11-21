use std;
use std::ffi::{CStr, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use futures::future;
use tokio_executor::threadpool;

use libc;
use libc::{c_char, getpwnam_r, getpwuid_r};

#[derive(Debug)]
pub struct User {
    pub name:   String,
    pub passwd: String,
    pub gecos:  String,
    pub uid:    u32,
    pub gid:    u32,
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

unsafe fn to_passwd(pwd: &libc::passwd) -> User {
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
    }
}

// Run some code via tokio_executor::threadpool::blocking().
async fn blocking<F, T>(func: F) -> T
where F: FnOnce() -> T {
    let mut func = Some(func);
    let r = future::poll_fn(move |_cx| threadpool::blocking(|| (func.take().unwrap())())).await;
    match r {
        Ok(x) => x,
        Err(_) => panic!("the thread pool has shut down"),
    }
}

impl User {
    pub fn by_name(name: &str) -> Result<User, io::Error> {
        let mut buf = [0; 1024];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let cname = match std::ffi::CString::new(name) {
            Ok(un) => un,
            Err(_) => return Err(io::Error::from_raw_os_error(libc::ENOENT)),
        };
        let ret = unsafe {
            getpwnam_r(
                cname.as_ptr(),
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
            let p = unsafe { to_passwd(&pwd) };
            Ok(p)
        } else {
            Err(io::Error::from_raw_os_error(ret))
        }
    }

    #[allow(dead_code)]
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
            let p = unsafe { to_passwd(&pwd) };
            Ok(p)
        } else {
            Err(io::Error::from_raw_os_error(ret))
        }
    }

    pub async fn by_name_async(name: &str) -> Result<User, io::Error> {
        blocking(move || User::by_name(name)).await
    }
}
