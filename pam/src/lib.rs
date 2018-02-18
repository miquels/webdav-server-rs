
#[macro_use] extern crate log;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate bincode;
extern crate unix_socket;
extern crate libc;

use std::ffi::{CStr,CString};
use std::os::raw::{c_char,c_int,c_void};
use std::error::Error;

mod fpc;

extern {
    fn c_pam_auth(service: *const c_char, user: *const c_char, pass: *const c_char, remip: *const c_char) -> c_int;
    fn _c_pam_return_value(index: c_int) -> c_int;
    fn pam_strerror(pamh: *const c_void, errnum: c_int) -> *const c_char;
    fn c_pam_lower_rlimits();
}

#[derive(Debug,Clone,PartialEq,Serialize,Deserialize)]
pub struct PamError(c_int);

#[derive(Debug,Clone,PartialEq,Serialize,Deserialize)]
struct PamRequest {
    service:    String,
    user:       String,
    pass:       String,
    remip:      String,
}

static mut PAM_FPC : Option<fpc::Fpc> = None;

pub fn init_worker() {
    unsafe {
        PAM_FPC = Some(fpc::Fpc::new(pam_server).unwrap());
    }
}

pub fn auth(service: &str, user: &str, pass: &str, remip: &str) -> Result<(), PamError> {
    let fpc = unsafe { PAM_FPC.clone() };
    if let Some(fpc) = fpc {
        debug!("sending fpc auth request for {}", user);
        let req = PamRequest{
            service: service.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            remip: remip.to_string(),
        };
        return match fpc.call(req) {
            Ok(r) => r,
            Err(e) => {
                error!("fpc.call() returned {}", e);
                Err(PamError(31339))
            },
        };
    }
    pam_auth(service, user, pass, remip)
}

fn pam_server(srv: &fpc::FpcServer) {
    unsafe { c_pam_lower_rlimits(); }
    let mut v = Vec::new();
    for _ in 0..16 {
        let s = srv.clone();
        v.push(std::thread::spawn(move || {
            loop {
                let (id, req) = match s.read_request::<PamRequest>() {
                    Err(_) => return,
                    Ok(r) => r,
                };
                let res = pam_auth(&req.service, &req.user, &req.pass, &req.remip);
                s.send_response(id, res).ok();
            }
        }));
    }
    drop(srv);
    v.into_iter().for_each(|t| { t.join().ok(); });
}

fn pam_auth(service: &str, user: &str, pass: &str, remip: &str) -> Result<(), PamError> {
    let c_service = CString::new(service)?;
    let c_user = CString::new(user)?;
    let c_pass = CString::new(pass)?;
    let c_remip = CString::new(remip)?;
    let ret = unsafe {
        c_pam_auth(c_service.as_ptr(), c_user.as_ptr(),
                    c_pass.as_ptr(), c_remip.as_ptr())
    };
    match ret {
        0 => Ok(()),
        errnum => Err(PamError(errnum)),
    }
}

impl std::fmt::Display for PamError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.0 == 414243 {
            return write!(f, "embedded 0 byte in string");
        }
        let errnum = self.0 as c_int;
        let nullptr : *const c_void = std::ptr::null();
        let errstr = unsafe {
            CStr::from_ptr(pam_strerror(nullptr, errnum)).to_string_lossy()
        };
        f.write_str(&format!("PAM error: {}", errstr))
    }
}

impl Error for PamError {
    fn description(&self) -> &str {
        "PAM authentication error"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl From<std::ffi::NulError> for PamError {
    fn from(_e: std::ffi::NulError) -> Self {
        PamError(414243)
    }
}

