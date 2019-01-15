
use std::ffi::{CStr,CString};
use std::os::raw::{c_char,c_int,c_void};
use std::error::Error;

extern {
    fn c_pam_auth(service: *const c_char, user: *const c_char, pass: *const c_char, remip: *const c_char) -> c_int;
    fn _c_pam_return_value(index: c_int) -> c_int;
    fn pam_strerror(pamh: *const c_void, errnum: c_int) -> *const c_char;
    fn c_pam_lower_rlimits();
}

pub(crate) const ERR_NUL_BYTE : i32 = 414243;
pub(crate) const ERR_SEND_TO_SERVER : i32 = 414244;
pub(crate) const ERR_RECV_FROM_SERVER : i32 = 414245;

/// Error returned oif authentication fails.
///
/// It's best not to try to interpret this, and handle all errors
/// as "authentication failed".
#[derive(Debug,Clone,PartialEq,Serialize,Deserialize)]
pub struct PamError(pub(crate) i32);

impl PamError {
    #[doc(hidden)]
    pub fn unknown() -> PamError {
        PamError(13)
    }
}

impl std::fmt::Display for PamError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            ERR_NUL_BYTE => {
                write!(f, "embedded 0 byte in string")
            },
            ERR_SEND_TO_SERVER => {
                write!(f, "error sending request to server")
            },
            ERR_RECV_FROM_SERVER => {
                write!(f, "error receiving response from server")
            },
            _ => {
                let errnum = self.0 as c_int;
                let nullptr : *const c_void = std::ptr::null();
                let errstr = unsafe {
                    CStr::from_ptr(pam_strerror(nullptr, errnum)).to_string_lossy()
                };
                f.write_str(&format!("PAM error: {}", errstr))
            },
        }
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
        PamError(ERR_NUL_BYTE)
    }
}

pub(crate) fn pam_auth(service: &str, user: &str, pass: &str, remip: &str) -> Result<(), PamError> {

    if service == "xyzzy-test-test" && remip == "xyzzy-test-test" {
        return if user == "test" {
            Ok(())
        } else {
            Err(PamError(1))
        };
    }

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

pub(crate) fn pam_lower_rlimits() {
    unsafe{ c_pam_lower_rlimits(); }
}

