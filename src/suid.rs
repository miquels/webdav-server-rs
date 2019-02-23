use std::io;
use std::sync::Once;

static DROP_AUX_GROUPS: Once = Once::new();

fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

#[cfg(all(target_os = "linux"))]
mod setuid {
    #[cfg(target_arch = "x86")]
    mod uid32 {
        pub use libc::SYS_setresuid32 as SYS_setresuid;
        pub use libc::SYS_setresgid32 as SYS_setresgid;
    }
    #[cfg(not(target_arch = "x86"))]
    mod uid32 {
        pub use libc::{SYS_setresuid, SYS_setresgid};
    }
    use libc::{uid_t, gid_t, SYS_setgid};
    use self::uid32::*;
    use std::cell::RefCell;
    use super::{DROP_AUX_GROUPS, drop_aux_groups, last_os_error};
    const NONE: uid_t = 0xffffffff;

    thread_local!(static CURRENT_UGID: RefCell<(u32, u32)> = RefCell::new((NONE, NONE)));

    /// Switch process credentials.
    #[allow(dead_code)]
    pub fn switch_ugid(uid: u32, gid: u32) {
        DROP_AUX_GROUPS.call_once(drop_aux_groups);
        CURRENT_UGID.with(|cur| {
            let (cur_uid, cur_gid) = *cur.borrow();
            if uid != cur_uid || gid != cur_gid {
                unsafe {
                    if libc::setresuid(NONE, 0, NONE) != 0 {
                        panic!("libc::setresuid(-1, 0, -1): {:?}", last_os_error());
                    }
                    if libc::setgid(gid as gid_t) != 0 {
                        panic!("libc::setgid({}): {:?}", gid, last_os_error());
                    }
                    if libc::setresuid(uid as uid_t, uid as uid_t, 0) != 0 {
                        panic!("libc::setresuid({}, {}, 0): {:?}", uid, uid, last_os_error());
                    }
                }
                *cur.borrow_mut() = (uid, gid);
            }
        }
    }

    /// Switch thread credentials.
    pub fn thread_switch_ugid(uid: u32, gid: u32) {
        unsafe {
            if libc::syscall(SYS_setresuid, NONE, 0, NONE) != 0 {
                panic!("syscall(SYS_setresuid, -1, 0, -1): {:?}", last_os_error());
            }
            if libc::syscall(SYS_setgid, gid as gid_t) != 0 {
                panic!("syscall(SYS_setgid, {}): {:?}", gid, last_os_error());
            }
            if libc::syscall(SYS_setresuid, uid as uid_t, uid as uid_t, 0) != 0 {
                panic!("syscall(SYS_setreuid, {}, {}, 0): {:?}", uid, uid, last_os_error());
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod setuid {
    use libc::{syscall, setreuid, setgid, uid_t, gid_t};
    use super::{DROP_AUX_GROUPS, drop_aux_groups, last_os_error};
    const NONE: uid_t = 0xffffffff;

    /// Switch process credentials.
    #[allow(dead_code)]
    pub fn switch_ugid(uid: u32, gid: u32) {
        DROP_AUX_GROUPS.call_once(drop_aux_groups);
        unsafe {
            if libc::setreuid(NONE, 0) != 0 {
                panic!("libc::setreuid(-1, 0): {:?}", last_os_error());
            }
            if libc::setgid(gid as gid_t) != 0 {
                panic!("libc::setgid({}): {:?}", gid, last_os_error());
            }
            if libc::setreuid(0, uid as uid_t) != 0 {
                panic!("libc::setreuid(0, {}): {:?}", uid, last_os_error());
            }
        }
    }

    // Not implemented, as it looks like only Linux has support for
    // per-thread uid/gid switching.
    //
    // DO NOT implement this through libc::setuid, as that will probably
    // switch the uids of all threads.
    //
    /// Switch thread credentials. Not implemented!
    pub fn thread_switch_ugid(uid: u32, gid: u32) {
        unimplemented!();
    }
}

pub use self::setuid::{switch_ugid, thread_switch_ugid};

/// Set uid/gid to a non-root value. Final, can not switch back to root
/// or to any other id when this is done.
#[allow(dead_code)]
pub fn set_ugid(uid: u32, gid: u32) {
    DROP_AUX_GROUPS.call_once(drop_aux_groups);
    unsafe {
        if libc::setuid(0) != 0 {
            panic!("libc::setuid(0): {:?}", last_os_error());
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            panic!("libc::setgid({}): {:?}", gid, last_os_error());
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            panic!("libc::setuid({}): {:?}", uid, last_os_error());
        }
    }
}

// Drop all auxilary groups.
fn drop_aux_groups() {
    unsafe {
        let gid = libc::getegid();
        if libc::setgroups(1, &gid as *const libc::gid_t) != 0 {
            panic!("libc::setgroups(1, &{}): {:?}", gid, last_os_error());
        }
    }
}

