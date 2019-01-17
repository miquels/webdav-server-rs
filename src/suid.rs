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
    use super::{DROP_AUX_GROUPS, drop_aux_groups, last_os_error};

    /// Switch process credentials.
    #[allow(dead_code)]
    pub fn switch_ugid(from_uid: u32, to_uid: u32, gid: u32) {
        DROP_AUX_GROUPS.call_once(drop_aux_groups);
        unsafe {
            if libc::setresuid(from_uid as uid_t, 0, 0) != 0 {
                panic!("libc::setresuid({}, {}, 0): {:?}", from_uid, 0, last_os_error());
            }
            if libc::setgid(gid as gid_t) != 0 {
                panic!("libc::setgid({}): {:?}", gid, last_os_error());
            }
            if libc::setresuid(to_uid as uid_t, to_uid as uid_t, 0) != 0 {
                panic!("libc::setresuid({}, {}, 0): {:?}", to_uid, to_uid, last_os_error());
            }
        }
    }

    /// Switch thread credentials.
    pub fn thread_switch_ugid(from_uid: u32, to_uid: u32, gid: u32) {
        unsafe {
            if libc::syscall(SYS_setresuid, from_uid as uid_t, 0, 0) != 0 {
                panic!("syscall(SYS_setresuid, {}, {}, 0): {:?}", from_uid, 0, last_os_error());
            }
            if libc::syscall(SYS_setgid, gid as gid_t) != 0 {
                panic!("syscall(SYS_setgid, {}): {:?}", gid, last_os_error());
            }
            if libc::syscall(SYS_setresuid, to_uid as uid_t, to_uid as uid_t, 0) != 0 {
                panic!("syscall(SYS_setreuid, {}, {}, 0): {:?}", to_uid, to_uid, last_os_error());
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod setuid {
    use libc::{syscall, setreuid, setgid, uid_t, gid_t};
    use super::{DROP_AUX_GROUPS, drop_aux_groups, last_os_error};

    /// Switch process credentials.
    #[allow(dead_code)]
    pub fn switch_ugid(from_uid: u32, to_uid: u32, gid: u32) {
        DROP_AUX_GROUPS.call_once(drop_aux_groups);
        unsafe {
            if libc::setreuid(from_uid as uid_t, 0) != 0 {
                panic!("libc::setreuid({}, {}): {:?}", from_uid, 0, last_os_error());
            }
            if libc::setgid(gid as gid_t) != 0 {
                panic!("libc::setgid({}): {:?}", gid, last_os_error());
            }
            if libc::setreuid(from_uid as uid_t, to_uid as uid_t) != 0 {
                panic!("libc::setreuid({}, {}): {:?}", from_uid, to_uid, last_os_error());
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
    pub fn thread_switch_ugid(from_uid: u32, to_uid: u32, gid: u32) {
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

