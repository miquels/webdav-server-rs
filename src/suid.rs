use std::io;
use std::sync::Once;

static DROP_AUX_GROUPS: Once = Once::new();

// helper.
fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

#[cfg(all(target_os = "linux"))]
mod setuid {
    // On x86, the default SYS_setresuid is 16 bits. We need to
    // import the 32-bit variant.
    #[cfg(target_arch = "x86")]
    mod uid32 {
        pub use libc::SYS_setregid32 as SYS_setregid;
        pub use libc::SYS_setresuid32 as SYS_setresuid;
    }
    #[cfg(not(target_arch = "x86"))]
    mod uid32 {
        pub use libc::{SYS_setregid, SYS_setresuid};
    }
    use self::uid32::*;
    use super::{drop_aux_groups, last_os_error, DROP_AUX_GROUPS};
    use libc::{gid_t, uid_t};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const ID_NONE: uid_t = 0xffffffff;

    static THREAD_SWITCH_UGID_USED: AtomicUsize = AtomicUsize::new(0);

    /// Switch process credentials. Keeps the saved-uid as root, so that
    /// we can switch to other ids later on.
    #[allow(dead_code)]
    pub fn switch_ugid(uid: u32, gid: u32) {
        if THREAD_SWITCH_UGID_USED.load(Ordering::SeqCst) > 0 {
            panic!("switch_ugid: called after thread_switch_ugid() has been used");
        }
        DROP_AUX_GROUPS.call_once(drop_aux_groups);
        unsafe {
            if libc::setresuid(ID_NONE, 0, ID_NONE) != 0 {
                panic!("libc::setresuid(-1, 0, -1): {:?}", last_os_error());
            }
            if libc::setgid(gid as gid_t) != 0 {
                panic!("libc::setgid({}): {:?}", gid, last_os_error());
            }
            if libc::setresuid(uid as uid_t, uid as uid_t, 0) != 0 {
                panic!("libc::setresuid({}, {}, 0): {:?}", uid, uid, last_os_error());
            }
        }
    }

    // we remember the state of
    struct UgidState {
        ruid: u32,
        euid: u32,
        rgid: u32,
        egid: u32,
    }
    impl UgidState {
        fn new() -> UgidState {
            THREAD_SWITCH_UGID_USED.store(1, Ordering::SeqCst);
            UgidState {
                ruid: unsafe { libc::getuid() } as u32,
                euid: unsafe { libc::geteuid() } as u32,
                rgid: unsafe { libc::getgid() } as u32,
                egid: unsafe { libc::getegid() } as u32,
            }
        }
    }
    thread_local!(static CURRENT_UGID: RefCell<UgidState> = RefCell::new(UgidState::new()));

    /// Switch thread credentials.
    pub fn thread_switch_ugid(newuid: u32, newgid: u32) -> (u32, u32) {
        CURRENT_UGID.with(|current_ugid| {
            // Only switch if we need to.
            let cur = current_ugid.borrow();
            let (olduid, oldgid) = (cur.euid, cur.egid);
            if newuid != cur.euid || newgid != cur.egid {
                unsafe {
                    if cur.euid != 0 && (newuid != cur.ruid || newgid != cur.rgid) {
                        // Must first switch to root.
                        if libc::syscall(SYS_setresuid, ID_NONE, 0, ID_NONE) != 0 {
                            panic!("syscall(SYS_setresuid, -1, 0, -1): {:?}", last_os_error());
                        }
                    }
                    if newgid != cur.egid {
                        // Change gid.
                        if libc::syscall(SYS_setregid, cur.egid as gid_t, newgid as gid_t) != 0 {
                            panic!(
                                "syscall(SYS_setregid, {}, {}): {:?}",
                                cur.egid,
                                newgid,
                                last_os_error()
                            );
                        }
                    }
                    if newuid != cur.euid {
                        // Change uid.
                        if libc::syscall(SYS_setresuid, cur.euid as uid_t, newuid as uid_t, 0) != 0 {
                            panic!(
                                "syscall(SYS_setresuid, {}, {}, 0): {:?}",
                                cur.euid,
                                newuid,
                                last_os_error()
                            );
                        }
                    }
                }
                // save the new state.
                let new_ugid = UgidState {
                    ruid: cur.euid,
                    euid: newuid,
                    rgid: cur.egid,
                    egid: newgid,
                };
                drop(cur);
                *current_ugid.borrow_mut() = new_ugid;
            }
            (olduid, oldgid)
        })
    }

    // Yup.
    pub fn has_thread_switch_ugid() -> bool {
        true
    }
}

#[cfg(not(target_os = "linux"))]
mod setuid {
    use super::{drop_aux_groups, last_os_error, DROP_AUX_GROUPS};
    use libc::{gid_t, uid_t};

    /// Switch process credentials.
    #[allow(dead_code)]
    pub fn switch_ugid(uid: u32, gid: u32) {
        DROP_AUX_GROUPS.call_once(drop_aux_groups);
        unsafe {
            if libc::setuid(0) != 0 {
                panic!("libc::setuid(0): {:?}", last_os_error());
            }
            if libc::setgid(gid as gid_t) != 0 {
                panic!("libc::setgid({}): {:?}", gid, last_os_error());
            }
            if libc::setresuid(uid as uid_t, uid as uid_t, 0) != 0 {
                panic!("libc::setreuid({}, {}, 0): {:?}", uid, uid, last_os_error());
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
    pub fn thread_switch_ugid(_uid: u32, _gid: u32) -> (u32, u32) {
        unimplemented!();
    }

    // Nope.
    pub fn has_thread_switch_ugid() -> bool {
        false
    }
}

pub use self::setuid::{has_thread_switch_ugid, switch_ugid, thread_switch_ugid};

#[derive(Clone, Debug)]
pub struct UgidSwitch {
    target_ugid: Option<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct UgidSwitchGuard {
    base_ugid: Option<(u32, u32)>,
}

impl UgidSwitch {
    pub fn new(target_ugid: Option<(u32, u32)>) -> UgidSwitch {
        UgidSwitch {
            target_ugid: target_ugid,
        }
    }

    #[allow(dead_code)]
    pub fn run<F, R>(&self, func: F) -> R
    where F: FnOnce() -> R {
        let _guard = self.guard();
        func()
    }

    pub fn guard(&self) -> UgidSwitchGuard {
        match self.target_ugid {
            None => UgidSwitchGuard { base_ugid: None },
            Some((target_uid, target_gid)) => {
                let (base_uid, base_gid) = thread_switch_ugid(target_uid, target_gid);
                UgidSwitchGuard {
                    base_ugid: Some((base_uid, base_gid)),
                }
            },
        }
    }
}

impl Drop for UgidSwitchGuard {
    fn drop(&mut self) {
        if let Some((base_uid, base_gid)) = self.base_ugid {
            thread_switch_ugid(base_uid, base_gid);
        }
    }
}

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
