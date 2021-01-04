use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static THREAD_SWITCH_UGID_USED: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_os = "linux"))]
mod setuid {
    // On x86, the default SYS_setresuid is 16 bits. We need to
    // import the 32-bit variant.
    #[cfg(target_arch = "x86")]
    mod uid32 {
        pub use libc::SYS_getgroups32 as SYS_getgroups;
        pub use libc::SYS_setgroups32 as SYS_setgroups;
        pub use libc::SYS_setresgid32 as SYS_setresgid;
        pub use libc::SYS_setresuid32 as SYS_setresuid;
    }
    #[cfg(not(target_arch = "x86"))]
    mod uid32 {
        pub use libc::{SYS_getgroups, SYS_setgroups, SYS_setresgid, SYS_setresuid};
    }
    use self::uid32::*;
    use std::cell::RefCell;
    use std::convert::TryInto;
    use std::io;
    use std::sync::atomic::Ordering;
    const ID_NONE: libc::uid_t = 0xffffffff;

    // current credentials of this thread.
    struct UgidState {
        ruid:   u32,
        euid:   u32,
        rgid:   u32,
        egid:   u32,
        groups: Vec<u32>,
    }

    impl UgidState {
        fn new() -> UgidState {
            super::THREAD_SWITCH_UGID_USED.store(true, Ordering::Release);
            UgidState {
                ruid:   unsafe { libc::getuid() } as u32,
                euid:   unsafe { libc::geteuid() } as u32,
                rgid:   unsafe { libc::getgid() } as u32,
                egid:   unsafe { libc::getegid() } as u32,
                groups: getgroups().expect("UgidState::new"),
            }
        }
    }

    fn getgroups() -> io::Result<Vec<u32>> {
        // get number of groups.
        let size = unsafe {
            libc::syscall(
                SYS_getgroups,
                0 as libc::c_int,
                std::ptr::null_mut::<libc::gid_t>(),
            )
        };
        if size < 0 {
            return Err(oserr(size, "getgroups(0, NULL)"));
        }

        // get groups.
        let mut groups = Vec::<u32>::with_capacity(size as usize);
        groups.resize(size as usize, 0);
        let res = unsafe { libc::syscall(SYS_getgroups, size as libc::c_int, groups.as_mut_ptr() as *mut _) };

        // sanity check.
        if res != size {
            if res < 0 {
                return Err(oserr(res, format!("getgroups({}, buffer)", size)));
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("getgroups({}, buffer): returned {}", size, res),
            ));
        }

        Ok(groups)
    }

    fn oserr(code: libc::c_long, msg: impl AsRef<str>) -> io::Error {
        let msg = msg.as_ref();
        let err = io::Error::from_raw_os_error(code.try_into().unwrap());
        io::Error::new(err.kind(), format!("{}: {}", msg, err))
    }

    // thread-local seteuid.
    fn seteuid(uid: u32) -> io::Result<()> {
        let res = unsafe { libc::syscall(SYS_setresuid, ID_NONE, uid, ID_NONE) };
        if res < 0 {
            return Err(oserr(res, format!("seteuid({})", uid)));
        }
        Ok(())
    }

    // thread-local setegid.
    fn setegid(gid: u32) -> io::Result<()> {
        let res = unsafe { libc::syscall(SYS_setresgid, ID_NONE, gid, ID_NONE) };
        if res < 0 {
            return Err(oserr(res, format!("setegid({})", gid)));
        }
        Ok(())
    }

    // thread-local setgroups.
    fn setgroups(gids: &[u32]) -> io::Result<()> {
        let size = gids.len() as libc::c_int;
        let res = unsafe { libc::syscall(SYS_setgroups, size, gids.as_ptr() as *const libc::gid_t) };
        if res < 0 {
            return Err(oserr(res, format!("setgroups({}, {:?}", size, gids)));
        }
        Ok(())
    }

    // credential state is thread-local.
    thread_local!(static CURRENT_UGID: RefCell<UgidState> = RefCell::new(UgidState::new()));

    /// Switch thread credentials.
    pub(super) fn thread_switch_ugid(newuid: u32, newgid: u32, newgroups: &[u32]) -> (u32, u32, Vec<u32>) {
        CURRENT_UGID.with(|current_ugid| {
            let mut cur = current_ugid.borrow_mut();
            let (olduid, oldgid, oldgroups) = (cur.euid, cur.egid, cur.groups.clone());
            let groups_changed = newgroups != cur.groups.as_slice();

            // Check if anything changed.
            if newuid != cur.euid || newgid != cur.egid || groups_changed {
                // See if we have to switch to root privs first.
                if cur.euid != 0 && (newuid != cur.ruid || newgid != cur.rgid || groups_changed) {
                    // Must first switch to root.
                    if let Err(e) = seteuid(0) {
                        panic!("{}", e);
                    }
                    cur.euid = 0;
                }

                if newgid != cur.egid {
                    // Change gid.
                    if let Err(e) = setegid(newgid) {
                        panic!("{}", e);
                    }
                    cur.egid = newgid;
                }
                if groups_changed {
                    // Change groups.
                    if let Err(e) = setgroups(newgroups) {
                        panic!("{}", e);
                    }
                    cur.groups.truncate(0);
                    cur.groups.extend_from_slice(newgroups);
                }
                if newuid != cur.euid {
                    // Change uid.
                    if let Err(e) = seteuid(newuid) {
                        panic!("{}", e);
                    }
                    cur.euid = newuid;
                }
            }
            (olduid, oldgid, oldgroups)
        })
    }

    // Yep..
    pub fn has_thread_switch_ugid() -> bool {
        true
    }
}

#[cfg(not(target_os = "linux"))]
mod setuid {
    // Not implemented, as it looks like only Linux has support for
    // per-thread uid/gid switching.
    //
    // DO NOT implement this through libc::setuid, as that will
    // switch the uids of all threads.
    //
    /// Switch thread credentials. Not implemented!
    pub(super) fn thread_switch_ugid(_newuid: u32, _newgid: u32, _newgroups: &[u32]) -> (u32, u32, Vec<u32>) {
        unimplemented!();
    }

    // Nope.
    pub fn has_thread_switch_ugid() -> bool {
        false
    }
}

pub use self::setuid::has_thread_switch_ugid;
use self::setuid::thread_switch_ugid;

#[derive(Clone, Debug)]
struct UgidCreds {
    pub uid:    u32,
    pub gid:    u32,
    pub groups: Vec<u32>,
}

pub struct UgidSwitch {
    target_creds: Option<UgidCreds>,
}

pub struct UgidSwitchGuard {
    base_creds: Option<UgidCreds>,
}

impl UgidSwitch {
    pub fn new(creds: Option<(u32, u32, &[u32])>) -> UgidSwitch {
        let target_creds = match creds {
            Some((uid, gid, groups)) => {
                Some(UgidCreds {
                    uid,
                    gid,
                    groups: groups.into(),
                })
            },
            None => None,
        };
        UgidSwitch { target_creds }
    }

    #[allow(dead_code)]
    pub fn run<F, R>(&self, func: F) -> R
    where F: FnOnce() -> R {
        let _guard = self.guard();
        func()
    }

    pub fn guard(&self) -> UgidSwitchGuard {
        match &self.target_creds {
            &None => UgidSwitchGuard { base_creds: None },
            &Some(ref creds) => {
                let (uid, gid, groups) = thread_switch_ugid(creds.uid, creds.gid, &creds.groups);
                UgidSwitchGuard {
                    base_creds: Some(UgidCreds { uid, gid, groups }),
                }
            },
        }
    }
}

impl Drop for UgidSwitchGuard {
    fn drop(&mut self) {
        if let Some(ref creds) = self.base_creds {
            thread_switch_ugid(creds.uid, creds.gid, &creds.groups);
        }
    }
}

/// Switch process credentials. Keeps the saved-uid as root, so that
/// we can switch to other ids later on.
pub fn proc_switch_ugid(uid: u32, gid: u32, keep_privs: bool) {
    if THREAD_SWITCH_UGID_USED.load(Ordering::Acquire) {
        panic!("proc_switch_ugid: called after thread_switch_ugid() has been used");
    }

    fn last_os_error() -> io::Error {
        io::Error::last_os_error()
    }

    unsafe {
        // first get full root privs (real, effective, and saved uids)
        if libc::setuid(0) != 0 {
            panic!("libc::setuid(0): {:?}", last_os_error());
        }

        // set real uid, and keep effective uid at 0.
        //#[cfg(not(any(target_os = "openbsd", target_os = "freebsd")))]
        // if libc::setreuid(uid, 0) != 0 {
        //     panic!("libc::setreuid({}, 0): {:?}", uid, last_os_error());
        // }
        #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
        if libc::setresuid(uid, 0, 0) != 0 {
            panic!("libc::setreuid({}, 0): {:?}", uid, last_os_error());
        }

        // set group id.
        if libc::setgid(gid) != 0 {
            panic!("libc::setgid({}): {:?}", gid, last_os_error());
        }

        // remove _all_ auxilary groups.
        if libc::setgroups(0, std::ptr::null::<libc::gid_t>()) != 0 {
            panic!("setgroups[]: {:?}", last_os_error());
        }

        if keep_privs {
            // finally set effective uid. saved uid is still 0.
            if libc::seteuid(uid) != 0 {
                panic!("libc::seteuid({}): {:?}", uid, last_os_error());
            }
        } else {
            // drop all privs.
            if libc::setuid(uid) != 0 {
                panic!("libc::setuid({}): {:?}", uid, last_os_error());
            }
        }
    }
}

/// Do we have sufficient privs to switch uids?
pub fn have_suid_privs() -> bool {
    unsafe { libc::geteuid() == 0 }
}
