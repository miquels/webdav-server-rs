use std::io;
use libc::{syscall, SYS_setreuid, SYS_setregid};

const UID_NONE: u32 = 0xffffffff;
const GID_NONE: u32 = 0xffffffff;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn thread_setreuid(real: Option<u32>, effective: Option<u32>) -> io::Result<()>
{
    let real = real.unwrap_or(UID_NONE);
    let effective = effective.unwrap_or(UID_NONE);
    match unsafe { syscall(SYS_setreuid, real, effective) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn thread_setregid(real: Option<u32>, effective: Option<u32>) -> io::Result<()>
{
    let real = real.unwrap_or(GID_NONE);
    let effective = effective.unwrap_or(GID_NONE);
    match unsafe { syscall(SYS_setregid, real, effective) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

// Switch UID using setreuid / setregid.
pub fn switch_uid(from_uid: u32, to_uid: u32, gid: u32) {
    // First, switch from uid/euid root/from_uid to uid/euid from_uid/root.
    if let Err(e) = thread_setreuid(Some(from_uid), Some(0)) {
        panic!("thread_setreuid({}, {}): {}", from_uid, 0, e);
    }
    // Now we're root, we can switch gids.
    if let Err(e) = thread_setregid(Some(gid), Some(gid)) {
        panic!("thread_setregid({}, {}): {}", gid, gid, e);
    }
    // Finally, switch from uid/euid from_uid/root to uid/euid root/to_uid.
    if let Err(e) = thread_setreuid(Some(0), Some(to_uid)) {
        panic!("thread_setreuid({}, {}): {}", 0, to_uid, e);
    }
}

