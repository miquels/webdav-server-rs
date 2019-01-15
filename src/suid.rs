use std::io;
use libc::{syscall, SYS_setresuid, SYS_setresgid};

const UID_NONE: u32 = 0xffffffff;
const GID_NONE: u32 = 0xffffffff;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn thread_setresuid(real: Option<u32>, effective: Option<u32>, saved: Option<u32>) -> io::Result<()>
{
    let real = real.unwrap_or(UID_NONE);
    let effective = effective.unwrap_or(UID_NONE);
    let saved = saved.unwrap_or(UID_NONE);
    match unsafe { syscall(SYS_setresuid, real, effective, saved) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn thread_setresgid(real: Option<u32>, effective: Option<u32>, saved: Option<u32>) -> io::Result<()>
{
    let real = real.unwrap_or(GID_NONE);
    let effective = effective.unwrap_or(GID_NONE);
    let saved = saved.unwrap_or(GID_NONE);
    match unsafe { syscall(SYS_setresgid, real, effective, saved) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

