use std::io;
use libc::{syscall, SYS_setreuid, SYS_setregid};

const UID_NONE: u32 = 0xffffffff;
const GID_NONE: u32 = 0xffffffff;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn thread_setreuid(real: Option<u32>, effective: Option<u32>) -> io::Result<()>
{
    let real = real.unwrap_or(UID_NONE);
    let effective = effective.unwrap_or(UID_NONE);
    match unsafe { syscall(SYS_setreuid, real, effective) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn thread_setregid(real: Option<u32>, effective: Option<u32>) -> io::Result<()>
{
    let real = real.unwrap_or(GID_NONE);
    let effective = effective.unwrap_or(GID_NONE);
    match unsafe { syscall(SYS_setregid, real, effective) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

