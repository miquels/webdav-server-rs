use std::io;
use socket2::Socket;

#[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
pub fn set_congestion_control(_sock: &Socket, _algo: &str) -> io::Result<()> {
    return Err(io::Error::new(io::ErrorKind::InvalidInput, "not implemented"));
}

#[cfg(target_os = "linux")]
pub fn set_congestion_control(sock: &Socket, algo: &str) -> io::Result<()> {
    sock.set_tcp_congestion(algo.as_bytes())
}

#[cfg(target_os = "freebsd")]
pub fn set_congestion_control(sock: &Socket, algo: &str) -> io::Result<()> {
    match algo {
        "bbr" => set_tcp_functions(sock, algo)?,
        "rack" => set_tcp_functions(sock, algo)?,
        _ => {
            set_tcp_functions(sock, "freebsd")?;
            sock.set_tcp_congestion(algo.as_bytes())?;
        },
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn set_tcp_functions(sock: &Socket, funcs: &str) -> io::Result<()> {
    const TCP_FUNCTION_BLK: libc::c_int = 8192;
    let slen = funcs.len();
    if slen >= libc::TCP_FUNCTION_NAME_LEN_MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
    }
    let mut function_set_name = [0 as libc::c_char; libc::TCP_FUNCTION_NAME_LEN_MAX as usize];
    let bytes = funcs.as_bytes();
    for idx in 0..slen {
        function_set_name[idx] = bytes[idx] as libc::c_char;
    }
    let fsn = libc::tcp_function_set {
        function_set_name,
        pcbcnt: 0,
    };
    use std::os::fd::AsRawFd;
    let res = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_FUNCTION_BLK,
            &fsn as *const libc::tcp_function_set as *const libc::c_void,
            std::mem::size_of_val(&fsn) as libc::socklen_t,
        )
    };
    if res == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}
