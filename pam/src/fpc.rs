
use std;
use std::io;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Sender,channel};
use std::os::unix::io::{AsRawFd, FromRawFd};

use serde::Serialize;
use serde::de::DeserializeOwned;

use libc::{self,pid_t};

use unix_socket::UnixDatagram;
use bincode::{serialize, deserialize};

#[derive(Debug,Clone)]
pub struct Fpc {
    pub pid:    pid_t,
    sock:       Arc<UnixDatagram>,
    state:      Arc<Mutex<FpcState>>,
}

#[derive(Debug,Clone)]
pub struct FpcServer {
    wsock:      Arc<UnixDatagram>,
    rsock:      Arc<Mutex<UnixDatagram>>,
}

#[derive(Debug)]
struct FpcState {
    idseq:      u64,
    waiters:    HashMap<u64, Sender<Vec<u8>>>,
}

#[derive(Debug,Serialize,Deserialize)]
struct FpcData<T> {
    id:     u64,
    data:   T,
}

impl Drop for FpcState {
    fn drop(&mut self) {
        println!("fpcstate droppio");
    }
}

impl Fpc {
    /// Create a new Forked Procedure Call.
    ///
    /// A new process will be forked, and in the new process environent
    /// func() will be called with an FpcServer instance.
    ///
    /// The Fpc that is returned cqn be used to call a procedure from
    /// the forked process.
    pub fn new<F: FnOnce(&FpcServer)>(func: F) -> io::Result<Fpc> {
        let (sock1, sock2) = sock_seqpacket_pair()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            panic!("could not fork!");
        }
        let fd = sock2.as_raw_fd();
        let sock3 = unsafe { UnixDatagram::from_raw_fd(fd) };
        if pid == 0 {
            drop(sock1);
            let remote = FpcServer {
                rsock: Arc::new(Mutex::new(sock2)),
                wsock: Arc::new(sock3),
            };
            func(&remote);
            std::process::exit(0);
        }
        let state = FpcState{
            idseq:      1,
            waiters:    HashMap::new(),
        };
        let lpc = Fpc{
            sock: Arc::new(sock1),
            pid: pid,
            state: Arc::new(Mutex::new(state)),
        };
        let lpc2 = lpc.clone();
        thread::spawn(move || lpc2.demux());
        Ok(lpc)
    }

    fn demux(&self) {
        loop {
            // receive message
            let (id, vec) = match recv_packet(&self.sock) {
                Ok(t) => t,
                Err(e) => {
                    // NotFound means EOF - other side has gone away.
                    if e.kind() != std::io::ErrorKind::NotFound {
                        error!("{:?} - exit", e);
                    }
                    break;
                }
            };

            // find waiter.
            let mut state = self.state.lock().unwrap();
            match state.waiters.remove(&id) {
                Some(tx) => { tx.send(vec).ok(); },
                None => error!("message id {}, no waiter for that id", id),
            }
            drop(state);
        }
    }

    /// Call a procedure in the forked process.
    pub fn call<R: Serialize, A: DeserializeOwned>(&self, request: R) -> io::Result<A> {

        let (tx, rx) = channel();

        let mut state = self.state.lock().unwrap();
        state.idseq += 1;
        let id = state.idseq;
        let data = FpcData{ id: id, data: request };
        let encoded: Vec<u8> = serialize(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.sock.send(&encoded)?;
        state.waiters.insert(id, tx);
        drop(state);

        let v : Vec<u8> = rx.recv().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let data : FpcData<A> = deserialize(&v[..]).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(data.data)
    }
}

impl FpcServer {

    /// Read one request from a remote caller.
    pub fn read_request<T: DeserializeOwned>(&self) -> io::Result<(u64, T)> {
        let sock = self.rsock.lock().unwrap();
        let (id, vec) = recv_packet(&*sock)?;
        let data : FpcData<T> = deserialize(&vec[..]).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok((id, data.data))
    }

    /// send response to remote caller.
    pub fn send_response<T: Serialize>(&self, id: u64, response: T) -> io::Result<()> {
        let data = FpcData{ id: id, data: response };
        let encoded: Vec<u8> = serialize(&data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.wsock.send(&encoded).map(|_| ())
    }
}

// receive one packet from the unix dgram socket
fn recv_packet(sock: &UnixDatagram) -> io::Result<(u64, Vec<u8>)> {
    let mut buffer = [0; 16384];

    let n = match sock.recv(&mut buffer[..]) {
        Ok(n) => n,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                  format!("error receiving rpc packet ({:?})", e)));
        }
    };
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "EOF"));
    }
    if n < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                  format!("short rpc packet received ({} bytes)", n)));
    }
    if n >= 16384 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                  format!("rpc packet received is too large ({} bytes)", n)));
    }
    let id : u64 = deserialize(&buffer[..8]).unwrap();
    Ok((id, buffer[..n].to_vec()))
}

// The linux SOCK_SEQPACKET unix dgram socket is the same as the
// standard SOCK_PACKET one with one crucial difference - it returns
// EOF when the other side is gone.
fn sock_seqpacket_pair() -> io::Result<(UnixDatagram, UnixDatagram)> {
    unsafe {
        let mut fds = [0, 0];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((UnixDatagram::from_raw_fd(fds[0]), UnixDatagram::from_raw_fd(fds[1])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn serve(srv: &FpcServer) {
        let mut v = Vec::new();
        for i in 0..16 {
            let s = srv.clone();
            v.push(thread::spawn(move || {
                loop {
                    println!("thread {} waiting", i);
                    let (id, req) = s.read_request::<i32>()
                        .map_err(|e| { println!("thread {} got read error {:?}", i, e); e }).unwrap();
                    println!("thread {} send_response", i);
                    s.send_response(id, 2*req)
                        .map_err(|e| { println!("thread {} got send error {:?}", i, e); e }).unwrap();
                }
            }));
        }
        drop(srv);
        v.into_iter().for_each(|t| { t.join().ok(); });
    }

    #[test]
    fn test_rpc() {
        let fpc = Fpc::new(serve).unwrap();
        for i in 1 .. 1000 {
            let r : i32 = fpc.call(i as i32).unwrap();
            assert!(r == i * 2);
        }
        println!("dropping fpc");
        drop(fpc);
    }
}

