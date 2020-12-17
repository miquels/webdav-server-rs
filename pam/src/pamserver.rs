// Server part - the code here is fork()ed off and lives in its own
// process. We communicate with it through a unix stream socket.
//
// This is all old-fashioned blocking and thread-based code.
//
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex};

use bincode::{deserialize, serialize};
use libc;

use crate::pam::{pam_auth, pam_lower_rlimits, PamError};
use crate::pamclient::PamRequest;

// Response back from the server process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PamResponse {
    pub id:     u64,
    pub result: Result<(), PamError>,
}

// server side.
pub(crate) struct PamServer {
    rx_socket: StdUnixStream,
    tx_socket: Arc<Mutex<StdUnixStream>>,
}

impl PamServer {
    // fork and start the server, return the stream socket for communication.
    pub(crate) fn start(num_threads: Option<usize>) -> Result<StdUnixStream, io::Error> {
        // Create a unix socketpair for communication.
        let (sock1, sock2) = StdUnixStream::pair()?;
        let sock3 = sock2.try_clone()?;

        let handle = std::thread::spawn(move || {
            // fork server.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            if pid == 0 {
                // first, close all filedescriptors (well, all..)
                for fdno in 3..8192 {
                    if fdno != sock2.as_raw_fd() && fdno != sock3.as_raw_fd() {
                        unsafe {
                            libc::close(fdno);
                        }
                    }
                }
                let mut server = PamServer {
                    rx_socket: sock2,
                    tx_socket: Arc::new(Mutex::new(sock3)),
                };
                pam_lower_rlimits();
                trace!("PamServer: child: starting server");
                server.serve(num_threads.unwrap_or(8));
                drop(server);
                std::process::exit(0);
            }
            Ok(())
        });
        handle.join().unwrap()?;

        trace!("PamServer: parent: started server");
        Ok(sock1)
    }

    // serve requests.
    fn serve(&mut self, num_threads: usize) {
        // create a threadpool, then serve connections via the threadpool.
        let pool = threadpool::ThreadPool::new(num_threads);

        // process incoming connections.
        loop {
            // read length.
            let mut buf = [0u8; 2];
            let res = self.rx_socket.read_exact(&mut buf);
            if let Err(e) = res {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // parent probably exited - not an error.
                    trace!("PamServer::serve: EOF reached on input");
                    break;
                }
                panic!("PamServer::serve: read socket: {}", e);
            }
            let sz = ((buf[0] as usize) << 8) + (buf[1] as usize);
            if sz == 0 {
                // size 0 packet indicates client wants to shut us down.
                trace!("PamServer::serve: EOF packet on input");
                break;
            }

            // read request data.
            let mut data = Vec::with_capacity(sz);
            data.resize(sz, 0u8);
            let res = self.rx_socket.read_exact(&mut data);
            if let Err(e) = res {
                panic!("PamServer::serve: read socket: {}", e);
            }
            let req: PamRequest = match deserialize(&data[..]) {
                Ok(req) => req,
                Err(_) => panic!("PamServer::serve: error deserializing request"),
            };
            trace!(
                "PamServer::serve: read request {:?} active threads: {} queued {}",
                req,
                pool.active_count(),
                pool.queued_count()
            );

            // run request on pool.
            let sock = self.tx_socket.clone();
            pool.execute(move || {
                if let Err(e) = pam_process(req, sock) {
                    panic!("PamServer::pam_process: error: {}", e);
                }
            });
            let mut i = 0;
            while pool.queued_count() > 2 * pool.max_count() {
                if i == 399 {
                    debug!(
                        "PamServer::serve: pool busy! active {}, max {}, queued: {}",
                        pool.active_count(),
                        pool.max_count(),
                        pool.queued_count()
                    );
                }
                i += 1;
                i = i % 400;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }

        pool.join();
        trace!("PamServer::serve: exit.");
        std::process::exit(0);
    }
}

// Process one request. This is run on the threadpool.
fn pam_process(req: PamRequest, sock: Arc<Mutex<StdUnixStream>>) -> Result<(), io::Error> {
    trace!("PamServer::pam_process: starting with request {:?}", req);

    // authenticate.
    let remip = req.remip.as_ref().map(|s| s.as_str()).unwrap_or("");
    let res = PamResponse {
        id:     req.id,
        result: pam_auth(&req.service, &req.user, &req.pass, remip),
    };

    // and send back result.
    trace!("PamServer::pam_process: returning response {:?}", res);
    let mut response: Vec<u8> = serialize(&res)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("error serializing response: {}", e)))?;
    let l1 = ((response.len() >> 8) & 0xff) as u8;
    let l2 = (response.len() & 0xff) as u8;
    response.insert(0, l1);
    response.insert(1, l2);

    match sock.lock().unwrap().write_all(&response) {
        Err(e) => {
            debug!("PamServer::pam_process: writing to response socket: {}", e);
            Err(e)
        },
        Ok(..) => Ok(()),
    }
}
