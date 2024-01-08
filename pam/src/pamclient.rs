// Client part, that is, the part that runs in the local process.
//
// All the futures based code lives here.
//
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex, Once};

use futures::channel::{mpsc, oneshot};
use futures::join;
use futures::{sink::SinkExt, stream::StreamExt};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::ReadHalf as UnixReadHalf;
use tokio::net::unix::WriteHalf as UnixWriteHalf;
use tokio::net::UnixStream;

use crate::pam::{PamError, ERR_RECV_FROM_SERVER, ERR_SEND_TO_SERVER};
use crate::pamserver::{PamResponse, PamServer};

// Request to be sent to the server process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PamRequest {
    pub id:      u64,
    pub user:    String,
    pub pass:    String,
    pub service: String,
    pub remip:   Option<String>,
}

// sent over request channel to PamAuthTask.
struct PamRequest1 {
    req:       PamRequest,
    resp_chan: oneshot::Sender<Result<(), PamError>>,
}

/// Pam authenticator.
#[derive(Clone)]
pub struct PamAuth {
    inner: Arc<PamAuthInner>,
}

struct PamAuthInner {
    once:       Once,
    serversock: RefCell<Option<StdUnixStream>>,
    req_chan:   RefCell<Option<mpsc::Sender<PamRequest1>>>,
}

// Mutation of PamAuthInner only happens once,
// protected by atomic Once, so this is safe.
unsafe impl Sync for PamAuthInner {}
unsafe impl Send for PamAuthInner {}

impl PamAuth {
    /// Create a new PAM authenticator. This will start a new PAM server process
    /// in the background, and it will contain a new PAM coordination task that
    /// will be lazily spawned the first time auth() is called.
    ///
    /// Note that it is important to call this very early in main(), before any
    /// threads or runtimes have started.
    ///
    /// ```no_run
    /// use pam_sandboxed::PamAuth;
    ///
    /// fn main() -> Result<(), Box<std::error::Error>> {
    ///     // get pam authentication handle.
    ///     let mut pam = PamAuth::new(None)?;
    ///
    ///     // now start tokio runtime and use handle.
    ///     let mut rt = tokio::runtime::Runtime::new()?;
    ///     rt.block_on(async move {
    ///         let res = pam.auth("other", "user", "pass", None).await;
    ///         println!("pam auth result: {:?}", res);
    ///     });
    ///     Ok(())
    /// }
    /// ```
    ///
    pub fn new(num_threads: Option<usize>) -> Result<PamAuth, io::Error> {
        // spawn the server process.
        let serversock = PamServer::start(num_threads)?;

        let inner = PamAuthInner {
            once:       Once::new(),
            req_chan:   RefCell::new(None),
            serversock: RefCell::new(Some(serversock)),
        };
        Ok(PamAuth {
            inner: Arc::new(inner),
        })
    }

    /// Authenticate via pam and return the result.
    ///
    /// - `service`: PAM service to use - usually "other".
    /// - `username`: account username
    /// - `password`: account password
    /// - `remoteip`: if this is a networking service, the remote IP address of the client.
    pub async fn auth(
        &mut self,
        service: &str,
        username: &str,
        password: &str,
        remoteip: Option<&str>,
    ) -> Result<(), PamError>
    {
        // If we haven't started the background task yet, do it now.
        // That also initializes req_chan.
        let inner = &self.inner;
        inner.once.call_once(|| {
            // These should not ever panic on unwrap().
            let serversock = inner.serversock.borrow_mut().take().unwrap();
            inner
                .req_chan
                .replace(Some(PamAuthTask::start(serversock).unwrap()));
        });

        // create request to be sent to the server.
        let req = PamRequest {
            id:      0,
            user:    username.to_string(),
            pass:    password.to_string(),
            service: service.to_string(),
            remip:   remoteip.map(|s| s.to_string()),
        };

        // add a one-shot channel for the response.
        let (tx, rx) = oneshot::channel::<Result<(), PamError>>();

        // put it all together and send it.
        let req1 = PamRequest1 {
            req:       req,
            resp_chan: tx,
        };
        let mut authtask_chan = inner.req_chan.borrow().as_ref().unwrap().clone();
        authtask_chan
            .send(req1)
            .await
            .map_err(|_| PamError(ERR_SEND_TO_SERVER))?;

        // wait for the response.
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(PamError(ERR_RECV_FROM_SERVER)),
        }
    }
}

// Shared data for the PamAuthTask tasks.
struct PamAuthTask {
    // clients waiting for a response.
    waiters: Mutex<HashMap<u64, oneshot::Sender<Result<(), PamError>>>>,
}

impl PamAuthTask {
    // Start the server process. Then return a handle to send requests on.
    fn start(serversock: StdUnixStream) -> io::Result<mpsc::Sender<PamRequest1>> {
        serversock.set_nonblocking(true)?; // so we can use it in tokio.
        let mut serversock = UnixStream::from_std(serversock)?;

        // create a request channel.
        let (req_tx, req_rx) = mpsc::channel::<PamRequest1>(0);

        // shared state between request and response task.
        let this = PamAuthTask {
            waiters: Mutex::new(HashMap::new()),
        };

        debug!("PamAuthTask: spawning task on runtime");
        tokio::spawn(async move {
            // split serversock into send/receive halves.
            let (srx, stx) = serversock.split();

            join!(this.handle_request(req_rx, stx), this.handle_response(srx));
        });

        Ok(req_tx)
    }

    async fn handle_request(&self, mut req_rx: mpsc::Receiver<PamRequest1>, mut stx: UnixWriteHalf<'_>) {
        let mut id: u64 = 0;
        loop {
            // receive next request.
            let PamRequest1 { mut req, resp_chan } = match req_rx.next().await {
                Some(r1) => r1,
                None => {
                    // PamAuth handle was dropped. Ask server to exit.
                    let data = [0u8; 2];
                    let _ = stx.write_all(&data).await;
                    return;
                },
            };

            // store the response channel.
            req.id = id;
            id += 1;
            {
                let mut waiters = self.waiters.lock().unwrap();
                waiters.insert(req.id, resp_chan);
            }

            // serialize data and send.
            let mut data: Vec<u8> = match bincode::serialize(&req) {
                Ok(data) => data,
                Err(e) => {
                    // this panic can never happen at runtime.
                    panic!("PamClient: serializing data: {:?}", e);
                },
            };
            if data.len() > 65533 {
                // this panic can never happen at runtime.
                panic!("PamClient: serialized data > 65533 bytes");
            }
            let l1 = ((data.len() >> 8) & 0xff) as u8;
            let l2 = (data.len() & 0xff) as u8;
            data.insert(0, l1);
            data.insert(1, l2);
            if let Err(e) = stx.write_all(&data).await {
                // this can happen if the server has gone away.
                // in which case, handle_response() will exit as well.
                error!("PamClient: FATAL: writing data to server: {:?}", e);
                return;
            }
        }
    }

    async fn handle_response(&self, mut srx: UnixReadHalf<'_>) {
        loop {
            // read size header.
            let mut buf = [0u8; 2];
            if let Err(_) = srx.read_exact(&mut buf).await {
                error!("PamClient: FATAL: short read, server gone away?!");
                return;
            }
            let sz = ((buf[0] as usize) << 8) + (buf[1] as usize);

            // read response data.
            let mut data = Vec::with_capacity(sz);
            data.resize(sz, 0u8);
            if let Err(_) = srx.read_exact(&mut data[..]).await {
                error!("PamClient: FATAL: short read, server gone away?!");
                return;
            }

            // deserialize.
            let resp: PamResponse = match bincode::deserialize(&data[..]) {
                Ok(req) => req,
                Err(_) => {
                    // this panic can never happen at runtime.
                    panic!("PamCLient: error deserializing response");
                },
            };

            // and send response to waiting requester.
            let resp_chan = {
                let mut waiters = self.waiters.lock().unwrap();
                waiters.remove(&resp.id)
            };
            if let Some(resp_chan) = resp_chan {
                let _ = resp_chan.send(resp.result);
            }
        }
    }
}
