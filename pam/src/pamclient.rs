// Client part, that is, the part that runs in the local process.
//
// All the futures based code lives here.
//
use std::collections::HashMap;
use std::default::Default;
use std::io;
use std::mem;

use futures::prelude::*;
use futures::sync::{mpsc, oneshot};
use futures::try_ready;

use tokio_uds::UnixStream;
use tokio_io::{self, AsyncRead};
use tokio_core;
use tokio_reactor;

use crate::pam::{ERR_RECV_FROM_SERVER, ERR_SEND_TO_SERVER, PamError};
use crate::stream_channel;
use crate::pamserver::{PamResponse, PamServer};

// Request to be sent to the server process.
#[derive(Debug,Clone,Serialize,Deserialize)]
pub(crate) struct PamRequest {
    pub id:         u64,
    pub user:       String,
    pub pass:       String,
    pub service:    String,
    pub remip:      Option<String>,
}

// sent over request channel to PamAuthTask.
struct PamRequest1 {
    req:        PamRequest,
    resp_chan:  oneshot::Sender<Result<(), PamError>>,
}

/// Pam authenticator.
#[derive(Clone)]
pub struct PamAuth {
    req_chan:   mpsc::Sender<PamRequest1>,
}

impl PamAuth {
    /// Create a new PAM authenticator. This will start a new PAM server process
    /// in the background, and it will start a new PAM coordination task on
    /// the current tokio runtime. `PamAuth` serves as a handle to send requests
    /// and receive responses from it.
    ///
    /// Note that you must call this from within the tokio runtime.
    pub fn new() -> Result<PamAuth, io::Error> {
        let (auth, task) = PamAuthTask::start()?;
        let task = task
            .map(|_| debug!("PamAuthTask is done."))
            .map_err(|_e| debug!("PamAuthTask future returned error: {}", _e));
        debug!("PamAuthTask: spawning task on runtime");
        tokio::spawn(task);
        Ok(auth)
    }

    /// Like new(), but it returns both an authentication handle (PamAuth)
    /// and a PamAuthTask future to be used later.
    /// This is useful if you need to instantiate a PamAuth while not in a runtime.
    ///
    /// You need to spawn the PamAuthTask on the runtime before using the PamAuth handle.
    pub fn lazy_new() -> Result<(PamAuth, PamAuthTask), io::Error> {
        PamAuthTask::start()
    }

    /// Authenticate via pam and return the result.
    ///
    /// - service: PAM service to use - usually "other".
    /// - username: account username
    /// - password: account password
    /// - remoteip: if this is a networking service, the remote IP address of the client.
    pub fn auth(&mut self, service: &str, username: &str, password: &str, remoteip: Option<&str>)
    -> PamAuthFuture
    {
        // create request to be sent to the server.
        let req = PamRequest {
            id:         0,
            user:       username.to_string(),
            pass:       password.to_string(),
            service:    service.to_string(),
            remip:      remoteip.map(|s| s.to_string()),
        };
        let (tx, rx) = oneshot::channel::<Result<(), PamError>>();
        let req1 = PamRequest1 {
            req:        req,
            resp_chan:  tx,
        };

        PamAuthFuture {
            state:      PamAuthState::Request(self.req_chan.clone().send(req1)),
            resp_rx:    Some(rx),
        }
    }
}

enum PamAuthState {
    Request(futures::sink::Send<mpsc::Sender<PamRequest1>>),
    Response(oneshot::Receiver<Result<(), PamError>>),
}

pub struct PamAuthFuture {
    state:      PamAuthState,
    resp_rx:    Option<oneshot::Receiver<Result<(), PamError>>>,
}

impl Future for PamAuthFuture {
    type Item = ();
    type Error = PamError;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {

        // wait for send to complete.
        if let PamAuthState::Request(ref mut r) = self.state {
            let _ = try_ready!(r.poll().map_err(|_e| {
                debug!("PamAuth::auth: send request: error: {}", _e);
                PamError(ERR_SEND_TO_SERVER)
            }));
            // set up waiting for response.
            let resp_rx = self.resp_rx.take().unwrap();
            self.state = PamAuthState::Response(resp_rx);
        }

        // poll response channel.
        if let PamAuthState::Response(ref mut resp_rx) = self.state {
            let res = try_ready!(resp_rx.poll().map_err(|_e| {
                debug!("PamAuth::auth: receive_response: error: {}", _e);
                PamError(ERR_RECV_FROM_SERVER)
            }));
            return match res {
                Ok(res) => Ok(Async::Ready(res)),
                Err(err) => Err(err),
            };
        }
        unreachable!()
    }
}

// state of the client request channel -> server request channel
// forwarding loop.
enum FwdState<T> {
    ReadChan,
    StartSend(T),
    PollComplete,
    Eof,
}

// Future that runs as a task, coordinating things.
pub struct PamAuthTask {
    // Requests from clients.
    req_rx:     mpsc::Receiver<PamRequest1>,
    // Requests to server
    srv_tx:     stream_channel::Sender<PamRequest>,
    // Response from server.
    srv_rx:     stream_channel::Receiver<PamResponse>,
    // client request -> server request forwarding state
    req_state:  FwdState<PamRequest>,
    // server response state.
    srv_state:  FwdState<PamResponse>,
    // clients waiting for a response.
    waiters:    HashMap<u64, oneshot::Sender<Result<(), PamError>>>,
    // Unique id.
    id_seq:     u64,
}

impl PamAuthTask {

    // Start the server process. Then return a handle to send requests on.
    fn start() -> Result<(PamAuth, PamAuthTask), io::Error> {

        // spawn the server process.
        let serversock = PamServer::start()?;

        // transform standard unixstream to tokio version.
        let handle = tokio_reactor::Handle::default();
        let serversock = UnixStream::from_std(serversock, &handle)?;

        // create send/receive channels.
        let (srx, stx) = serversock.split();
        let server_tx = stream_channel::sender::<PamRequest, _>(stx);
        let server_rx = stream_channel::receiver::<PamResponse, _>(srx);

        // create a request channel.
        let (req_tx, req_rx) = mpsc::channel::<PamRequest1>(0);

        // create a future that processes the request channel and the server stream.
        let task = PamAuthTask {
            req_rx:     req_rx,
            srv_tx:     server_tx,
            srv_rx:     server_rx,
            req_state:  FwdState::ReadChan,
            srv_state:  FwdState::ReadChan,
            waiters:    HashMap::new(),
            id_seq:     0,
        };

        Ok((PamAuth{ req_chan: req_tx }, task))
    }
}

// Forward stream `R` to sink `S`. The transform function F() transforms the
// data read from R, type RI, to data to be sent to S, type SI.
fn forward<R, S, RI, SI, F>(mut recv: R, mut send: S, state: FwdState<SI>, mut transform: F)
    -> Result<FwdState<SI>, io::Error>
    where R: Stream<Item=RI, Error=()>,
          S: Sink<SinkItem=SI, SinkError=io::Error>,
          F: FnMut(RI) -> SI,
{
    let mut state = state;

    let mut again = true;
    while again {
        again = false;

        state = match state {
            FwdState::ReadChan => {
                match recv.poll() {
                    Ok(Async::Ready(Some(item))) => {
                        again = true;
                        FwdState::StartSend(transform(item))
                    },
                    Ok(Async::Ready(None)) => FwdState::Eof,
                    Ok(Async::NotReady) => FwdState::ReadChan,
                    Err(..) => return Err(io::ErrorKind::Other.into()),
                }
            },
            FwdState::StartSend(item) => {
                match send.start_send(item) {
                    Ok(AsyncSink::NotReady(item)) => FwdState::StartSend(item),
                    Ok(AsyncSink::Ready) => {
                        again = true;
                        FwdState::PollComplete
                    },
                    Err(e) => return Err(e),
                }
            },
            FwdState::PollComplete => {
                match send.poll_complete() {
                    Err(e) => return Err(e),
                    Ok(Async::Ready(())) => {
                        again = true;
                        FwdState::ReadChan
                    },
                    Ok(Async::NotReady) => {
                        futures::task::current().notify();
                        FwdState::PollComplete
                    },
                }
            },
            FwdState::Eof => FwdState::Eof,
        };
    }
    Ok(state)
}

// This future forwards client requests to the server process, and
// server reponses back to the client. It resolves when both the
// request stream and the server response stream reach end-of-file.
impl Future for PamAuthTask {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {

        // read from request channel, transform and formward request onto server channel.
        match mem::replace(&mut self.req_state, FwdState::Eof) {
            FwdState::Eof => {},
            state => {
                let id_seq = &mut self.id_seq;
                let waiters = &mut self.waiters;
                let fwd_result = forward(&mut self.req_rx, &mut self.srv_tx, state, |item| {
                    let PamRequest1{ mut req, resp_chan } = item;
                    *id_seq += 1;
                    req.id = *id_seq;
                    waiters.insert(req.id, resp_chan);
                    req
                });
                self.req_state = match fwd_result {
                    Ok(res) => res,
                    Err(e) => {
                        debug!("PamAuthTask: {}", e);
                        return Err(e);
                    },
                };
                match self.req_state {
                    FwdState::Eof => {
                        trace!("PamAuthTask: request channel EOF");
                        self.srv_tx.close().ok();
                        ()
                    },
                    _ => {},
                }
            },
        }

        // read from server channel, return response to requestor.
        if let FwdState::Eof = self.srv_state {} else {
            let mut again = true;
            while again {
                again = false;
                self.srv_state = match self.srv_rx.poll() {
                    Ok(Async::Ready(Some(PamResponse{id, result}))) => {
                        if let Some(resp_chan) = self.waiters.remove(&id) {
                            resp_chan.send(result).ok();
                        }
                        again = true;
                        FwdState::ReadChan
                    }
                    Ok(Async::Ready(None)) => {
                        trace!("PamAuthTask: read eof from server");
                        FwdState::Eof
                    },
                    Ok(Async::NotReady) => {
                        FwdState::ReadChan
                    },
                    Err(e) => {
                        return Err(e);
                    },
                }
            }
        }

        // see if both channels have reached EOF.
        if let FwdState::Eof = self.req_state {
            if let FwdState::Eof = self.srv_state {
                return Ok(Async::Ready(()));
            }
        }
        Ok(Async::NotReady)
    }
}

