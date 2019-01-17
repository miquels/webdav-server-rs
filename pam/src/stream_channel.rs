//! # stream_channel
//!
//! Transform a unix-type stream (i.e. a pipe, a TcpStream, a UnixStream) into
//! something that looks like a tokio::sync::mspc::channel.
//!
//! We have two adapters, one for sending (Multiple Producer), one for
//! receiving (Single Consumer).
//!
//! ## stream_channel::sender::<T>(object: T) -> Sender<T>
//!
//! Adapter to send objects of type T over the write-half of the stream.
//! Implements the stream::Sender trait.
//!
//! ## stream_channel::receiver::<T>(object: T) -> Receiver<T>
//!
//! Adapter to receive objects of type T from the read-half of the stream.
//! Implements the stream::Sink trait.
//!
//! Example creating a channel over a UnixStream socketpair:
//! ```text
//! let (sock1, sock2) = tokio::net::UnixStream::pair().unwrap();
//! let tx = stream_channel::sender::<String>(sock1);
//! let rx = stream_channel::receiver::<String>(sock2);
//!
//! // is the equivalent of:
//! let (tx, rx) = tokio::sync::mpsc::channel::<String>(0);
//! ```
//!
use std::io;
use std::mem;
use std::marker::PhantomData;

use bincode::{serialize, deserialize};
use serde::Serialize;
use serde::de::DeserializeOwned;

use futures::{Async, AsyncSink, Poll, Future, Sink, Stream, try_ready};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{ReadExact, WriteAll, read_exact, write_all};

pub(crate) struct Receiver<T> {
    state:      ReadState,
    phantom:    PhantomData<T>,
}

enum ReadState {
	Header(ReadExact<Box<AsyncRead + Send>, Vec<u8>>),
	Body(ReadExact<Box<AsyncRead + Send>, Vec<u8>>),
}

pub(crate) fn receiver<T, A>(a: A) -> Receiver<T>
    where T: DeserializeOwned,
          A: AsyncRead + Send + 'static,
{
    let mut buf = Vec::with_capacity(2);
    buf.resize(2, 0u8);
    Receiver {
        state:      ReadState::Header(read_exact(Box::new(a), buf)),
        phantom:    PhantomData,
    }
}

impl<T> Stream for Receiver<T>
    where T: DeserializeOwned,
{
    type Item = T;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<T>, io::Error> {
        let (sock, mut databuf, state) = match self.state {
            ReadState::Header(ref mut r) => {
                let (sock, data) = match r.poll() {
                    Ok(Async::Ready((sock, data))) => (sock, data),
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        return Ok(Async::Ready(None));
                    },
                    Err(e) => return Err(e),
                };
                (sock, data, 0)
            },
            ReadState::Body(ref mut r) => {
                let (sock, data) = try_ready!(r.poll());
                (sock, data, 1)
            },
        };

        // we haven't exhausted the socket, so make sure we read it again.
        futures::task::current().notify();

        match state {
            0 => {
                let len = ((databuf[0] as usize) << 8) + (databuf[1] as usize);
                databuf.resize(len, 0u8);
                let mut s = ReadState::Body(read_exact(sock, databuf));
                mem::swap(&mut self.state, &mut s);
                Ok(Async::NotReady)
            },
            1 => {
                let res: T = match deserialize(&databuf[..]) {
                    Ok(res) => res,
                    Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "error deserializing")),
                };
                databuf.resize(2, 0u8);
                let mut s = ReadState::Header(read_exact(sock, databuf));
                mem::swap(&mut self.state, &mut s);
                Ok(Async::Ready(Some(res)))
            },
            _ => unreachable!(),
        }
    }
}

pub(crate) struct Sender<T> {
    state:      SendState,
    eof_state:  EofState,
    phantom:    PhantomData<T>,
}

enum SendState {
    Ready(Box<AsyncWrite + Send>),
    Writing(WriteAll<Box<AsyncWrite + Send>, Vec<u8>>),
    Empty,
}

enum EofState {
    Open,
    Pending,
    Closed,
}

pub(crate) fn sender<T, A>(a: A) -> Sender<T>
    where T: Serialize,
          A: AsyncWrite + Send + 'static,
{
    Sender {
        state:      SendState::Ready(Box::new(a)),
        eof_state:  EofState::Open,
        phantom:    PhantomData,
    }
}

impl<T> Sink for Sender<T>
    where T: Serialize,
{
    type SinkItem = T;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Self::SinkItem)
      -> Result<AsyncSink<Self::SinkItem>, Self::SinkError>
    {
        // see if we can send.
        match self.poll_complete() {
            Ok(Async::Ready(())) => {},
            _ => return Ok(AsyncSink::NotReady(item)),
        }
        if let EofState::Open = self.eof_state {} else {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"));
        }

        // serialize data
        let mut data: Vec<u8> = serialize(&item)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if data.len() > 65533 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "sink-item too big"));
        }
        let l1 = ((data.len() >> 8) & 0xff) as u8;
        let l2 = (data.len() & 0xff) as u8;
        data.insert(0, l1);
        data.insert(1, l2);

        // We need to get the stream out of self.state, so first swap it
        // with an empty state, then construct new state with the stream
        // and put it back into self.state. Is there a smarter way?
        let mut state = SendState::Empty;
        mem::swap(&mut self.state, &mut state);
        match state {
            SendState::Ready(strm) => {
                self.state = SendState::Writing(write_all(strm, data));
            },
            _ => unreachable!(),
        }

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, Self::SinkError> {

        // self.close() support.
        if let EofState::Pending = self.eof_state {
            let state = mem::replace(&mut self.state, SendState::Empty);
            self.state = match state {
                SendState::Ready(strm) => {
                    // Send packet of 0 bytes length to indicate EOF.
                    // Unfortunately, shutdown() does not work on WriteHalf.
                    let mut data = Vec::with_capacity(2);
                    data.resize(2, 0u8);
                    self.eof_state = EofState::Closed;
                    SendState::Writing(write_all(strm, data))
                },
                SendState::Writing(w) => SendState::Writing(w),
                SendState::Empty => unreachable!(),
            };
        }

        let strm = match self.state {
            SendState::Ready(..) => {
                return Ok(Async::Ready(()));
            },
            SendState::Writing(ref mut w) => {
                match w.poll() {
                    Ok(Async::Ready((strm, _))) => strm,
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(e) => return Err(e),
                }
            }
            SendState::Empty => unreachable!(),
        };
        self.state = SendState::Ready(strm);
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        if let EofState::Open = self.eof_state {
            self.eof_state = EofState::Pending;
        }
        self.poll_complete()
    }
}

