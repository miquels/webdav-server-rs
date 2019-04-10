//! PAM authentication for async tokio applications.
//!
//! The PAM client in this crate creates a future that resolves with the
//! PAM authentication result.
//!
//! This crate forks a worker process, with worker threads, that handle
//! PAM requests, so that the main process is protected against the whole
//! PAM machinery and vice-versa.
//!
//! Use it as follows:
//! ```no_run
//! // call this once.
//! let pam = PamAuth::new();
//!
//! // now use `pam` as a handle to authenticate.
//! let fut = pam.auth("other", "user", "pass", None)
//!     .then(|res| println!("pam auth result: {}", res));
//! tokio::spawn(fut.map_err(|_| ()));
//! ```
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

mod pam;
mod pamclient;
mod pamserver;
mod stream_channel;

use std::sync::atomic::Ordering;

pub use crate::pam::PamError;
pub use crate::pamclient::{PamAuth, PamAuthFuture};

// See bin/main.rs, mod tests.
#[doc(hidden)]
pub fn test_mode(enabled: bool) {
    use crate::pam::TEST_MODE;
    let getal = if enabled { 1 } else { 0 };
    TEST_MODE.store(getal, Ordering::SeqCst);
}
