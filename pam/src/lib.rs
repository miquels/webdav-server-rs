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
//! ```text
//! let pam = PamAuth::new();
//!
//! let fut = pam.auth("user", "pass", "other", None)
//!     .then(|res| println!("pam auth result: {}", res));
//! fut.wait();
//! ```
#[macro_use] extern crate log;
#[macro_use] extern crate serde_derive;

mod pam;
mod pamclient;
mod pamserver;
mod stream_channel;

pub use crate::pam::PamError;
pub use crate::pamclient::{PamAuth, PamAuthFuture};

// See bin/main.rs, mod tests.
use std::sync::Once;
static TEST_INIT: Once = Once::new();
#[doc(hidden)]
pub fn test_mode() {
    use crate::pam::TEST_MODE;
    TEST_INIT.call_once(|| TEST_MODE.set(()).unwrap());
}

