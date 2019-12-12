#![doc(html_root_url = "https://docs.rs/pam-sandboxed/0.2.0")]
//! ## PAM authentication with the pam library running in a separate process.
//!
//! The PAM client in this crate creates a future that resolves with the
//! PAM authentication result.
//!
//! ## HOW.
//!
//! When initialized, the code fork()s and sets up a pipe-based communications
//! channel between the parent (pam-client) and the child (pam-server). All
//! the Pam work is then done on a threadpool in the child process.
//!
//! ## WHY.
//!
//! Reasons for doing this instead of just calling libpam directly:
//!
//! - Debian still comes with pam 1.8, which when calling setuid helpers
//!   will first close all filedescriptors up to the rlimit. if
//!   If that limit is high (millions) then it takes a looong while.
//!   `RLIMIT_NOFILE` is reset to a reasonably low number in the child process.
//! - You might want to run the pam modules as a different user than
//!   the main process
//! - There is code in libpam that might call setreuid(), and that is an
//!   absolute non-starter in threaded code.
//! - Also, if you're mucking around with per-thread uid credentials on Linux by
//!   calling the setresuid syscall directly, the pthread library code that
//!   handles setuid() gets confused.
//!
//! ## EXAMPLE.
//! ```
//! use pam_sandboxed::PamAuth;
//!
//! fn main() {
//!     // call this once, early.
//!     let mut pam = PamAuth::new(None).expect("failed to initialized PAM");
//!
//!     let mut rt = tokio::runtime::Runtime::new().expect("failed to initialize tokio runtime");
//!     rt.block_on(async move {
//!         let res = pam.auth("other", "user", "pass", None).await;
//!         println!("pam auth result: {:?}", res);
//!     });
//! }
//! ```
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

mod pam;
mod pamclient;
mod pamserver;

use std::sync::atomic::Ordering;

pub use crate::pam::PamError;
pub use crate::pamclient::PamAuth;

// See bin/main.rs, mod tests.
#[doc(hidden)]
pub fn test_mode(enabled: bool) {
    use crate::pam::TEST_MODE;
    let getal = if enabled { 1 } else { 0 };
    TEST_MODE.store(getal, Ordering::SeqCst);
}
