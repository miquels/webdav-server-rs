#[macro_use] extern crate error_chain;

use std::io::Write;

use env_logger;

use futures::prelude::*;
use futures::future;
use tokio;

use tokio_pam;

error_chain! {
    foreign_links {
        NulError(::std::ffi::NulError);
        Io(::std::io::Error);
        Pam(tokio_pam::PamError);
    }
}

fn prompt(s: &str) -> Result<String> {
    print!("{}", s);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn run() -> Result<()> {
    env_logger::init();
    let name = prompt("What's your login? ")?;
    let pass = prompt("What's your password? ")?;

    let fut = future::ok::<(), ()>(())
        .then(|_| {
            match tokio_pam::PamAuth::new() {
                Ok(p) => Ok(p),
                Err(_e) => {
                    eprintln!("PamAuth::new() returned error: {}", _e);
                    Err(())
                },
            }
        }).and_then(move |mut pam| {
            tokio::spawn(
                pam.auth("other", &name, &pass, None)
                    .map(|_res| println!("pam.auth returned Ok({:?})", _res))
                    .map_err(|_e| println!("pam.auth returned error: {}", _e))
            )
        });

    let rt = tokio::runtime::Runtime::new().unwrap();
    if let Err(e) = rt.block_on_all(fut) {
        eprintln!("runtime returned error {:?}", e);
    }

    Ok(())
}

quick_main!(run);

// I've put the tests here in bin/main.rs instead of in lib.rs, because "cargo test"
// for the library links the tests without -lpam, so it fails. It sucks, because
// now the test for the magic service "xyzzy-test-test" is always present in src/pam.rs,
// instead of only during tests.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_pam::{PamAuth, PamError};
    use futures::future::lazy;
    use tokio;

    const TEST_STR: &str = "xyzzy-test-test";

    #[test]
    fn test_auth() {
        let fut = lazy(move || {
                let mut pam = PamAuth::new().unwrap();
                let mut pam2 = pam.clone();
                pam.auth(TEST_STR, "test", "foo", Some(TEST_STR))
                    .map_err(|e| {
                        eprintln!("auth(test) failed: {:?}", e);
                        e
                    })
                    .and_then(move |_| {
                        pam2.auth(TEST_STR, "unknown", "bar", Some(TEST_STR))
                            .then(|res| {
                                match res {
                                    Ok(()) => {
                                        eprintln!("auth(unknown) succeeded, should have failed");
                                        Err(PamError::unknown())
                                    },
                                    Err(_) => Ok(()),
                                }
                            })
                    })
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on_all(fut).is_ok());
    }

    #[test]
    fn test_many() {
        let fut = lazy(move || {
            let mut pam = PamAuth::new().unwrap();
            for i in 1..=1000 {
                tokio::spawn(
                    pam.auth(TEST_STR, "test", "bar", Some(TEST_STR))
                        .map_err(move |e| panic!("auth(test) failed at iteration {}: {:?}", i, e))
                );
            }
            futures::future::ok::<(), ()>(())
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on_all(fut).is_ok());
    }
}
