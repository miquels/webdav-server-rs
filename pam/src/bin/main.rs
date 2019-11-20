use std::io::{self, Write};

use env_logger;
use pam_sandboxed::PamAuth;

fn prompt(s: &str) -> io::Result<String> {
    print!("{}", s);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let name = prompt("What's your login? ")?;
    let pass = prompt("What's your password? ")?;

    let mut pamauth = PamAuth::new(None)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        match pamauth.auth("other", &name, &pass, None).await {
            Ok(res) => println!("pam.auth returned Ok({:?})", res),
            Err(e) => println!("pam.auth returned error: {}", e),
        }
        Ok(())
    })
}

// I've put the tests here in bin/main.rs instead of in lib.rs, because "cargo test"
// for the library links the tests without -lpam, so it fails. The price we pay
// for that is a dynamic test-mode setting in the library, instead of compile-time.
#[cfg(test)]
mod tests {
    use pam_sandboxed::{test_mode, PamAuth, PamError};
    use tokio;

    const TEST_STR: &str = "xyzzy-test-test";

    #[test]
    fn test_auth() {
        test_mode(true);

        let mut pam = PamAuth::new(None).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let res = rt.block_on(async {
            let mut pam2 = pam.clone();

            if let Err(e) = pam.auth(TEST_STR, "test", "foo", Some(TEST_STR)).await {
                eprintln!("auth(test) failed: {:?}", e);
                return Err(e);
            }

            if let Ok(_) = pam2.auth(TEST_STR, "unknown", "bar", Some(TEST_STR)).await {
                eprintln!("auth(unknown) succeeded, should have failed");
                return Err(PamError::unknown());
            }

            Ok(())
        });
        assert!(res.is_ok());
    }

    #[test]
    fn test_many() {
        test_mode(true);

        let pam = PamAuth::new(None).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async move {
            for i in 1u32..=1000 {
                let mut pam = pam.clone();
                tokio::spawn(async move {
                    if let Err(e) = pam.auth(TEST_STR, "test", "bar", Some(TEST_STR)).await {
                        panic!("auth(test) failed at iteration {}: {:?}", i, e);
                    }
                });
            }
        });
        rt.shutdown_on_idle();
    }
}
