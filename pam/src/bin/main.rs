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
