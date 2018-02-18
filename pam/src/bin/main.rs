#[macro_use] extern crate error_chain;
extern crate pam;

use std::io::Write;

error_chain! {
    foreign_links {
        NulError(::std::ffi::NulError);
        Io(::std::io::Error);
        Pam(pam::PamError);
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
    //pam::init_worker();
    let name = prompt("What's your login? ")?;
    let pass = prompt("What's your password? ")?;
    let res = pam::auth("webdav", &name, &pass, "");
    if let Err(e) = res {
        println!("{}", e);
    } else {
        println!("OK");
    }
    Ok(())
}

quick_main!(run);
