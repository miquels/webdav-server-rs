extern crate cc;

fn main() {
    println!("cargo:rustc-link-lib=pam");
    cc::Build::new()
        .file("src/pam.c")
        .compile("rpam");   // outputs `librpam.a`
}

