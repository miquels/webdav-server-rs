extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/suid.c")
        .compile("rsuid");   // outputs `librsuid.a`
}

