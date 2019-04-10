extern crate fs_quota;
use fs_quota::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("usage: fs_quota <path>");
        return;
    }
    println!("{:#?}", FsQuota::check(&args[1], None));
}
