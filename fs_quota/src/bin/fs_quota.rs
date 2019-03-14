extern crate fs_quota;
use fs_quota::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("usage: fs_quota <path>");
        return;
    }
    let path = &args[1];
    let r = FsQuota::check(path).or_else(|e| {
        if e == FqError::NoQuota {
            FsQuota::system(path)
        } else {
            Err(e)
        }
    });
    println!("{:#?}", r);
}
