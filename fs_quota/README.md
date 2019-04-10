# FS-QUOTA

Get filesystem disk space used and available for a unix user.

This crate has support for:

- Linux ext2/ext3/ext4 quotas
- Linux XFS quotas
- NFS quotas (via SUNRPC).
- `libc::vfsstat` lookups (like `df`).

NOTE: right now this is all only implemented for **Linux**.

Example application:

```rust
use fs_quota::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("usage: fs_quota <path>");
        return;
    }
    println!("{:#?}", FsQuota::check(&args[1], None));
}
```

## Copyright and License.

 * © 2018, 2019 XS4ALL Internet bv
 * © 2018, 2019 Miquel van Smoorenburg
 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

