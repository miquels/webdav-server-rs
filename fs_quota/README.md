
# fs-quota

Get filesystem disk space used and available for a unix user.

This crate has support for:

- Linux ext2/ext3/ext4 quotas
- Linux XFS quotas
- NFS quotas (via SUNRPC).
- `libc::vfsstat` lookups (like `df`).

The linux ext2/ext3/ext4/xfs quota support only works on linux, not
on non-linux systems with ext4 or xfs support. The `vfsstat` is also
system dependant and, at the moment, only implemented for linux.

NFS quota support can be left out by disabling the `nfs` feature.

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

### Copyright and License.

 * © 2018, 2019 XS4ALL Internet bv
 * © 2018, 2019 Miquel van Smoorenburg
 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
