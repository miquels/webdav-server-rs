
# fs-quota

Get filesystem disk space used and available for a unix user.

This crate has support for:

- the Linux quota system
- NFS quotas (via SUNRPC).
- `libc::vfsstat` lookups (like `df`).

Both the `quota` systemcall and `vfsstat` systemcall are different
on every system. That functionality is only implemented on Linux
right now. NFS quota support _should_ work everywhere.

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
