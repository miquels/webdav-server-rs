# FS-QUOTA

A library that reports how much space is left for a user in a certain
directory.

If quotas are enabled for the user, that information will be queried
first. The library has support for:

- Linux ext2/ext3/ext4 quotas
- Linux XFS quotas
- NFS quotas (via SUNRPC).

If no quota is found, the `statvfs` system call will be used.

## Copyright and License.

 * © 2018, 2019 XS4ALL Internet bv
 * © 2018, 2019 Miquel van Smoorenburg
 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

