# WEBDAV-SERVER

An implementation of a webdav server with support for user accounts,
and switching uid/gid to those users accounts. That last feature
is Linux-only, since the server is threaded and no other OSes have
support for thread-local credentials.

Uses PAM authentication and local unix accounts.

This server does not implement TLS or logging. For now, it is assumed that
most users of this software want to put an NGNIX or Apache reverse-proxy
in front of it anyway, and that frontend can implement TLS, logging,
enforcing a maximum number of connections, and timeouts.

This crate uses futures 0.3 and async/await, so it can only be compiled
with rust nightly. The `rust-toolchain` file currently has it pinned
on nightly-2019-04-19.

## Configuration.

See the [example webdav-server.toml file](webdav-server.toml)

## Notes.

The built-in PAM client will add the client IP address to PAM requests.
If the client IP adress is localhost (127/8 or ::1) then the content of
the X-Forwarded-For header is used instead (if present) to allow for
aforementioned frontend proxies.

## Copyright and License.

 * © 2018, 2019 XS4ALL Internet bv
 * © 2018, 2019 Miquel van Smoorenburg
 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

