# WEBDAV-SERVER

An implementation of a webdav server with support for user accounts,
and running switching uid/gid to those users accounts. That last
feature is Linux-only, since no other OSes have thread-local credentials.

Uses PAM authentication and local unix accounts.

This server does not implement TLS or logging. For now, it is assumed that
most users of this software want to put an NGNIX or Apache reverse-proxy
in front of it anyway, and that frontend can implement TLS, logging,
enforcing a maximum number of connections, and timeouts.

## Configuration.

See the [example webdav-server.toml file](blob/master/webdav-server.toml)

## Notes.

The built-in PAM client will add the client IP address to PAM requests.
If the client IP adress is localhost (127/8 or ::1) then the content of
the X-Real-IP header is used instead (if present) to allow for afore-mentioned
frontend proxies.

## Copyright and License.

 * © 2018, 2019 XS4ALL Internet bv
 * © 2018, 2019 Miquel van Smoorenburg
 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

