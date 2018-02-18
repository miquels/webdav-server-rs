
## webdav-server

An implementation of a webdav server with support for user accounts.

Uses PAM authentication and local unix accounts.

An nginx proxy is used in front of this software for:

- TLS offload
- enforcing a max #of open connections
- logging

# Implementation notes:

- PAM is run in a separate process for the following reasons:
  * pam sometimes want to call setuid()/setreuid(). We use the setresuid
    systemcall directly, and the glibc thread-aware implementation
    of the setuid calls doesn't like that and abort.
  * PAM wants to run as root, we want to run with lower priviliges and
    eventually block uid 0 completely (using seccomp-bpf for example)
  * The PAM version that comes with debian in some cases tried to
    close all fildescriptors 1 .. ulimit-hard-max, which is 1M. We lower
    the NOFILE limit in the child process to 256.

- Successful PAM and getpwnam() lookups are cached for 120 seconds.

