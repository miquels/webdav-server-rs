
## PAM crate TODO items

- make Fpc mode more robust:
  - in fn pam_server(), do we really need to exit on all errors?
  - if so, process exit instead of thread exit ?
  - in demux, better check to see if Fpc server has gone away
  - when that happens wake up all waiting threads with an error
  - error logging
  - restart Fpc server ? or exit ?

