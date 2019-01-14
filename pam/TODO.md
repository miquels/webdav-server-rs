
## PAM crate TODO items

- check all panics. If the server-side panics - that's OK, the client-side
  will just return errors.

- client side, when server has gone away:
  - panic ?
  - start returning errors ?
  - try to restart the server ?

