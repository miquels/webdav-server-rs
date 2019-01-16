
use futures::{Future, Poll};
pub use futures::future::Either;

pub enum Either3<A, B, C> {
    A(A),
    B(B),
    C(C),
}

impl<A, B, C> Future for Either3<A, B, C>
    where A: Future,
          B: Future<Item = A::Item, Error = A::Error>,
          C: Future<Item = A::Item, Error = A::Error>,
{
    type Item = A::Item;
    type Error = A::Error;

    fn poll(&mut self) -> Poll<A::Item, A::Error> {
        match *self {
            Either3::A(ref mut a) => a.poll(),
            Either3::B(ref mut b) => b.poll(),
            Either3::C(ref mut c) => c.poll(),
        }
    }
}

