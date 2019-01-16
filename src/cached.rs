
use std::time::Duration;
use std::sync::Arc;
use std::io;

use futures::prelude::*;
use futures::try_ready;
use tokio_threadpool::blocking;

use crate::cache;
use crate::unixuser;
use tokio_pam;

lazy_static! {
    static ref PWCACHE: cache::Cache<String, unixuser::User> = cache::Cache::new().maxage(Duration::new(120, 0));
    static ref PAMCACHE: cache::Cache<String, ()> = cache::Cache::new().maxage(Duration::new(120, 0));
}

pub struct User {
    try_cache:  bool,
    user:       String,
}

impl User {
    pub fn by_name(user: &str) -> User {
        User {
            try_cache:  true,
            user:       user.to_string(),
        }
    }
}

impl Future for User {
    type Item = Arc<unixuser::User>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {

        if self.try_cache {
            if let Some(p) = PWCACHE.get(&self.user) {
                return Ok(Async::Ready(p));
            }
            self.try_cache = false;
        }

        let user = self.user.clone();
        let bres = blocking(move || {
            match unixuser::User::by_name(&user) {
                Ok(r) => {
                    let p = PWCACHE.insert(user, r);
                    return Ok(p);
                }
                Err(e) => {
                    Err(e)
                }
            }
        });
        match bres {
            Ok(Async::Ready(Ok(pw))) => Ok(Async::Ready(pw)),
            Ok(Async::Ready(Err(e))) => Err(e),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

pub struct PamAuth {
    service:    String,
    user:       String,
    pass:       String,
    remip:      Option<String>,
    key:        String,
    pam_auth:   tokio_pam::PamAuth,
    fut:        Option<tokio_pam::PamAuthFuture>,
}

impl PamAuth {
    pub fn auth(pam_auth: tokio_pam::PamAuth, service: &str, user: &str, pass: &str, remip: Option<&str>) -> PamAuth {
        PamAuth {
            service:    service.to_string(),
            user:       user.to_string(),
            pass:       pass.to_string(),
            remip:      remip.map(|s| s.to_string()),
            key:        format!("{}.{}.{}.{}", service, user, pass, remip.unwrap_or("")),
            pam_auth:   pam_auth,
            fut:        None,
        }
    }
}

impl Future for PamAuth {
    type Item = ();
    type Error = tokio_pam::PamError;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {

        if let None = self.fut {
            // first time, check cache.
            if let Some(_) = PAMCACHE.get(&self.key) {
                return Ok(Async::Ready(()));
            }
            // not in cache, create future.
            let remip = self.remip.as_ref().map(|s| s.as_str());
            self.fut = Some(self.pam_auth.auth(&self.service, &self.user, &self.pass, remip));
        }

        // poll the future.
        let res = try_ready!(self.fut.as_mut().unwrap().poll());

        // future has resolved, auth OK.
        PAMCACHE.insert(self.key.clone(), res);
        Ok(Async::Ready(()))
    }
}

