//
// Cached versions of Unix account lookup and Pam auth.
//
use std::time::Duration;
use std::io;
use std::sync::Arc;

use futures::prelude::*;
use futures::try_ready;

use crate::cache;
use crate::unixuser;
use tokio_pam;

lazy_static! {
    static ref PWCACHE: cache::Cache<String, unixuser::User> = cache::Cache::new().maxage(Duration::new(120, 0));
    static ref PAMCACHE: cache::Cache<String, ()> = cache::Cache::new().maxage(Duration::new(120, 0));
}

pub struct CachedUser {
    try_cache:  bool,
    user:       String,
    userfut:    unixuser::UserFuture,
}

impl CachedUser {
    pub fn by_name(user: &str) -> CachedUser {
        CachedUser {
            try_cache:  true,
            user:       user.to_string(),
            userfut:    unixuser::User::by_name_fut(user),
        }
    }
}

impl Future for CachedUser {
    type Item = Arc<unixuser::User>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        if self.try_cache {
            if let Some(p) = PWCACHE.get(&self.user) {
                return Ok(Async::Ready(p));
            }
            self.try_cache = false;
        }
        match self.userfut.poll() {
            Ok(Async::Ready(pw)) => {
                let p = PWCACHE.insert(self.user.clone(), pw);
                Ok(Async::Ready(p))
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }
}

pub struct CachedPamAuth {
    service:    String,
    user:       String,
    pass:       String,
    remip:      Option<String>,
    key:        String,
    pam_auth:   tokio_pam::PamAuth,
    fut:        Option<tokio_pam::PamAuthFuture>,
}

impl CachedPamAuth {
    pub fn auth(pam_auth: tokio_pam::PamAuth, service: &str, user: &str, pass: &str, remip: Option<&str>) -> CachedPamAuth {
        CachedPamAuth {
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

impl Future for CachedPamAuth {
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

