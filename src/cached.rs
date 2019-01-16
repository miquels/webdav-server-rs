
use std::time::Duration;
use std::sync::Arc;
use std::io;

use futures::prelude::*;
use tokio_threadpool::blocking;

use crate::cache;
use crate::unixuser;
use tokio_pam::{PamAuth, PamError};

lazy_static! {
    static ref PWCACHE: cache::Cache<String, unixuser::Passwd> = cache::Cache::new().maxage(Duration::new(120, 0));
    static ref PAMCACHE: cache::Cache<String, PamData> = cache::Cache::new().maxage(Duration::new(120, 0));
}

pub fn getpwnam_cached(name: &str) -> Result<Arc<unixuser::Passwd>, std::io::Error> {
    if let Some(p) = PWCACHE.get(name) {
        return Ok(p);
    }
    match unixuser::getpwnam(name) {
        Ok(r) => {
            let p = PWCACHE.insert(name.to_string(), r);
            return Ok(p);
        }
        Err(e) => {
            Err(e)
        }
    }
}

pub struct GetPwnamCached {
    try_cache:  bool,
    user:       String,
}

impl GetPwnamCached {
    pub fn lookup(user: &str) -> GetPwnamCached {
        GetPwnamCached {
            try_cache:  true,
            user:       user.to_string(),
        }
    }
}

impl Future for GetPwnamCached {
    type Item = Arc<unixuser::Passwd>;
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
            match unixuser::getpwnam(&user) {
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

struct PamData {
    passwd:     String,
}

pub fn pam_auth_cached(_service: &str, user: &str, pass: &str, _remip: &str) -> Result<(), PamError> {
    if let Some(p) = PAMCACHE.get(user) {
        if p.passwd.as_str() == pass {
            return Ok(());
        }
    }
    /*
    match pam::auth(service, user, pass, remip) {
        Ok(_) => {
            let r = PamData{
                passwd:     pass.to_string(),
            };
            PAMCACHE.insert(user.to_string(), r);
            Ok(())
        }
        Err(e) => {
            Err(e)
        }
    }
    */
    Ok(())
}

