
use std;
use std::time::Duration;
use std::sync::Arc;

use crate::cache;
use crate::unixuser;
use tokio_pam::{PamError};

lazy_static! {
    static ref PWCACHE: cache::Cache<String, unixuser::Passwd> = cache::Cache::new().maxage(Duration::new(120, 0));
    static ref PAMCACHE: cache::Cache<String, PamData> = cache::Cache::new().maxage(Duration::new(120, 0));
}

struct PamData {
    passwd:     String,
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

