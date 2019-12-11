//
// Cached versions of Unix account lookup and Pam auth.
//
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cache;
use crate::unixuser::{self, User};
use lazy_static::lazy_static;
use pam_sandboxed::{PamAuth, PamError};

struct Timeouts {
    pwcache:  Duration,
    pamcache: Duration,
}

lazy_static! {
    static ref TIMEOUTS: Mutex<Timeouts> = Mutex::new(Timeouts {
        pwcache:  Duration::new(120, 0),
        pamcache: Duration::new(120, 0),
    });
    static ref PWCACHE: cache::Cache<String, unixuser::User> = new_pwcache();
    static ref PAMCACHE: cache::Cache<u64, String> = new_pamcache();
}

fn new_pwcache() -> cache::Cache<String, unixuser::User> {
    let timeouts = TIMEOUTS.lock().unwrap();
    cache::Cache::new().maxage(timeouts.pwcache)
}

fn new_pamcache() -> cache::Cache<u64, String> {
    let timeouts = TIMEOUTS.lock().unwrap();
    cache::Cache::new().maxage(timeouts.pamcache)
}

pub(crate) fn set_pwcache_timeout(secs: usize) {
    let mut timeouts = TIMEOUTS.lock().unwrap();
    timeouts.pwcache = Duration::new(secs as u64, 0);
}

pub(crate) fn set_pamcache_timeout(secs: usize) {
    let mut timeouts = TIMEOUTS.lock().unwrap();
    timeouts.pamcache = Duration::new(secs as u64, 0);
}

pub async fn pam_auth<'a>(
    pam_auth: PamAuth,
    service: &'a str,
    user: &'a str,
    pass: &'a str,
    remip: Option<&'a str>,
) -> Result<(), PamError>
{
    let mut s = DefaultHasher::new();
    service.hash(&mut s);
    user.hash(&mut s);
    pass.hash(&mut s);
    remip.as_ref().hash(&mut s);
    let key = s.finish();

    if let Some(cache_user) = PAMCACHE.get(&key) {
        if user == cache_user.as_str() {
            return Ok(());
        }
    }

    let mut pam_auth = pam_auth;
    match pam_auth.auth(&service, &user, &pass, remip).await {
        Err(e) => Err(e),
        Ok(()) => {
            PAMCACHE.insert(key, user.to_owned());
            Ok(())
        },
    }
}

pub async fn unixuser(username: &str) -> Result<Arc<User>, io::Error> {
    if let Some(pwd) = PWCACHE.get(username) {
        return Ok(pwd);
    }
    match User::by_name_async(username).await {
        Err(e) => Err(e),
        Ok(pwd) => Ok(PWCACHE.insert(username.to_owned(), pwd)),
    }
}
