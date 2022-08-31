use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{AuthType, Config, Location};

use headers::{authorization::Basic, Authorization, HeaderMapExt};
use http::status::StatusCode;

type HttpRequest = http::Request<hyper::Body>;

#[derive(Clone)]
pub struct Auth {
    config:   Arc<Config>,
    #[cfg(all(not(windows), feature = "pam"))]
    pam_auth: pam_sandboxed::PamAuth,
}

impl Auth {
    pub fn new(config: Arc<Config>) -> io::Result<Auth> {
        // initialize pam.
        #[cfg(all(not(windows), feature = "pam"))]
        let pam_auth = {
            // set cache timeouts.
            if let Some(timeout) = config.pam.cache_timeout {
                crate::cache::cached::set_pamcache_timeout(timeout);
            }
            pam_sandboxed::PamAuth::new(config.pam.threads.clone())?
        };

        Ok(Auth {
            #[cfg(all(not(windows), feature = "pam"))]
            pam_auth,
            config,
        })
    }

    // authenticate user.
    pub async fn auth<'a>(
        &'a self,
        req: &'a HttpRequest,
        location: &Location,
        _remote_ip: SocketAddr,
    ) -> Result<String, StatusCode>
    {
        // we must have a login/pass
        let basic = match req.headers().typed_get::<Authorization<Basic>>() {
            Some(Authorization(basic)) => basic,
            _ => return Err(StatusCode::UNAUTHORIZED),
        };
        let user = basic.username();
        let pass = basic.password();

        // match the auth type.
        let auth_type = location
            .accounts
            .auth_type
            .as_ref()
            .or(self.config.accounts.auth_type.as_ref());
        match auth_type {
            #[cfg(all(not(windows), feature = "pam"))]
            Some(&AuthType::Pam) => self.auth_pam(req, user, pass, _remote_ip).await,
            Some(&AuthType::HtPasswd(ref ht)) => self.auth_htpasswd(user, pass, ht.as_str()).await,
            None => {
                debug!("need authentication, but auth-type is not set");
                Err(StatusCode::UNAUTHORIZED)
            },
        }
    }

    // authenticate user using PAM.
    #[cfg(all(not(windows), feature = "pam"))]
    async fn auth_pam<'a>(
        &'a self,
        req: &'a HttpRequest,
        user: &'a str,
        pass: &'a str,
        remote_ip: SocketAddr,
    ) -> Result<String, StatusCode>
    {
        // stringify the remote IP address.
        let ip = remote_ip.ip();
        let ip_string = if ip.is_loopback() {
            // if it's loopback, take the value from the x-forwarded-for
            // header, if present.
            req.headers()
                .get("x-forwarded-for")
                .and_then(|s| s.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_owned())
        } else {
            Some(match ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => ip.to_string(),
            })
        };
        let ip_ref = ip_string.as_ref().map(|s| s.as_str());

        // authenticate.
        let service = self.config.pam.service.as_str();
        let pam_auth = self.pam_auth.clone();
        match crate::cache::cached::pam_auth(pam_auth, service, user, pass, ip_ref).await {
            Ok(_) => Ok(user.to_string()),
            Err(_) => {
                debug!(
                    "auth_pam({}): authentication for {} ({:?}) failed",
                    service, user, ip_ref
                );
                Err(StatusCode::UNAUTHORIZED)
            },
        }
    }

    // authenticate user using htpasswd.
    async fn auth_htpasswd<'a>(
        &'a self,
        user: &'a str,
        pass: &'a str,
        section: &'a str,
    ) -> Result<String, StatusCode>
    {
        // Get the htpasswd.WHATEVER section from the config file.
        let file = match self.config.htpasswd.get(section) {
            Some(section) => section.htpasswd.as_str(),
            None => return Err(StatusCode::UNAUTHORIZED),
        };

        // Read the file and split it into a bunch of lines.
        tokio::task::block_in_place(move || {
            let data = match std::fs::read_to_string(file) {
                Ok(data) => data,
                Err(e) => {
                    debug!("{}: {}", file, e);
                    return Err(StatusCode::UNAUTHORIZED);
                },
            };
            let lines = data
                .split('\n')
                .map(|s| s.trim())
                .filter(|s| !s.starts_with("#") && !s.is_empty());

            // Check each line for a match.
            for line in lines {
                let mut fields = line.split(':');
                if let (Some(htuser), Some(htpass)) = (fields.next(), fields.next()) {
                    if htuser == user && pwhash::unix::verify(pass, htpass) {
                        return Ok(user.to_string());
                    }
                }
            }

            debug!("auth_htpasswd: authentication for {} failed", user);
            Err(StatusCode::UNAUTHORIZED)
        })
    }
}
