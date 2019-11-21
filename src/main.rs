#![doc(html_root_url = "https://docs.rs/webdav-server/0.3.0")]
//! # `webdav-server` is a webdav server that handles user-accounts.
//!
//! This is a webdav server that allows access to a users home directory,
//! just like an ancient FTP server would (remember those?).
//!
//! This is an application. There is no API documentation here.
//! If you want to build your _own_ webdav server, use the `webdav-handler` crate.
//!
//! See the [GitHub repository](https://github.com/miquels/webdav-server-rs/)
//! for documentation on how to run the server.
//!

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;

mod cache;
mod cached;
mod config;
mod rootfs;
mod suid;
mod unixuser;
mod userfs;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::exit;
use std::sync::Arc;

use env_logger;
use handlebars::Handlebars;
use headers::{authorization::Basic, Authorization, HeaderMapExt};
use http;
use http::status::StatusCode;
use hyper::{self, server::conn::AddrStream, service::{service_fn, make_service_fn}};
use net2;
use tokio;

use pam_sandboxed::PamAuth;
use webdav_handler::{fakels::FakeLs, localfs::LocalFs, ls::DavLockSystem, memls::MemLs};
use webdav_handler::{fs, fs::DavFileSystem, webpath::WebPath, DavConfig, DavHandler};

use crate::rootfs::RootFs;
use crate::suid::switch_ugid;
use crate::userfs::UserFs;

static PROGNAME: &'static str = "webdav-server";

// Contains "state" and a handle to the config.
#[derive(Clone)]
struct Server {
    dh:         DavHandler,
    pam_auth:   PamAuth,
    users_path: Arc<Option<String>>,
    config:     Arc<config::Config>,
}

#[allow(dead_code)]
type HttpResult = Result<hyper::Response<webdav_handler::body::Body>, io::Error>;
type HttpRequest = http::Request<hyper::Body>;

// Server implementation.
impl Server {
    // Constructor.
    pub fn new(config: Arc<config::Config>, auth: PamAuth) -> Self {
        // any locksystem?
        let ls = match config.webdav.locksystem.as_str() {
            "" | "fakels" => Some(FakeLs::new() as Box<dyn DavLockSystem>),
            "memls" => Some(MemLs::new() as Box<dyn DavLockSystem>),
            _ => None,
        };

        // mostly empty handler.
        let dh = DavHandler::new_with(DavConfig {
            ls: ls,
            ..DavConfig::default()
        });

        // base path of the users.
        let users_path = match config.users {
            Some(ref users) => {
                if let Some(idx) = users.path.find("/:username") {
                    let userbase = match &users.path[..idx] {
                        "" => "/",
                        x => x,
                    };
                    Some(String::from(userbase))
                } else {
                    None
                }
            },
            None => None,
        };

        Server {
            dh:         dh,
            pam_auth:   auth,
            config:     config,
            users_path: Arc::new(users_path),
        }
    }

    // get the user path from config.users.path.
    fn user_path(&self, user: &str) -> String {
        match self.config.users {
            Some(ref users) => {
                // replace :user with the username.
                users.path.replace(":username", user)
            },
            None => {
                // something that can never match.
                "-".to_string()
            },
        }
    }

    // check if this is the root filesystem.
    fn is_realroot(&self, uri: &http::uri::Uri) -> Option<(WebPath, bool)> {
        // is a rootfs configured?
        let rootfs = match self.config.rootfs {
            Some(ref rootfs) => rootfs,
            None => return None,
        };

        // check prefix.
        let webpath = match WebPath::from_uri(uri, &rootfs.path) {
            Ok(path) => path,
            Err(_) => return None,
        };

        // only files one level deep.
        let nseg = webpath.num_segments();
        if nseg > 1 || (nseg == 1 && webpath.is_collection()) {
            return None;
        }

        Some((webpath, rootfs.auth))
    }

    // authenticate user.
    async fn auth<'a>(
        &'a self,
        req: &'a HttpRequest,
        remote_ip: Option<&'a str>,
    ) -> Result<Arc<unixuser::User>, StatusCode>
    {
        // we must have a login/pass
        let basic = match req.headers().typed_get::<Authorization<Basic>>() {
            Some(Authorization(basic)) => basic,
            _ => return Err(StatusCode::UNAUTHORIZED),
        };
        let user = basic.username();
        let pass = basic.password();

        // check if user exists.
        let pwd = match cached::unixuser(user).await {
            Ok(pwd) => pwd,
            Err(_) => return Err(StatusCode::UNAUTHORIZED),
        };

        // authenticate.
        let service = self.config.pam.service.as_str();
        let pam_auth = self.pam_auth.clone();
        if let Err(_) = cached::pam_auth(pam_auth, service, &pwd.name, pass, remote_ip).await {
            return Err(StatusCode::UNAUTHORIZED);
        }

        // check minimum uid
        if let Some(min_uid) = self.config.unix.min_uid {
            if pwd.uid < min_uid {
                debug!(
                    "Server::auth: {}: uid {} too low (<{})",
                    pwd.name, pwd.uid, min_uid
                );
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Ok(pwd)
    }

    // return a new response::Builder with the Server: header set.
    fn response_builder(&self) -> http::response::Builder {
        let mut builder = hyper::Response::builder();
        let id = self
            .config
            .server
            .identification
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("webdav-server-rs");
        if id != "" {
            builder.header("Server", id);
        }
        builder
    }

    // Set Server: webdav-server-rs header.
    fn set_server_header(&self, headers: &mut http::HeaderMap<http::header::HeaderValue>) {
        let id = self
            .config
            .server
            .identification
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("webdav-server-rs");
        if id != "" {
            headers.insert("server", id.parse().unwrap());
        }
    }

    // handle a request.
    async fn handle(
        &self,
        req: HttpRequest,
        remote_ip: SocketAddr,
    ) -> HttpResult
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
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => ip.to_string(),
            })
        };
        let ip_ref = ip_string.as_ref().map(|s| s.as_str());

        // see if this is a request for the root filesystem.
        let method = req.method();
        if method == &http::Method::GET || method == &http::Method::HEAD {
            if let Some((webpath, do_auth)) = self.is_realroot(req.uri()) {
                debug!("handle: {:?}: handle as realroot", req.uri());
                let user = if do_auth {
                    match self.auth(&req, ip_ref).await {
                        Ok(pwd) => Some(pwd.name.clone()),
                        Err(status) => return self.error(status).await,
                    }
                } else {
                    None
                };
                return self.handle_realroot(req, user, webpath).await;
            }
            debug!("handle: {:?}: not realroot", req.uri());
        }

        // Normalize the path.
        let path = match WebPath::from_uri(req.uri(), "") {
            Ok(path) => path.as_utf8_string_with_prefix(),
            Err(_) => return self.error(StatusCode::BAD_REQUEST).await,
        };

        // Could be a request for the virtual root.
        if let Some(users_path) = self.users_path.as_ref() {
            if is_virtroot(&path, users_path) {
                let pwd = match self.auth(&req, ip_ref).await {
                    Ok(pwd) => pwd,
                    Err(status) => return self.error(status).await,
                };
                debug!("handle: {:?}: handle as virtualroot", req.uri());
                return self.handle_virtualroot(req, pwd).await;
            }
        }

        // is this the users part of the path?
        let prefix = self.user_path("");
        if !path.starts_with(&prefix) {
            debug!("handle: {}: doesn't match start with {}", path, prefix);
            return self.error(StatusCode::NOT_FOUND).await;
        }

        // authenticate now.
        let pwd = match self.auth(&req, ip_ref).await {
            Ok(pwd) => pwd,
            Err(status) => return self.error(status).await,
        };

        // Check if username matches basedir.
        let prefix = self.user_path(&pwd.name);
        if !path.starts_with(&prefix) {
            // in /<something>/ but doesn't match /:user/
            debug!(
                "Server::handle: user {} prefix {} path {} -> 401",
                pwd.name, prefix, path
            );
            return self.error(StatusCode::UNAUTHORIZED).await;
        }

        // All set.
        self.handle_user(req, prefix, pwd).await
    }

    async fn error(&self, code: StatusCode) -> HttpResult {
        let msg = format!(
            "<error>{} {}</error>\n",
            code.as_u16(),
            code.canonical_reason().unwrap_or("")
        );
        let mut response = self.response_builder();
        response.status(code);
        response.header("Content-Type", "text/xml");
        if code == StatusCode::UNAUTHORIZED {
            let realm = self
                .config
                .accounts
                .realm
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("Webdav Server");
            response.header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm).as_str());
        }
        Ok(response.body(msg.into()).unwrap())
    }

    async fn redirect(&self, path: String) -> HttpResult {
        let resp = self
            .response_builder()
            .status(302)
            .header("content-type", "text/plain")
            .header("location", path)
            .body("302 Moved\n".into())
            .unwrap();
        Ok(resp)
    }

    // serve from the local filesystem.
    async fn handle_realroot(
        &self,
        req: HttpRequest,
        user: Option<String>,
        webpath: WebPath,
    ) -> HttpResult
    {
        // get filename.
        let mut webpath = webpath;
        let mut filename = match std::str::from_utf8(webpath.file_name()) {
            Ok(n) => n,
            Err(_) => return self.error(StatusCode::NOT_FOUND).await,
        };

        let rootfs = self.config.rootfs.as_ref().unwrap();
        debug!("Server::handle_realroot: serving {:?}", req.uri());

        // index.html?
        let mut req = req;
        if filename == "" {
            let index = rootfs.index.as_ref().map(|s| s.as_str()).unwrap_or("index.html");
            filename = index;
            webpath.push_segment(index.as_bytes());
            let path = webpath.as_url_string_with_prefix();
            if let Ok(pq) = http::uri::PathAndQuery::from_shared(path.into()) {
                let mut parts = req.uri().clone().into_parts();
                parts.path_and_query = Some(pq);
                *req.uri_mut() = http::uri::Uri::from_parts(parts).unwrap();
            }
        }

        // see if file exists.
        let fs: Box<dyn DavFileSystem> = LocalFs::new(&rootfs.directory, true, false, false);
        if fs.metadata(&webpath).await.is_err() {
            if let Some(users_path) = self.users_path.as_ref() {
                if users_path == &rootfs.path {
                    // file doesn't exist and we share the path with the users path.
                    // if it matches a valid username, redirect.
                    if cached::unixuser(&filename).await.is_ok() {
                        debug!("Server::handle_realroot: redirect to /{}/", filename);
                        let mut p = WebPath::from_str(&rootfs.path, "").unwrap();
                        p.push_segment(filename.as_bytes());
                        p.add_slash();
                        return self.redirect(p.as_utf8_string_with_prefix()).await;
                    }
                }
            }
            return self.error(StatusCode::NOT_FOUND).await;
        }

        // Might be handlebars.
        if filename.ends_with(".hbs") {
            return self.render_hbs(req, fs, webpath, user).await;
        }

        // serve.
        let config = DavConfig {
            fs: Some(fs),
            ..DavConfig::default()
        };
        self.run_davhandler(config, req).await
    }

    // handlebars support.
    async fn render_hbs(
        &self,
        req: HttpRequest,
        mut fs: Box<dyn DavFileSystem>,
        webpath: WebPath,
        user: Option<String>,
    ) -> HttpResult
    {
        let filename = std::str::from_utf8(webpath.file_name()).unwrap();
        debug!("Server::render_hbs {}", filename);
        let indata = match read_file(&mut fs, &webpath).await {
            Ok(data) => data,
            Err(e) => {
                debug!("render_hbs: {}: {:?}", filename, e);
                return self.error(StatusCode::INTERNAL_SERVER_ERROR).await;
            },
        };
        let hbs = Handlebars::new();
        let mut vars = HashMap::new();
        let h = req
            .headers()
            .get("host")
            .and_then(|s| s.to_str().ok())
            .map(|s| s.to_owned());
        if let Some(host) = h {
            vars.insert("hostname", host.to_string());
        }
        if let Some(user) = user {
            vars.insert("username", user);
        }
        let outdata = match hbs.render_template(&indata, &vars) {
            Ok(data) => data,
            Err(e) => {
                debug!("handle_realroot: {}: render template: {:?}", filename, e);
                return self.error(StatusCode::INTERNAL_SERVER_ERROR).await;
            },
        };
        self.response_builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(outdata.into())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    // virtual root filesytem for PROPFIND/OPTIONS in "/".
    async fn handle_virtualroot(
        &self,
        req: HttpRequest,
        pwd: Arc<unixuser::User>,
    ) -> HttpResult
    {
        debug!("Server::handle_virtualroot: /");
        let ugid = match self.config.accounts.setuid {
            true => Some((pwd.uid, pwd.gid)),
            false => None,
        };
        let user = pwd.name.clone();

        let mut methods = webdav_handler::AllowedMethods::none();
        methods.add(webdav_handler::Method::Head);
        methods.add(webdav_handler::Method::Get);
        methods.add(webdav_handler::Method::PropFind);
        methods.add(webdav_handler::Method::Options);

        let prefix = self.users_path.as_ref().clone().unwrap();

        let fs = RootFs::new(&pwd.dir, user.clone(), ugid);
        let config = DavConfig {
            fs: Some(fs),
            prefix: Some(prefix),
            principal: Some(user),
            allow: Some(methods),
            ..DavConfig::default()
        };
        self.run_davhandler(config, req).await
    }

    async fn handle_user(
        &self,
        req: HttpRequest,
        prefix: String,
        pwd: Arc<unixuser::User>,
    ) -> HttpResult
    {
        // do we have a users section?
        let users = match self.config.users {
            Some(ref users) => users,
            None => return self.error(StatusCode::NOT_FOUND).await,
        };

        let ugid = match self.config.accounts.setuid {
            true => Some((pwd.uid, pwd.gid)),
            false => None,
        };

        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("");
        let case_insensitive = users.ms_case_insensitive && user_agent.contains("Microsoft");
        let macos = user_agent.contains("WebDAVFS/") && user_agent.contains("Darwin");

        let fs = UserFs::new(&pwd.dir, ugid, true, case_insensitive, macos);

        debug!("Server::handle_user: in userdir {} prefix {} ", pwd.name, prefix);
        let config = DavConfig {
            prefix: Some(prefix),
            fs: Some(fs),
            principal: Some(pwd.name.to_string()),
            hide_symlinks: users.hide_symlinks,
            ..DavConfig::default()
        };
        self.run_davhandler(config, req).await
    }

    // Call the davhandler, then add headers to the response.
    async fn run_davhandler(
        &self,
        config: DavConfig,
        req: HttpRequest,
    ) -> HttpResult
    {

        match self.dh.handle_with(config, req).await {
            Ok(resp) => {
                let (mut parts, body) = resp.into_parts();
                self.set_server_header(&mut parts.headers);
                Ok(http::Response::from_parts(parts, body))
            },
            Err(e) => Err(e),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // command line option processing.
    let matches = clap_app!(webdav_server =>
        (version: "0.1")
        (@arg CFG: -c --config +takes_value "configuration file (/etc/webdav-server.toml)")
        (@arg PORT: -p --port +takes_value "listen to this port on localhost only")
        (@arg DIR: -d --dir +takes_value "override local directory to serve")
        (@arg DBG: -D --debug "enable debug level logging")
    )
    .get_matches();

    if matches.is_present("DBG") {
        use env_logger::Env;
        let level = "webdav_server=debug,webdav_handler=debug";
        env_logger::from_env(Env::default().default_filter_or(level)).init();
    } else {
        env_logger::init();
    }

    let dir = matches.value_of("DIR");
    let port = matches.value_of("PORT");
    let cfg = matches.value_of("CFG").unwrap_or("/etc/webdav-server.toml");

    // read config.
    let mut config = match config::read(cfg.clone()) {
        Err(e) => {
            eprintln!("{}: {}: {}", PROGNAME, cfg, e);
            exit(1);
        },
        Ok(c) => c,
    };
    config::check(cfg.clone(), &config);

    // override parts of the config with command line options.
    if let Some(dir) = dir {
        if config.rootfs.is_none() {
            eprintln!("{}: [rootfs] section missing", cfg);
            exit(1);
        }
        config.rootfs.as_mut().unwrap().directory = dir.to_owned();
    }
    if let Some(port) = port {
        let localhosts = vec![
            ("127.0.0.1:".to_string() + port).parse::<SocketAddr>().unwrap(),
            ("[::]:".to_string() + port).parse::<SocketAddr>().unwrap(),
        ];
        config.server.listen = config::OneOrManyAddr::Many(localhosts);
    }
    let config = Arc::new(config);

    // set cache timeouts.
    if let Some(timeout) = config.pam.cache_timeout {
        cached::set_pamcache_timeout(timeout);
    }
    if let Some(timeout) = config.unix.cache_timeout {
        cached::set_pwcache_timeout(timeout);
    }

    // resolve addresses.
    let addrs = match config.server.listen.clone().to_socket_addrs() {
        Err(e) => {
            eprintln!("{}: [server] listen: {:?}", cfg, e);
            exit(1);
        },
        Ok(a) => a,
    };

    // initialize pam.
    let pam = PamAuth::new(config.pam.threads.clone())?;

    // start servers (one for each listen address).
    let dav_server = Server::new(config.clone(), pam);
    let mut servers = Vec::new();
    for sockaddr in addrs {
        let listener = match make_listener(&sockaddr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{}: listener on {:?}: {}", PROGNAME, &sockaddr, e);
                exit(1);
            },
        };
        let dav_server = dav_server.clone();
		let make_service = make_service_fn(move |socket: &AddrStream| {
			let dav_server = dav_server.clone();
            let remote_addr = socket.remote_addr();
			async move {
				let func = move |req| {
					let dav_server = dav_server.clone();
					async move { dav_server.handle(req, remote_addr).await }
				};
				Ok::<_, hyper::Error>(service_fn(func))
			}
		});

		let server = hyper::Server::from_tcp(listener)?.tcp_nodelay(true);
        println!("Listening on http://{:?}", sockaddr);

        servers.push(async move {
            if let Err(e) = server.serve(make_service).await {
                eprintln!("server error: {}", e);
            }
        });

    }

    // drop privs.
    match (&config.server.uid, &config.server.gid) {
        (&Some(uid), &Some(gid)) => switch_ugid(uid, gid),
        _ => {},
    }

    // start tokio runtime, run all servers, and wait for them to finish.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        for server in servers.drain(..) {
            let _ = tokio::spawn(server);
        }
    });
    rt.shutdown_on_idle();

    Ok(())
}

// Is this a file that belongs on the root filesystem?
// (whether it exists or not)
fn is_virtroot(path: &str, users_path: &str) -> bool {

    // strip users_path prefix.
    if !path.starts_with(users_path) {
        return false;
    }
    let p = path[users_path.len()..].trim_start_matches('/');

    // more than one level deep, not the root fs.
    if p.contains('/') {
        return false;
    }

    // only send this to the virtual root fs handler if
    // we know this file - either root itself, or one of the
    // special files windows/macos/linux probes for.
    //
    // otherwise it could still be a username.
    p == "" ||
        p.contains(char::is_uppercase) ||
        p.starts_with(".") ||
        p == "internal.dat" ||
        p == "fakehome.dat" ||
        p == "loopdir" ||
        p == "index.html"
}

// Make a new TcpListener, and if it's a V6 listener, set the
// V6_V6ONLY socket option on it.
fn make_listener(addr: &SocketAddr) -> io::Result<std::net::TcpListener> {
    let s = if addr.is_ipv6() {
        let s = net2::TcpBuilder::new_v6()?;
        s.only_v6(true)?;
        s
    } else {
        net2::TcpBuilder::new_v4()?
    };
    s.reuse_address(true)?;
    s.bind(addr)?;
    s.listen(128)
}

async fn read_file<'a>(
    fs: &'a mut Box<dyn DavFileSystem>,
    webpath: &'a WebPath,
) -> fs::FsResult<String>
{
    let oo = fs::OpenOptions {
        read: true,
        ..fs::OpenOptions::default()
    };
    let mut file = fs.open(webpath, oo).await?;
    let mut buffer = [0; 8192];
    let mut data = Vec::new();
    loop {
        let n = file.read_bytes(&mut buffer[..]).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);
    }
    match String::from_utf8(data) {
        Ok(s) => Ok(s),
        Err(_) => Err(fs::FsError::GeneralFailure),
    }
}
