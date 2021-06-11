#![doc(html_root_url = "https://docs.rs/webdav-server/0.4.0")]
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
extern crate log;

mod auth;
mod cache;
mod config;
mod rootfs;
#[doc(hidden)]
pub mod router;
mod suid;
mod tls;
mod unixuser;
mod userfs;

use std::convert::TryFrom;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::io::{FromRawFd, AsRawFd};
use std::process::exit;
use std::sync::Arc;

use clap::clap_app;
use headers::{authorization::Basic, Authorization, HeaderMapExt};
use http::status::StatusCode;
use hyper::{
    self,
    server::conn::{AddrIncoming, AddrStream},
    service::{make_service_fn, service_fn},
};
use tls_listener::TlsListener;
use tokio_rustls::server::TlsStream;
use webdav_handler::{davpath::DavPath, DavConfig, DavHandler, DavMethod, DavMethodSet};
use webdav_handler::{fakels::FakeLs, fs::DavFileSystem, ls::DavLockSystem};

use crate::config::{AcctType, Auth, CaseInsensitive, Handler, Location, OnNotfound};
use crate::rootfs::RootFs;
use crate::router::MatchedRoute;
use crate::suid::proc_switch_ugid;
use crate::tls::tls_config;
use crate::userfs::UserFs;

static PROGNAME: &'static str = "webdav-server";

// Contains "state" and a handle to the config.
#[derive(Clone)]
struct Server {
    dh:     DavHandler,
    auth:   auth::Auth,
    config: Arc<config::Config>,
}

type HttpResult = Result<hyper::Response<webdav_handler::body::Body>, io::Error>;
type HttpRequest = http::Request<hyper::Body>;

// Server implementation.
impl Server {
    // Constructor.
    pub fn new(config: Arc<config::Config>, auth: auth::Auth) -> Self {
        // mostly empty handler.
        let ls = FakeLs::new() as Box<dyn DavLockSystem>;
        let dh = DavHandler::builder().locksystem(ls).build_handler();

        Server { dh, auth, config }
    }

    // check user account.
    async fn acct<'a>(
        &'a self,
        location: &Location,
        auth_user: Option<&'a String>,
        user_param: Option<&'a str>,
    ) -> Result<Option<Arc<unixuser::User>>, StatusCode>
    {
        // Get username - if any.
        let user = match auth_user.map(|u| u.as_str()).or(user_param) {
            Some(u) => u,
            None => return Ok(None),
        };

        // If account is not set, fine.
        let acct_type = location
            .accounts
            .acct_type
            .as_ref()
            .or(self.config.accounts.acct_type.as_ref());
        match acct_type {
            Some(&AcctType::Unix) => {},
            None => return Ok(None),
        };

        // check if user exists.
        let pwd = match cache::cached::unixuser(user, self.config.unix.aux_groups).await {
            Ok(pwd) => pwd,
            Err(_) => {
                debug!("acct: unix: user {} not found", user);
                return Err(StatusCode::UNAUTHORIZED);
            },
        };

        // check minimum uid
        if let Some(min_uid) = self.config.unix.min_uid {
            if pwd.uid < min_uid {
                debug!("acct: {}: uid {} too low (<{})", pwd.name, pwd.uid, min_uid);
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Ok(Some(pwd))
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
            builder = builder.header("Server", id);
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
    async fn route(&self, req: HttpRequest, remote_ip: SocketAddr) -> HttpResult {
        // Get the URI path.
        let davpath = match DavPath::from_uri(req.uri()) {
            Ok(p) => p,
            Err(_) => return self.error(StatusCode::BAD_REQUEST).await,
        };
        let path = davpath.as_bytes();

        // Get the method.
        let method = match DavMethod::try_from(req.method()) {
            Ok(m) => m,
            Err(_) => return self.error(http::StatusCode::METHOD_NOT_ALLOWED).await,
        };

        // Request is stored here.
        let mut reqdata = Some(req);
        let mut got_match = false;

        // Match routes to one or more locations.
        for route in self
            .config
            .router
            .matches(path, method, &["user", "path"])
            .drain(..)
        {
            got_match = true;

            // Take the request from the option.
            let req = reqdata.take().unwrap();

            // if we might continue, store a clone of the request for the next round.
            let location = &self.config.location[*route.data];
            if let Some(OnNotfound::Continue) = location.on_notfound {
                reqdata.get_or_insert(clone_httpreq(&req));
            }

            // handle request.
            let res = self
                .handle(req, method, path, route, location, remote_ip.clone())
                .await?;

            // no on_notfound? then this is final.
            if reqdata.is_none() || res.status() != StatusCode::NOT_FOUND {
                return Ok(res);
            }
        }

        if !got_match {
            debug!("route: no matching route for {:?}", davpath);
        }

        self.error(StatusCode::NOT_FOUND).await
    }

    // handle a request.
    async fn handle<'a, 't: 'a, 'p: 'a>(
        &'a self,
        req: HttpRequest,
        method: DavMethod,
        path: &'a [u8],
        route: MatchedRoute<'t, 'p, usize>,
        location: &'a Location,
        remote_ip: SocketAddr,
    ) -> HttpResult
    {
        // See if we matched a :user parameter
        // If so, it must be valid UTF-8, or we return NOT_FOUND.
        let user_param = match route.params[0].as_ref() {
            Some(p) => {
                match p.as_str() {
                    Some(p) => Some(p),
                    None => {
                        debug!("handle: invalid utf-8 in :user part of path");
                        return self.error(StatusCode::NOT_FOUND).await;
                    },
                }
            },
            None => None,
        };

        // Do authentication if needed.
        let auth_hdr = req.headers().typed_get::<Authorization<Basic>>();
        let do_auth = match location.auth {
            Some(Auth::True) => true,
            Some(Auth::Write) => !DavMethodSet::WEBDAV_RO.contains(method) || auth_hdr.is_some(),
            Some(Auth::False) => false,
            Some(Auth::Opportunistic) | None => auth_hdr.is_some(),
        };
        let auth_user = if do_auth {
            let user = match self.auth.auth(&req, location, remote_ip).await {
                Ok(user) => user,
                Err(status) => return self.auth_error(status, location).await,
            };
            // if there was a :user in the route, return error if it does not match.
            if user_param.map(|u| u != &user).unwrap_or(false) {
                debug!("handle: auth user and :user mismatch");
                return self.auth_error(StatusCode::UNAUTHORIZED, location).await;
            }
            Some(user)
        } else {
            None
        };

        // Now see if we want to do a account lookup, for uid/gid/homedir.
        let pwd = match self.acct(location, auth_user.as_ref(), user_param).await {
            Ok(pwd) => pwd,
            Err(status) => return self.auth_error(status, location).await,
        };

        // Expand "~" in the directory.
        let dir = match expand_directory(location.directory.as_str(), pwd.as_ref()) {
            Ok(d) => d,
            Err(_) => return self.error(StatusCode::NOT_FOUND).await,
        };

        // If :path matched, we can calculate the prefix.
        // If it didn't, the entire path _is_ the prefix.
        let prefix = match route.params[1].as_ref() {
            Some(p) => {
                let mut start = p.start();
                if start > 0 {
                    start -= 1;
                }
                &path[..start]
            },
            None => path,
        };
        let prefix = match std::str::from_utf8(prefix) {
            Ok(p) => p.to_string(),
            Err(_) => {
                debug!("handle: prefix is non-UTF8");
                return self.error(StatusCode::NOT_FOUND).await;
            },
        };

        // Get User-Agent for user-agent specific modes.
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("");

        // Case insensitivity wanted?
        let case_insensitive = match location.case_insensitive {
            Some(CaseInsensitive::True) => true,
            Some(CaseInsensitive::Ms) => user_agent.contains("Microsoft"),
            Some(CaseInsensitive::False) | None => false,
        };

        // macOS optimizations?
        let macos = user_agent.contains("WebDAVFS/") && user_agent.contains("Darwin");

        // Get the filesystem.
        let auth_ugid = if location.setuid {
            pwd.as_ref().map(|p| (p.uid, p.gid, p.groups.as_slice()))
        } else {
            None
        };
        let fs = match location.handler {
            Handler::Virtroot => {
                let auth_user = auth_user.as_ref().map(String::to_owned);
                RootFs::new(dir, auth_user, auth_ugid) as Box<dyn DavFileSystem>
            },
            Handler::Filesystem => {
                UserFs::new(dir, auth_ugid, true, case_insensitive, macos) as Box<dyn DavFileSystem>
            },
        };

        // Build a handler.
        let methods = location
            .methods
            .unwrap_or(DavMethodSet::from_vec(vec!["GET", "HEAD"]).unwrap());
        let hide_symlinks = location.hide_symlinks.clone().unwrap_or(true);

        let mut config = DavConfig::new()
            .filesystem(fs)
            .strip_prefix(prefix)
            .methods(methods)
            .hide_symlinks(hide_symlinks)
            .autoindex(location.autoindex);
        if let Some(auth_user) = auth_user {
            config = config.principal(auth_user);
        }
        if let Some(indexfile) = location.indexfile.clone() {
            config = config.indexfile(indexfile);
        }

        // All set.
        self.run_davhandler(config, req).await
    }

    async fn build_error(&self, code: StatusCode, location: Option<&Location>) -> HttpResult {
        let msg = format!(
            "<error>{} {}</error>\n",
            code.as_u16(),
            code.canonical_reason().unwrap_or("")
        );
        let mut response = self
            .response_builder()
            .status(code)
            .header("Content-Type", "text/xml");
        if code == StatusCode::UNAUTHORIZED {
            let realm = location.and_then(|location| location.accounts.realm.as_ref());
            let realm = realm.or(self.config.accounts.realm.as_ref());
            let realm = realm.map(|s| s.as_str()).unwrap_or("Webdav Server");
            response = response.header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm).as_str());
        }
        Ok(response.body(msg.into()).unwrap())
    }

    async fn auth_error(&self, code: StatusCode, location: &Location) -> HttpResult {
        self.build_error(code, Some(location)).await
    }

    async fn error(&self, code: StatusCode) -> HttpResult {
        self.build_error(code, None).await
    }

    // Call the davhandler, then add headers to the response.
    async fn run_davhandler(&self, config: DavConfig, req: HttpRequest) -> HttpResult {
        let resp = self.dh.handle_with(config, req).await;
        let (mut parts, body) = resp.into_parts();
        self.set_server_header(&mut parts.headers);
        Ok(http::Response::from_parts(parts, body))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // command line option processing.
    let matches = clap_app!(webdav_server =>
        (version: "0.3")
        (@arg CFG: -c --config +takes_value "configuration file (/etc/webdav-server.toml)")
        (@arg PORT: -p --port +takes_value "listen to this port on localhost only")
        (@arg DBG: -D --debug "enable debug level logging")
    )
    .get_matches();

    if matches.is_present("DBG") {
        use env_logger::Env;
        let level = "webdav_server=debug,webdav_handler=debug";
        env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
    } else {
        env_logger::init();
    }

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

    // build routes.
    if let Err(e) = config::build_routes(cfg.clone(), &mut config) {
        eprintln!("{}: {}: {}", PROGNAME, cfg, e);
        exit(1);
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
    if let Some(timeout) = config.unix.cache_timeout {
        cache::cached::set_pwcache_timeout(timeout);
    }

    // resolve addresses.
    let addrs = config.server.listen.clone().to_socket_addrs().unwrap_or_else(|e| {
        eprintln!("{}: {}: [server] listen: {:?}", PROGNAME, cfg, e);
        exit(1);
    });
    let tls_addrs = config.server.tls_listen.clone().to_socket_addrs().unwrap_or_else(|e| {
        eprintln!("{}: {}: [server] listen: {:?}", PROGNAME, cfg, e);
        exit(1);
    });

    // initialize auth early.
    let auth = auth::Auth::new(config.clone())?;

    // start tokio runtime and initialize the rest from within the runtime.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()?;

    rt.block_on(async move {
        // build servers (one for each listen address).
        let dav_server = Server::new(config.clone(), auth);
        let mut servers = Vec::new();
        let mut tls_servers = Vec::new();

        // Plaintext servers.
        for sockaddr in addrs {
            let listener = match make_listener(sockaddr) {
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
                        async move { dav_server.route(req, remote_addr).await }
                    };
                    Ok::<_, hyper::Error>(service_fn(func))
                }
            });
            let incoming = AddrIncoming::from_listener(listener)?;
            let server = hyper::Server::builder(incoming);
            println!("Listening on http://{:?}", sockaddr);

            servers.push(async move {
                if let Err(e) = server.serve(make_service).await {
                    eprintln!("{}: server error: {}", PROGNAME, e);
                    exit(1);
                }
            });
        }

        // TLS servers.
        for sockaddr in tls_addrs {
            let listener = make_listener(sockaddr).unwrap_or_else(|e| {
                eprintln!("{}: listener on {:?}: {}", PROGNAME, &sockaddr, e);
                exit(1);
            });
            let dav_server = dav_server.clone();
            let tls_config = tls_config(&config.server)?;
            let make_service = make_service_fn(move |stream: &TlsStream<AddrStream>| {
                let dav_server = dav_server.clone();
                let remote_addr = stream.get_ref().0.remote_addr();
                async move {
                    let func = move |req| {
                        let dav_server = dav_server.clone();
                        async move { dav_server.route(req, remote_addr).await }
                    };
                    Ok::<_, hyper::Error>(service_fn(func))
                }
            });

            // Since the server can exit when there's an error on the TlsStream,
            // we run it in a loop. Every time the loop is entered we dup() the
            // listening fd and create a new TcpListener. This way, we should
            // not lose any pending connections during a restart.
            let master_listen_fd = listener.as_raw_fd();
            std::mem::forget(listener);

            println!("Listening on http://{:?}", sockaddr);
            tls_servers.push(async move {
                loop {
                    // reuse the incoming socket after the server exits.
                    let listen_fd = match nix::unistd::dup(master_listen_fd) {
                        Ok(fd) => fd,
                        Err(e) => {
                            eprintln!("{}: server error: dup: {}", PROGNAME, e);
                            break;
                        }
                    };
                    // SAFETY: listen_fd is unique (we just dup'ed it).
                    let std_listen = unsafe { std::net::TcpListener::from_raw_fd(listen_fd) };
                    let listener = match tokio::net::TcpListener::from_std(std_listen) {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("{}: server error: new TcpListener: {}", PROGNAME, e);
                            break;
                        }
                    };
                    let a_incoming = match AddrIncoming::from_listener(listener) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("{}: server error: new AddrIncoming: {}", PROGNAME, e);
                            break;
                        }
                    };
                    let incoming = TlsListener::new(tls_config.clone(), a_incoming);
                    let server = hyper::Server::builder(incoming);
                    if let Err(e) = server.serve(make_service.clone()).await {
                        eprintln!("{}: server error: {} (retrying)", PROGNAME, e);
                    }
                }
            });
        }

        // drop privs.
        match (&config.server.uid, &config.server.gid) {
            (&Some(uid), &Some(gid)) => {
                if !suid::have_suid_privs() {
                    eprintln!(
                        "{}: insufficent priviliges to switch uid/gid (not root).",
                        PROGNAME
                    );
                    exit(1);
                }
                let keep_privs = config.location.iter().any(|l| l.setuid);
                proc_switch_ugid(uid, gid, keep_privs);
            },
            _ => {},
        }

        // spawn all servers, and wait for them to finish.
        let mut tasks = Vec::new();
        for server in servers.drain(..) {
            tasks.push(tokio::spawn(server));
        }
        for server in tls_servers.drain(..) {
            tasks.push(tokio::spawn(server));
        }
        for task in tasks.drain(..) {
            let _ = task.await;
        }

        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

// Clones a http request with an empty body.
fn clone_httpreq(req: &HttpRequest) -> HttpRequest {
    let mut builder = http::Request::builder()
        .method(req.method().clone())
        .uri(req.uri().clone())
        .version(req.version().clone());
    for (name, value) in req.headers().iter() {
        builder = builder.header(name, value);
    }
    builder.body(hyper::Body::empty()).unwrap()
}

fn expand_directory(dir: &str, pwd: Option<&Arc<unixuser::User>>) -> Result<String, StatusCode> {
    // If it doesn't start with "~", skip.
    if !dir.starts_with("~") {
        return Ok(dir.to_string());
    }
    // ~whatever doesn't work.
    if dir.len() > 1 && !dir.starts_with("~/") {
        debug!("expand_directory: rejecting {}", dir);
        return Err(StatusCode::NOT_FOUND);
    }
    // must have a directory, and that dir must be UTF-8.
    let pwd = match pwd {
        Some(pwd) => pwd,
        None => {
            debug!("expand_directory: cannot expand {}: no account", dir);
            return Err(StatusCode::NOT_FOUND);
        },
    };
    let homedir = pwd.dir.to_str().ok_or(StatusCode::NOT_FOUND)?;
    Ok(format!("{}/{}", homedir, &dir[1..]))
}

// Make a new TcpListener, and if it's a V6 listener, set the
// V6_V6ONLY socket option on it.
fn make_listener(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, SockAddr, Socket, Type, Protocol};
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    s.set_nodelay(true)?;
    s.set_reuse_address(true)?;
    let addr: SockAddr = addr.into();
    s.bind(&addr)?;
    s.listen(128)?;
    let listener: std::net::TcpListener = s.into();
    tokio::net::TcpListener::from_std(listener)
}
