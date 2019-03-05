//
//  Sample application.
//
//  Listens on localhost:4918, plain http, no ssl.
//  Connect to http://localhost:4918/<DIR>/
//
#![feature(async_await, await_macro, futures_api)]

#[macro_use] extern crate clap;
#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;

mod userfs;
mod rootfs;
mod unixuser;
mod cache;
mod cached;
mod suid;
mod either;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use percent_encoding::percent_decode;
use futures::prelude::*;
use futures::future::Either;
use futures;
use bytes::Bytes;
use hyper;
use http;
use http::status::StatusCode;
use env_logger;
use tokio;

use tokio_pam::PamAuth;
use webdav_handler::typed_headers::{HeaderMapExt, Authorization, Basic};
use webdav_handler::{DavConfig, DavHandler, localfs::LocalFs};

use crate::userfs::UserFs;
use crate::rootfs::RootFs;
use crate::suid::switch_ugid;
use crate::either::*;

#[derive(Clone)]
struct Server {
    dh:         DavHandler,
    directory:  String,
    uid:        u32,
    gid:        u32,
    pam_auth:   PamAuth,
}

type BoxedFuture = Box<Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error> + Send>;

impl Server {
    pub fn new(rootdir: String, auth: PamAuth) -> Self {
        let mut methods = webdav_handler::AllowedMethods::none();
        methods.add(webdav_handler::Method::Get);
        methods.add(webdav_handler::Method::PropFind);
        methods.add(webdav_handler::Method::Options);
        let dh = DavHandler::new_with(DavConfig{
            allow:  Some(methods),
            ..DavConfig::default()
        });
        Server{
            dh:         dh,
            directory:  rootdir,
            pam_auth:   auth,
            uid:        33,
            gid:        33,
        }
    }

    fn handle(&self, req: hyper::Request<hyper::Body>) -> BoxedFuture {

        // we must have a login/pass
        let (user, pass) = match req.headers().typed_get::<Authorization<Basic>>() {
            Some(Authorization(Basic{
                                username,
                                password: Some(password)
                            }
            )) => (username, password),
            _ => return Box::new(self.handle_error(StatusCode::UNAUTHORIZED)),
        };

        let pam_auth = self.pam_auth.clone();
        let self2 = self.clone();

        // start by checking if user exists.
        let fut = cached::User::by_name(&user)
            .map_err(|_| StatusCode::UNAUTHORIZED)
            .and_then(move |pwd| {
                // authenticate user.
                cached::PamAuth::auth(pam_auth, "other", &pwd.name, &pass, None)
                    .map_err(|_| StatusCode::UNAUTHORIZED)
                    .map(move |_| pwd)
            })
            .and_then(move |pwd| {

                // get first segment of url.
                let x = req.uri().path().splitn(3, "/").collect::<Vec<&str>>();
                if x.len() < 2 {
                    return Err(StatusCode::UNAUTHORIZED);
                }
                let nseg = x.len() - 1;
                let first_seg = percent_decode(x[1].as_bytes()).decode_utf8_lossy().into_owned();

                // Check if username matches basedir.
                if nseg >= 2 && first_seg != user.as_str() {
                    // in /<something>/ but doesn't match username.
                    debug!("Server::handle: user {} path /{} -> 401", user, first_seg);
                    return Err(StatusCode::UNAUTHORIZED);
                }

                Ok((req, pwd, first_seg, nseg))
            }).then(move |res| {

                let (req, pwd, first_seg, nseg) = match res {
                    Err(e) => return Either3::A(self2.handle_error(e)),
                    Ok(res) => res,
                };

                if nseg < 2 {
                    Either3::B(self2.handle_root(req, pwd, first_seg))
                } else {
                    Either3::C(self2.handle_user(req, pwd, first_seg))
                }
            });
        Box::new(fut)
    }

    fn handle_error(&self, code: StatusCode)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        let msg = format!("<error>{} {}</error>\n",
                          code.as_u16(), code.canonical_reason().unwrap_or(""));
        let body = futures::stream::once(Ok(Bytes::from(msg)));
        let body: webdav_handler::BoxedByteStream = Box::new(body);
        let body = hyper::Body::wrap_stream(body);
        let mut response = hyper::Response::builder();
        response.status(code);
        response.header("Content-Type", "text/xml");
        if code == StatusCode::UNAUTHORIZED {
            response.header("WWW-Authenticate", "Basic realm=\"XS4ALL Webdisk\"");
        }
        let resp = response.body(body).unwrap();
        futures::future::ok(resp)
    }

    fn handle_root(&self, req: hyper::Request<hyper::Body>, pwd: Arc<unixuser::User>, first_seg: String)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        if first_seg == "" {
            // in "/", create a synthetic home directory.
            debug!("Server::handle_root: /");
            let fs = RootFs::new(pwd.name.clone(), &self.directory, true, self.uid, self.gid);
            let config = DavConfig {
                fs:         Some(fs),
                principal:  Some(pwd.name.to_string()),
                ..DavConfig::default()
            };
            Either::A(self.run_davhandler(req, config))
        } else {
            // in "/" asking for specific file.
            let fs = LocalFs::new(&self.directory, true);

            // FIXME: make async.
            let mut path = std::path::PathBuf::from(&self.directory);
            path.push(&first_seg);

            if !std::fs::metadata(&path).is_ok() {
                debug!("Server::handle_root: /{} does not exist", first_seg);

                // file does not exist. If first_seg is a username, return
                // 401 Unauthorized, otherwise return 404 Not Found.
                let self2 = self.clone();
                let fut = cached::User::by_name(&first_seg)
                    .then(move |res| {
                        let code = match res {
                            Ok(_) => StatusCode::UNAUTHORIZED,
                            Err(_) => StatusCode::NOT_FOUND,
                        };
                        self2.handle_error(code)
                    });
                Either::B(fut)
            } else {
                debug!("Server::handle_root: /{} exists, serving", first_seg);
                let config = DavConfig {
                    fs:         Some(fs),
                    principal:  Some(pwd.name.to_string()),
                    ..DavConfig::default()
                };
                Either::A(self.run_davhandler(req, config))
            }
        }
    }

    fn handle_user(&self, req: hyper::Request<hyper::Body>, pwd: Arc<unixuser::User>, _first_seg: String)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        // in /user
        let prefix = "/".to_string() + &pwd.name;
        let fs = UserFs::new(&pwd.dir, Some((pwd.uid, pwd.gid)), true);
        debug!("Server::handle_user: in userdir {} prefix {} ", pwd.name, prefix);
        let config = DavConfig {
            prefix:     Some(prefix),
            fs:         Some(fs),
            principal:  Some(pwd.name.to_string()),
            ..DavConfig::default()
        };
        self.run_davhandler(req, config)
    }

    fn run_davhandler(&self, req: hyper::Request<hyper::Body>, config: DavConfig)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        // transform hyper::Request into http::Request, run handler,
        // then transform http::Response into hyper::Response.
        let (parts, body) = req.into_parts();
        let body = body.map(|item| Bytes::from(item));
        let req = http::Request::from_parts(parts, body);
        self.dh.handle_with(config, req)
            .and_then(|resp| {
                let (parts, body) = resp.into_parts();
                let body = hyper::Body::wrap_stream(body);
                Ok(hyper::Response::from_parts(parts, body))
            })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = clap_app!(webdav_server =>
        (version: "0.1")
        (@arg PORT: -p --port +takes_value "port to listen on (4918)")
        (@arg DIR: -d --dir +takes_value "local directory to serve")
    ).get_matches();

    let dir = matches.value_of("DIR").unwrap_or("/var/tmp");

    let (pam, pam_task) = PamAuth::lazy_new()?;

    let dav_server = Server::new(dir.to_string(), pam);
    let make_service = move || {
        let dav_server = dav_server.clone();
        hyper::service::service_fn(move |req| {
            dav_server.handle(req)
        })
    };

    let port = matches.value_of("PORT").unwrap_or("4918");
    let addr = "0.0.0.0:".to_string() + port;
    let addr = SocketAddr::from_str(&addr)?;
    let server = hyper::Server::try_bind(&addr)?
        .serve(make_service)
        .map_err(|e| eprintln!("server error: {}", e));

    // drop privs.
    switch_ugid(33, 33);

    let mut rt = tokio::runtime::Runtime::new()?;
    rt.spawn(pam_task.map_err(|_e| debug!("pam_task returned error {}", _e)));

    println!("Serving {} on {}", dir, port);
    rt.block_on_all(server.map_err(|_e| debug!("hyper server returned error {:?}", _e))).is_ok();

    Ok(())
}

