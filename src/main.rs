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
use webdav_handler::{DavConfig, DavHandler, localfs::LocalFs, fakels::FakeLs};

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

        // get first segment of url.
        let x = req.uri().path().splitn(3, "/").collect::<Vec<&str>>();
        if x.len() < 2 {
            // can't happen, means there was no "/" in the path.
            return Box::new(self.handle_error(StatusCode::UNAUTHORIZED));
        }
        let nseg = x.len() - 1;
        let first_seg = percent_decode(x[1].as_bytes()).decode_utf8_lossy().into_owned();

        // If we ask for "/" or "/file" with GET or HEAD, serve from local fs.
        if nseg == 1 && (req.method() == &http::Method::GET || req.method() == &http::Method::HEAD) {
            return Box::new(self.handle_realroot(req, first_seg));
        }

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
            .then(move |res| {

                // handle errors.
                let pwd = match res {
                    Err(e) => return Either3::A(self2.handle_error(e)),
                    Ok(res) => res,
                };

                // Check if username matches basedir.
                if nseg >= 2 && first_seg != user.as_str() {
                    // in /<something>/ but doesn't match username.
                    debug!("Server::handle: user {} path /{} -> 401", user, first_seg);
                    return Either3::A(self2.handle_error(StatusCode::UNAUTHORIZED));
                }

                // either virtual root or userfs.
                if nseg < 2 {
                    Either3::B(self2.handle_root(req, pwd))
                } else {
                    Either3::C(self2.handle_user(req, pwd))
                }
            });
        Box::new(fut)
    }

    fn handle_error(&self, code: StatusCode)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        let msg = format!("<error>{} {}</error>\n",
                          code.as_u16(), code.canonical_reason().unwrap_or(""));
        let mut response = hyper::Response::builder();
        response.status(code);
        response.header("Content-Type", "text/xml");
        if code == StatusCode::UNAUTHORIZED {
            response.header("WWW-Authenticate", "Basic realm=\"XS4ALL Webdisk\"");
        }
        let resp = response.body(msg.into()).unwrap();
        futures::future::ok(resp)
    }

    fn handle_redirect(&self, path: String)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        let resp = hyper::Response::builder()
            .status(302)
            .header("content-type", "text/plain")
            .header("location", path)
            .body("302 Moved\n".into()).unwrap();
        futures::future::ok(resp)
    }

    fn handle_realroot(&self, req: hyper::Request<hyper::Body>, first_seg: String)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        let self2 = self.clone();
        let mut req = req;

        // If this part of the path is a valid user, redirect.
        // Otherwise serve from the local filesystem.
        cached::User::by_name(&first_seg)
            .then(move |res| {
                match res {
                    Ok(_) => {
                        debug!("Server::handle_realroot: redirect to /{}/", first_seg);
                        Either::A(self2.handle_redirect("/".to_string() + &first_seg + "/"))
                    },
                    Err(_) => {
                        if first_seg == "" {
                            let mut parts = req.uri().clone().into_parts();
                            let pq = http::uri::PathAndQuery::from_static("/index.html");
                            parts.path_and_query = Some(pq);
                            *req.uri_mut() = http::uri::Uri::from_parts(parts).unwrap();
                        }
                        debug!("Server::handle_realroot: serving {:?}", req.uri());
                        let fs = LocalFs::new(&self2.directory, true);
                        let config = DavConfig {
                            fs:         Some(fs),
                            ..DavConfig::default()
                        };
                        Either::B(self2.run_davhandler(req, config))
                    }
                }
            })
    }

    fn handle_root(&self, req: hyper::Request<hyper::Body>, pwd: Arc<unixuser::User>)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        debug!("Server::handle_root: /");
        let fs = RootFs::new(pwd.name.clone(), &pwd.dir, pwd.uid, pwd.gid);
        let ls = FakeLs::new();
        let config = DavConfig {
            fs:         Some(fs),
            ls:         Some(ls),
            principal:  Some(pwd.name.to_string()),
            ..DavConfig::default()
        };
        self.run_davhandler(req, config)
    }

    fn handle_user(&self, req: hyper::Request<hyper::Body>, pwd: Arc<unixuser::User>)
        -> impl Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error>
    {
        // in /user
        let prefix = "/".to_string() + &pwd.name;
        let fs = UserFs::new(&pwd.dir, Some((pwd.uid, pwd.gid)), true);
        let ls = FakeLs::new();
        debug!("Server::handle_user: in userdir {} prefix {} ", pwd.name, prefix);
        let config = DavConfig {
            prefix:     Some(prefix),
            fs:         Some(fs),
            ls:         Some(ls),
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

