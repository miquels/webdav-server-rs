//
//  Sample application.
//
//  Listens on localhost:4918, plain http, no ssl.
//  Connect to http://localhost:4918/<DIR>/
//

#[macro_use] extern crate clap;
#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;

mod quotafs;
mod rootfs;
mod unixuser;
mod cache;
mod cached;
mod suid;

use std::net::SocketAddr;
use std::str::FromStr;

use percent_encoding::percent_decode;
use futures::prelude::*;
use futures;
use bytes::Bytes;
use hyper;
use http;
use http::status::StatusCode;
use env_logger;

use webdav_handler as dav;
use webdav_handler::typed_headers::{HeaderMapExt, Authorization, Basic};
use crate::dav::{DavConfig, DavHandler};

use crate::quotafs::QuotaFs;
use crate::rootfs::RootFs;
use crate::suid::{thread_setresuid, thread_setresgid};

#[derive(Clone)]
struct Server {
    dh:         DavHandler,
    directory:  String,
}

type BoxedFuture = Box<Future<Item=hyper::Response<hyper::Body>, Error=std::io::Error> + Send>;

fn box_response(msg: &str, code: StatusCode) -> BoxedFuture {
    let body = futures::stream::once(Ok(Bytes::from(msg)));
    let body: webdav_handler::BoxedByteStream = Box::new(body);
    let body = hyper::Body::wrap_stream(body);
    let mut response = hyper::Response::builder();
    response.status(code);
    if code == StatusCode::UNAUTHORIZED {
        response.header("WWW-Authenticate", "Basic realm=\"XS4ALL Webdisk\"");
    }
    let resp = response.body(body).unwrap();
    return Box::new(futures::future::ok(resp));
}

impl Server {
    pub fn new(rootdir: String) -> Self {
        let mut methods = dav::AllowedMethods::none();
        methods.add(dav::Method::Get);
        methods.add(dav::Method::PropFind);
        methods.add(dav::Method::Options);
        let dh = DavHandler::new_with(DavConfig{
            allow:  Some(methods),
            ..DavConfig::default()
        });
        Server{
            dh:         dh,
            directory:  rootdir,
        }
    }

    fn handle(&self, req: hyper::Request<hyper::Body>) -> BoxedFuture {

        // we must have a login/pass
        let (user, _pass) = match req.headers().typed_get::<Authorization<Basic>>() {
            Some(Authorization(Basic{
                                username,
                                password: Some(password)
                            }
            )) => (username, password),
            _ => return box_response("Authentication required", StatusCode::UNAUTHORIZED),
        };

        // see if user exists.
        let pwd = match cached::getpwnam_cached(&user) {
            Ok(p) => p,
            Err(_) => return box_response("Authentication required", StatusCode::UNAUTHORIZED),
        };

        // XXX FIXME call PAM to authenticate.

        // XXX FIXME handle OPTIONS * (is that being used? check webdisk logs)

        let config = {
            // get first segment of url.
            let x = req.uri().path().splitn(3, "/").collect::<Vec<&str>>();
            if x.len() < 2 {
                return box_response("Authentication required", StatusCode::UNAUTHORIZED);
            }
            let nseg = x.len() - 1;
            let first_seg = percent_decode(x[1].as_bytes()).decode_utf8_lossy();

            let config = if nseg < 2 {
                println!("in / ");
                // in "/", create a synthetic home directory.
                let fs = RootFs::new(user.to_string(), &self.directory, true, 0xfffffffe);
                DavConfig {
                    fs:         Some(fs),
                    principal:  Some(user.to_string()),
                    ..DavConfig::default()
                }
            } else if first_seg != user.as_str() {
                // in /<something>/ but doesn't match username.
                println!("user {} path {}", first_seg, user);
                return box_response("Authentication required", StatusCode::UNAUTHORIZED);
            } else {
                // in /user
                let uid = pwd.uid;
                let gid = pwd.gid;
                let start = move || {
                    if let Err(e) = thread_setresgid(Some(gid), Some(gid), None) {
                        panic!("thread_setresgid({}, {}, -1): {}", gid, gid, e);
                    }
                    if let Err(e) = thread_setresuid(Some(uid), Some(uid), None) {
                        panic!("thread_setresuid({}, {}, -1): {}", uid, uid, e);
                    }
                    debug!("start request-hook")
                };
                let stop = || {
                    /*
                    if let Err(e) = thread_setresgid(Some(33), Some(33), None) {
                        panic!("thread_setresgid({}, {}, -1): {}", 33, 33, e);
                    }*/
                    if let Err(e) = thread_setresuid(Some(33), Some(33), None) {
                        panic!("thread_setresuid({}, {}, -1): {}", 33, 33, e);
                    }
                    debug!("start request-hook")
                };
                let prefix = "/".to_string() + &user;
                let fs = QuotaFs::new(&pwd.dir, pwd.uid, true);
                println!("in userdir {} prefix {} ", user, prefix);
                DavConfig {
                    prefix:     Some(prefix),
                    fs:         Some(fs),
                    principal:  Some(user.to_string()),
                    reqhooks:   Some((Box::new(start), Box::new(stop))),
                    ..DavConfig::default()
                }
            };
            config
        };

        // transform hyper::Request into http::Request, run handler,
        // then transform http::Response into hyper::Response.
        let (parts, body) = req.into_parts();
        let body = body.map(|item| Bytes::from(item));
        let req = http::Request::from_parts(parts, body);
        let fut = self.dh.handle_with(config, req)
            .and_then(|resp| {
                let (parts, body) = resp.into_parts();
                let body = hyper::Body::wrap_stream(body);
                Ok(hyper::Response::from_parts(parts, body))
            });
        Box::new(fut)
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

    let dav_server = Server::new(dir.to_string());
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

    println!("Serving {} on {}", dir, port);
    hyper::rt::run(server);

    Ok(())
}

