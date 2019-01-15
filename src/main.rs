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
use crate::dav::{DavConfig, DavHandler, fs::DavFileSystem, localfs::LocalFs, webpath::WebPath};

use crate::quotafs::QuotaFs;
use crate::rootfs::RootFs;
use crate::suid::switch_uid;

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

        // get first segment of url.
        let x = req.uri().path().splitn(3, "/").collect::<Vec<&str>>();
        if x.len() < 2 {
            return box_response("Authentication required", StatusCode::UNAUTHORIZED);
        }
        let nseg = x.len() - 1;
        let first_seg = percent_decode(x[1].as_bytes()).decode_utf8_lossy();
        debug!("* nseg {} x {:?}", nseg, x);

        // Check if username matches basedir.
        if nseg >= 2 && first_seg != user.as_str() {
            // in /<something>/ but doesn't match username.
            debug!("user {} path {}", first_seg, user);
            return box_response("Authentication required", StatusCode::UNAUTHORIZED);
        }

        let config = if nseg < 2 {
            if first_seg == "" {
                // in "/", create a synthetic home directory.
                debug!("in /");
                let fs = RootFs::new(user.to_string(), &self.directory, true, 0xfffffffe);
                DavConfig {
                    fs:         Some(fs),
                    principal:  Some(user.to_string()),
                    ..DavConfig::default()
                }
            } else {
                // in "/" asking for specific file.
                debug!("in root, /{}", first_seg);
                let fs = LocalFs::new(&self.directory, true);
                let path = "/".to_string() + &first_seg;
                let path = WebPath::from_str(&path, "").unwrap();
                if !fs.metadata(&path).is_ok() {
                    debug!("/{} does not exist", first_seg);
                    // file does not exist. If first_seg is a username, return
                    // 401 Unauthorized, otherwise return 404 Not Found.
                    if cached::getpwnam_cached(&first_seg).is_ok() {
                        return box_response("Authentication required", StatusCode::UNAUTHORIZED);
                    } else {
                        return box_response("Not found", StatusCode::NOT_FOUND);
                    }
                }
                debug!("/{} exists, serving", first_seg);
                DavConfig {
                    fs:         Some(fs),
                    principal:  Some(user.to_string()),
                    ..DavConfig::default()
                }
            }
        } else {
            // in /user
            let uid = pwd.uid;
            let gid = pwd.gid;
            let start = move || switch_uid(33, uid, gid);
            let uid = pwd.uid;
            let stop = move || switch_uid(uid, 33, gid);
            let prefix = "/".to_string() + &user;
            let fs = QuotaFs::new(&pwd.dir, pwd.uid, true);
            debug!("in userdir {} prefix {} ", user, prefix);
            DavConfig {
                prefix:     Some(prefix),
                fs:         Some(fs),
                principal:  Some(user.to_string()),
                reqhooks:   Some((Box::new(start), Box::new(stop))),
                ..DavConfig::default()
            }
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

