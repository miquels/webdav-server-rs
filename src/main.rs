//
//  Sample application.
//
//  Listens on localhost:4918, plain http, no ssl.
//  Connect to http://localhost:4918/<DIR>/
//

#[macro_use] extern crate hyper;
#[macro_use] extern crate clap;
#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;
extern crate env_logger;
extern crate webdav_handler;
extern crate libc;
extern crate pam;
extern crate fs_quota;

use std::path::PathBuf;

use hyper::header::{Authorization, Basic};
use hyper::server::{Handler,Request, Response};
use hyper::status::StatusCode;

use webdav_handler as dav;
use dav::DavHandler;

use libc::{uid_t,gid_t};

mod suidfs;
mod rootfs;
mod unixuser;
mod cache;
mod cached;

header! { (WWWAuthenticate, "WWW-Authenticate") => [String] }

#[derive(Debug)]
struct Server {
    directory:      String,
}

impl Server {
    pub fn new(directory: String) -> Self {
        Server{
            directory:      directory,
        }
    }
}

fn authenticate(req: &Request, user: &str) -> Option<(String, String, uid_t, gid_t, PathBuf)> {
    // we must have a login/pass
    // some nice destructuring going on here eh.
    let (u, p) = match req.headers.get::<Authorization<Basic>>() {
        Some(&Authorization(Basic{
                                ref username,
                                password: Some(ref password)
                            }
        )) => (username, password),
        _ => return None,
    };
    if u != user && user != "" {
        return None;
    }

    // find user.
    let pwd = match cached::getpwnam_cached(u) {
        Ok(p) => p,
        Err(_) => return None,
    };

    // authenticate
    if let Err(e) = cached::pam_auth_cached("webdav", u, p, "") {
        debug!("pam error {}", e);
        return None;
    }
    Some((u.to_string(), "/".to_string() + u, pwd.uid, pwd.gid, pwd.dir.clone()))
}

impl Handler for Server {

    //fn handle<'a, 'k>(&'a self, req: Request<'a, 'k>, mut res: Response<'a>) {
    fn handle(&self, req: Request, mut res: Response) {

        // Get request path.
        let path = match req.uri {
            hyper::uri::RequestUri::AbsolutePath(ref s) => s.to_string(),
            _ => {
                *res.status_mut() = StatusCode::BadRequest;
                return;
            }
        };

        // NOTE we no not percent-decode here, if this was a real
        // application that would be bad.
        let x = path.splitn(3, "/").collect::<Vec<&str>>();
        let (user, prefix, uid, gid, dir) = match authenticate(&req, x[1]) {
            Some(result) => result,
            None => {
                res.headers_mut().set(WWWAuthenticate(
                        "Basic realm=\"XS4ALL Webdisk\"".to_string()));
                *res.status_mut() = StatusCode::Unauthorized;
                return;
            },
        };

        if x[1] == "" {
            // in "/", create a synthetic home directory.
            let fs = rootfs::RootFs::new(user, dir, true, uid, gid, 33, 33);
            let dav = DavHandler::new("/".to_string(), fs)
                .allow(dav::Method::PropFind)
                .allow(dav::Method::Options);
            dav.handle(req, res);
        } else {
            // in /user
            let fs = suidfs::SuidFs::new(dir, true, uid, gid, 33, 33);
            let dav = DavHandler::new(prefix, fs);
            dav.handle(req, res);
        }
    }
}

fn main() {
    env_logger::init().unwrap();

    let matches = clap_app!(webdav_lib =>
        (version: "0.1")
        (@arg PORT: -p --port +takes_value "port to listen on (4918)")
        (@arg DIR: -d --dir +takes_value "local directory to serve")
    ).get_matches();

    let dir = matches.value_of("DIR").unwrap_or("/var/tmp");
    let port = matches.value_of("PORT").unwrap_or("4918");
    let port = "0.0.0.0:".to_string() + port;
    let hyper_server = hyper::server::Server::http(&port).unwrap();
    let dav_server = Server::new(dir.to_string());

    pam::init_worker();

    println!("Listening on {}", port);
    hyper_server.handle_threads(dav_server, 8).unwrap();
}

