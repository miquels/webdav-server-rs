use std::fs::File;
use std::io;

use tokio_rustls::rustls::internal::pemfile;
use tokio_rustls::rustls::{NoClientAuth, ServerConfig};

use crate::config::Server;

pub fn tls_config(cfg: &Server) -> io::Result<ServerConfig> {
    let pkey_fn = cfg.tls_key.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "config: server: tls_key not set")
    })?;
    let cert_fn = cfg.tls_cert.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "config: server: tls_cert not set")
    })?;
    let pkey_file = File::open(pkey_fn).map_err(|e| {
        io::Error::new(e.kind(), format!("{}: {}", pkey_fn, e))
    })?;
    let mut pkey_file = io::BufReader::new(pkey_file);
    let cert_file = File::open(cert_fn).map_err(|e| {
        io::Error::new(e.kind(), format!("{}: {}", cert_fn, e))
    })?;
    let mut cert_file = io::BufReader::new(cert_file);
    let mut pkey = pemfile::rsa_private_keys(&mut pkey_file).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: invalid data", pkey_fn))
    })?;
    if pkey.len() != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: expected one private key (found {})", pkey_fn, pkey.len())));
    }
    let cert = pemfile::certs(&mut cert_file).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: invalid data", cert_fn))
    })?;
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_single_cert(cert, pkey.pop().unwrap()).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}/{}: {}", pkey_fn, cert_fn, e))
    })?;
    Ok(config)
}

