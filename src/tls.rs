use std::fs::File;
use std::io::{self, ErrorKind};
use std::sync::Arc;

use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use rustls_pemfile as pemfile;

use crate::config::Server;

pub fn tls_acceptor(cfg: &Server) -> io::Result<TlsAcceptor> {

    // Private key.
    let pkey_fn = cfg.tls_key.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "config: server: tls_key not set")
    })?;
    let pkey_file = File::open(pkey_fn).map_err(|e| {
        io::Error::new(e.kind(), format!("{}: {}", pkey_fn, e))
    })?;
    let mut pkey_file = io::BufReader::new(pkey_file);
    let pkey = match pemfile::read_one(&mut pkey_file) {
        Ok(Some(pemfile::Item::RSAKey(pkey))) => PrivateKey(pkey),
        Ok(Some(pemfile::Item::PKCS8Key(pkey))) => PrivateKey(pkey),
        Ok(Some(pemfile::Item::ECKey(pkey))) => PrivateKey(pkey),
        Ok(Some(_)) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: unknown private key format", pkey_fn))),
        Ok(None) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: expected one private key", pkey_fn))),
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: invalid data", pkey_fn))),
    };

    // Certificate.
    let cert_fn = cfg.tls_cert.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "config: server: tls_cert not set")
    })?;
    let cert_file = File::open(cert_fn).map_err(|e| {
        io::Error::new(e.kind(), format!("{}: {}", cert_fn, e))
    })?;
    let mut cert_file = io::BufReader::new(cert_file);
    let certs = pemfile::certs(&mut cert_file).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: invalid data", cert_fn))
    })?;
    let certs = certs
        .into_iter()
        .map(|cert| Certificate(cert.into()))
        .collect();

    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, pkey)
            .map_err(|e| {
                io::Error::new(ErrorKind::InvalidData, format!("{}/{}: {}", pkey_fn, cert_fn, e))
            })?
    ).into();

    Ok(config)
}

