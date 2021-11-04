use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::exit;
use std::{fs, io};

use enum_from_str::ParseEnumVariantError;
use enum_from_str_derive::FromStr;
use serde::{Deserialize, Deserializer};
use toml;
use webdav_handler::DavMethodSet;

use crate::router::Router;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub server:   Server,
    #[serde(default)]
    pub accounts: Accounts,
    #[serde(default)]
    pub pam:      Pam,
    #[serde(default)]
    pub htpasswd: HashMap<String, HtPasswd>,
    #[serde(default)]
    pub unix:     Unix,
    #[serde(default)]
    pub location: Vec<Location>,
    #[serde(skip)]
    pub router:   Router<usize>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    #[serde(default)]
    pub listen:         OneOrManyAddr,
    #[serde(default)]
    pub tls_listen:     OneOrManyAddr,
    #[serde(default)]
    pub tls_key:        Option<String>,
    #[serde(default)]
    pub tls_cert:       Option<String>,
    //#[serde(deserialize_with = "deserialize_user", default)]
    pub uid:            Option<u32>,
    //#[serde(deserialize_with = "deserialize_group", default)]
    pub gid:            Option<u32>,
    #[serde(default)]
    pub identification: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Accounts {
    #[serde(rename = "auth-type", deserialize_with = "deserialize_authtype", default)]
    pub auth_type: Option<AuthType>,
    #[serde(rename = "acct-type", deserialize_with = "deserialize_opt_enum", default)]
    pub acct_type: Option<AcctType>,
    #[serde(default)]
    pub realm:     Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Pam {
    pub service:       String,
    #[serde(rename = "cache-timeout")]
    pub cache_timeout: Option<usize>,
    pub threads:       Option<usize>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct HtPasswd {
    pub htpasswd: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Unix {
    #[serde(rename = "cache-timeout")]
    pub cache_timeout: Option<usize>,
    #[serde(rename = "min-uid", default)]
    pub min_uid:       Option<u32>,
    #[serde(rename = "supplementary-groups", default)]
    pub aux_groups:    bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Location {
    #[serde(default)]
    pub route:            Vec<String>,
    #[serde(deserialize_with = "deserialize_methodset", default)]
    pub methods:          Option<DavMethodSet>,
    #[serde(deserialize_with = "deserialize_opt_enum", default)]
    pub auth:             Option<Auth>,
    #[serde(default, flatten)]
    pub accounts:         Accounts,
    #[serde(deserialize_with = "deserialize_enum")]
    pub handler:          Handler,
    #[serde(default)]
    pub setuid:           bool,
    pub directory:        String,
    #[serde(default, alias = "hide-symlinks")]
    pub hide_symlinks:    Option<bool>,
    #[serde(default)]
    pub indexfile:        Option<String>,
    #[serde(default)]
    pub autoindex:        bool,
    #[serde(
        rename = "case-insensitive",
        deserialize_with = "deserialize_opt_enum",
        default
    )]
    pub case_insensitive: Option<CaseInsensitive>,
    #[serde(deserialize_with = "deserialize_opt_enum", default)]
    pub on_notfound:      Option<OnNotfound>,
}

#[derive(FromStr, Debug, Clone, Copy)]
pub enum Handler {
    #[from_str = "virtroot"]
    Virtroot,
    #[from_str = "filesystem"]
    Filesystem,
}

#[derive(FromStr, Debug, Clone, Copy)]
pub enum Auth {
    #[from_str = "false"]
    False,
    #[from_str = "true"]
    True,
    #[from_str = "opportunistic"]
    Opportunistic,
    #[from_str = "write"]
    Write,
}

#[derive(Debug, Clone)]
pub enum AuthType {
    #[cfg(feature = "pam")]
    Pam,
    HtPasswd(String),
}

#[derive(FromStr, Debug, Clone, Copy)]
pub enum AcctType {
    #[from_str = "unix"]
    Unix,
}

#[derive(FromStr, Debug, Clone, Copy)]
pub enum CaseInsensitive {
    #[from_str = "true"]
    True,
    #[from_str = "ms"]
    Ms,
    #[from_str = "false"]
    False,
}

#[derive(FromStr, Debug, Clone, Copy)]
pub enum OnNotfound {
    #[from_str = "continue"]
    Continue,
    #[from_str = "return"]
    Return,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum OneOrManyAddr {
    One(SocketAddr),
    Many(Vec<SocketAddr>),
}

impl OneOrManyAddr {
    pub fn is_empty(&self) -> bool {
        match self {
            OneOrManyAddr::One(_) => false,
            OneOrManyAddr::Many(v) => v.is_empty(),
        }
    }
}

impl Default for OneOrManyAddr {
    fn default() -> Self {
        OneOrManyAddr::Many(Vec::new())
    }
}

impl ToSocketAddrs for OneOrManyAddr {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<std::vec::IntoIter<SocketAddr>> {
        let i = match self {
            OneOrManyAddr::Many(ref v) => v.to_owned(),
            OneOrManyAddr::One(ref s) => vec![*s],
        };
        Ok(i.into_iter())
    }
}

// keep this here for now, we might implement a enum{(u32, String} later for
// usernames and groupnames.
#[allow(unused)]
pub fn deserialize_user<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;
    s.parse::<u32>()
        .map(|v| Some(v))
        .map_err(serde::de::Error::custom)
}

#[allow(unused)]
pub fn deserialize_group<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;
    s.parse::<u32>()
        .map(|v| Some(v))
        .map_err(serde::de::Error::custom)
}

pub fn deserialize_methodset<'de, D>(deserializer: D) -> Result<Option<DavMethodSet>, D::Error>
where D: Deserializer<'de> {
    let m = Vec::<String>::deserialize(deserializer)?;
    DavMethodSet::from_vec(m)
        .map(|v| Some(v))
        .map_err(serde::de::Error::custom)
}

pub fn deserialize_authtype<'de, D>(deserializer: D) -> Result<Option<AuthType>, D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;
    if s.starts_with("htpasswd.") {
        return Ok(Some(AuthType::HtPasswd(s[9..].to_string())));
    }
    #[cfg(feature = "pam")]
    if &s == "pam" {
        return Ok(Some(AuthType::Pam));
    }
    if s == "" {
        return Ok(None);
    }
    Err(serde::de::Error::custom("unknown auth-type"))
}

pub fn deserialize_opt_enum<'de, D, E>(deserializer: D) -> Result<Option<E>, D::Error>
where
    D: Deserializer<'de>,
    E: std::str::FromStr,
    E::Err: std::fmt::Display,
{
    String::deserialize(deserializer)?
        .as_str()
        .parse::<E>()
        .map(|e| Some(e))
        .map_err(serde::de::Error::custom)
}

pub fn deserialize_enum<'de, D, E>(deserializer: D) -> Result<E, D::Error>
where
    D: Deserializer<'de>,
    E: std::str::FromStr,
    E::Err: std::fmt::Display,
{
    String::deserialize(deserializer)?
        .as_str()
        .parse::<E>()
        .map_err(serde::de::Error::custom)
}

// Read the TOML config into a config::Config struct.
pub fn read(toml_file: impl AsRef<Path>) -> io::Result<Config> {
    let buffer = fs::read_to_string(&toml_file)?;

    // initial parse.
    let config: Config = match toml::from_str(&buffer) {
        Ok(v) => Ok(v),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }?;

    Ok(config)
}

pub fn build_routes(cfg: &str, config: &mut Config) -> io::Result<()> {
    let mut builder = Router::builder();
    for (idx, location) in config.location.iter().enumerate() {
        for r in &location.route {
            if let Err(e) = builder.add(r, location.methods.clone(), idx) {
                let msg = format!("{}: [[location]][{}]: route {}: {}", cfg, idx, r, e);
                return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
            }
        }
    }
    config.router = builder.build();
    Ok(())
}

pub fn check(cfg: &str, config: &Config) {
    #[cfg(feature = "pam")]
    if let Some(AuthType::Pam) = config.accounts.auth_type {
        if config.pam.service == "" {
            eprintln!("{}: missing section [pam]", cfg);
            exit(1);
        }
    }

    if config.server.listen.is_empty() && config.server.tls_listen.is_empty() {
        eprintln!("{}: [server]: at least one of listen or tls_listen must be set", cfg);
        exit(1);
    }
    if !config.server.tls_listen.is_empty() {
        if config.server.tls_cert.is_none() {
            eprintln!("{}: [server]: tls_cert not set", cfg);
            exit(1);
        }
        if config.server.tls_key.is_none() {
            eprintln!("{}: [server]: tls_key not set", cfg);
            exit(1);
        }
    }

    for (idx, location) in config.location.iter().enumerate() {
        if location.setuid {
            if !crate::suid::has_thread_switch_ugid() {
                eprintln!(
                    "{}: [[location]][{}]: setuid: uid switching not supported on this OS",
                    cfg, idx
                );
                exit(1);
            }
            if config.server.uid.is_none() || config.server.gid.is_none() {
                eprintln!("{}: [server]: missing uid and/or gid", cfg);
                exit(1);
            }
            if config.accounts.acct_type.is_none() && location.accounts.acct_type.is_none() {
                eprintln!("{}: [[location]][{}]: setuid: no acct-type set", cfg, idx);
                exit(1);
            }
        }
    }
}
