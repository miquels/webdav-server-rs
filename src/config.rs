use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::exit;
use std::{fs, io};

use serde::{Deserialize, Deserializer};
use toml;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub server: Server,
    pub accounts: Accounts,
    #[serde(default)]
    pub webdav: Webdav,
    #[serde(default)]
    pub pam: Pam,
    #[serde(default)]
    pub unix: Unix,
    pub rootfs: Option<RootFs>,
    pub users: Option<Users>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    pub listen: OneOrManyAddr,
    //#[serde(deserialize_with = "deserialize_user", default)]
    pub uid: Option<u32>,
    //#[serde(deserialize_with = "deserialize_group", default)]
    pub gid: Option<u32>,
    #[serde(default)]
    pub identification: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Accounts {
    #[serde(rename = "acct-type")]
    pub acct_type: String,
    #[serde(rename = "auth-type")]
    pub auth_type: String,
    #[serde(default)]
    pub setuid: bool,
    #[serde(default)]
    pub realm: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Webdav {
    #[serde(default)]
    pub locksystem: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Pam {
    pub service: String,
    #[serde(rename = "cache-timeout")]
    pub cache_timeout: Option<usize>,
    pub threads: Option<usize>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Unix {
    #[serde(rename = "cache-timeout")]
    pub cache_timeout: Option<usize>,
    #[serde(rename = "min-uid", default)]
    pub min_uid: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RootFs {
    pub path: String,
    pub directory: String,
    pub index: Option<String>,
    #[serde(default)]
    pub auth: bool,
    #[serde(default)]
    pub webdav: Option<bool>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Users {
    pub path: String,
    #[serde(default)]
    pub hide_symlinks: Option<bool>,
    #[serde(default)]
    pub ms_case_insensitive: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum OneOrManyAddr {
    One(SocketAddr),
    Many(Vec<SocketAddr>),
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

pub fn check(cfg: &str, config: &Config) {
    if config.accounts.acct_type != "unix" {
        eprintln!(
            "{}: [accounts]: unknown acct-type: {}",
            cfg, config.accounts.acct_type
        );
        exit(1);
    }
    if config.accounts.auth_type != "pam" {
        eprintln!(
            "{}: [accounts]: unknown auth-type: {}",
            cfg, config.accounts.auth_type
        );
        exit(1);
    }
    if config.pam.service == "" {
        eprintln!("{}: missing section [pam]", cfg);
        exit(1);
    }
    match config.webdav.locksystem.as_str() {
        "" | "none" | "fakels" | "memls" => {},
        _ => {
            eprintln!(
                "{}: [webdav]: unknown locksystem: {}",
                cfg, config.webdav.locksystem
            );
            exit(1);
        },
    }
    if config.rootfs.is_none() && config.users.is_none() {
        eprintln!("{}: must have at least one of [rootfs] or [users]", cfg);
        exit(1);
    }
    if config.accounts.setuid {
        if !crate::suid::has_thread_switch_ugid() {
            eprintln!("{}: [accounts]: setuid: uid switching not supported on this OS", cfg);
            exit(1);
        }
        if config.server.uid.is_none() || config.server.gid.is_none() {
            eprintln!("{}: [server]: missing uid and/or gid", cfg);
            exit(1);
        }
    }
    if let Some(ref users) = config.users {
        if users.path.contains(":username") && !users.path.ends_with(":username") {
            eprintln!("{}: [users]: :username must be at the end of the path", cfg);
            exit(1);
        }
    }
}
