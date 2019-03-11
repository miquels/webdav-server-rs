use std::{fs, io};
use std::path::Path;
use std::net::{SocketAddr, ToSocketAddrs};

use serde::{Deserialize, Deserializer};
use toml;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    server:     Server,
    accounts:   Option<Accounts>,
    webdav:     Option<Webdav>,
    pam:        Option<Pam>,
    unix:       Option<Unix>,
    rootfs:     Option<RootFs>,
    users:      Option<Users>
}

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    pub listen:         OneOrManyAddr,
    //#[serde(deserialize_with = "deserialize_user", default)]
    pub uid:            Option<u32>,
    //#[serde(deserialize_with = "deserialize_group", default)]
    pub gid:            Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Accounts {
    #[serde(rename = "acct-type")]
    acct_type:      String,
    #[serde(rename = "auth-type")]
    auth_type:      String,
    #[serde(default)]
    setuid:         bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Webdav {
    pub locking:    String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Pam {
    pub service:                String,
    #[serde(rename = "cache-timeout-between")]
    pub cache_timeout_between:  Option<usize>,
    #[serde(rename = "cache-timeout-absolute")]
    pub cache_timeout_absolute: Option<usize>,
    pub threads:                Option<usize>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Unix {
    #[serde(rename = "cache-timeout")]
    pub cache_timeout:  Option<usize>,
    #[serde(rename = "min-uid", default)]
    pub min_uid:        u32,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RootFs {
    pub path:       String,
    pub directory:  String,
    pub index:      Option<String>,
    #[serde(default)]
    pub auth:       bool,
    #[serde(default)]
    pub webdav:     bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Users {
    pub path:       String,
    #[serde(default)]
    pub dirindex:   bool,
}

#[derive(Deserialize,Debug,Clone)]
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
    s.parse::<u32>().map(|v| Some(v)).map_err(serde::de::Error::custom)
}

#[allow(unused)]
pub fn deserialize_group<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
        where D: Deserializer<'de> {

    let s = String::deserialize(deserializer)?;
    s.parse::<u32>().map(|v| Some(v)).map_err(serde::de::Error::custom)
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

