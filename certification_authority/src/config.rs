use serde::{Deserialize, Serialize};
use shared_library::safe_read::{safe_read, SafeReadError};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::path::PathBuf;
use thiserror::Error;

const TOML_EXT: Option<&str> = Some("toml");
const PEM_EXT: Option<&str> = Some("pem");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    network: NetworkConfig,
    keys: KeyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    ip: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CaContext {
    pub address: SocketAddr,
    pub ca_cert_pem: Vec<u8>,
    pub ca_key_pem: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid UTF-8 inside the CA TOML configuration file: {0}")]
    TomlNotUtf8(String),

    #[error("failed to parse the CA TOML configuration file: {0}")]
    Parse(String),

    #[error(transparent)]
    SafeRead(#[from] SafeReadError),
}

#[derive(Debug, Error)]
pub enum ContextConversionError {
    #[error(transparent)]
    SafeRead(#[from] SafeReadError),

    #[error("invalid CA listener IP address: {0}")]
    InvalidIp(String),

    #[error("port 0 is not valid for the CA listener")]
    InvalidPort,
}

impl Config {
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let raw_toml = String::from_utf8(safe_read(path, TOML_EXT)?)
            .map_err(|e| ConfigError::TomlNotUtf8(e.to_string()))?;

        toml::from_str(&raw_toml).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    pub fn to_context(self) -> Result<CaContext, ContextConversionError> {
        let ip = self
            .network
            .ip
            .parse::<IpAddr>()
            .map_err(|e| ContextConversionError::InvalidIp(e.to_string()))?;

        let port = NonZeroU16::new(self.network.port).ok_or(ContextConversionError::InvalidPort)?;

        let address = SocketAddr::new(ip, port.get());

        let ca_cert_pem = safe_read(self.keys.ca_cert_path, PEM_EXT)?;
        let ca_key_pem = safe_read(self.keys.ca_key_path, PEM_EXT)?;

        Ok(CaContext {
            address,
            ca_cert_pem,
            ca_key_pem,
        })
    }
}
