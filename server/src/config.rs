//! Contains all the utils to load and parse the configurations of the server.

use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

use crate::database::DataBaseLocation;
use crate::server::{KeyContext, LogDestination, NetworkPort, RuntimeContext, ServerContext};
use crate::time_oracle::{TimeOracle, TimeOracleError, TimeOracleType};
use shared_library::safe_read::{safe_read, SafeReadError};

const PEM_EXT: Option<&str> = Some("pem");
const TOML_EXT: Option<&str> = Some("toml");

/// Represent the raw configurations found in the toml file.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    network: NetworkConfig,
    runtime: RuntimeConfig,
    keys: KeysConfig,
    synced_time_oracle: Option<SyncedTimeOracleConfig>,
    log: Option<PathBuf>,
}

impl Config {
    pub fn new(
        network: NetworkConfig,
        runtime: RuntimeConfig,
        keys: KeysConfig,
        time_oracle: Option<SyncedTimeOracleConfig>,
        log: Option<PathBuf>,
    ) -> Self {
        Self {
            network,
            runtime,
            keys,
            synced_time_oracle: time_oracle,
            log,
        }
    }
}

/// Network utils of the server.
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkConfig {
    ip: String, // Stored in String type to be human-readable.
    port: u16,  // serde will fail if encounters a number that requires more than 16 bits
                // to be represented.
}

impl NetworkConfig {
    pub fn new(ip: String, port: u16) -> Self {
        Self { ip, port }
    }
}

/// Configurations of the coroutines. In general, we want to support old machines that aren't
/// likely to support hardware acceleration. In this scenario, cryptography threads will be used
/// to perform heavy, cryptographical calculations.
#[derive(Serialize, Deserialize, Debug)]
pub struct RuntimeConfig {
    working_threads: usize,      // Threads destined to handle network connections.
    cryptography_threads: usize, // Threads that will perform heavy calculations.
}

impl RuntimeConfig {
    pub fn new(working_threads: usize, cryptography_threads: usize) -> Self {
        Self {
            working_threads,
            cryptography_threads,
        }
    }
}

/// Two pairs of keys for the tls connection and the RSA signing.
#[derive(Serialize, Deserialize, Debug)]
pub struct KeysConfig {
    tls_cert_path: PathBuf,
    tls_priv_path: PathBuf,
    tss_priv_path: PathBuf,
    ca_cert_path: PathBuf,
}

impl KeysConfig {
    pub fn new(
        tls_cert_path: impl Into<PathBuf>,
        tls_priv_path: impl Into<PathBuf>,
        tss_priv_path: impl Into<PathBuf>,
        ca_cert_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            tls_cert_path: tls_cert_path.into(),
            tls_priv_path: tls_priv_path.into(),
            tss_priv_path: tss_priv_path.into(),
            ca_cert_path: ca_cert_path.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SyncedTimeOracleConfig {
    ntp_server_host: String,
    ntp_server_port: u16,
    listener_ip: String,
    listener_port: u16,
    sync_interval_in_minutes: u16,
}

impl SyncedTimeOracleConfig {
    pub fn new(
        ntp_server_host: String,
        ntp_server_port: u16,
        listener_ip: String,
        listener_port: u16,
        sync_interval_in_minutes: u16,
    ) -> Self {
        Self {
            ntp_server_host,
            ntp_server_port,
            listener_ip,
            listener_port,
            sync_interval_in_minutes,
        }
    }
}

/// Possible errors while reading the toml file.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid utf8 encoding of the .toml file: {0:?}")]
    TomlNotInUtf8(String),

    #[error("failed to parse the .toml file: {0:?}")]
    Parse(String),

    #[error(transparent)]
    SafeRead(#[from] SafeReadError),
}

/// Possible errors while parsing the toml file.
#[derive(Error, Debug)]
pub enum ServerConfigConversionError {
    #[error("failed to parse the ip address: {0:?}")]
    IpParse(String),

    #[error("failed to parse the TLS certificates: {0:?}")]
    CertificateParse(String),

    #[error("failed to parse the TLS private key: {0:?}")]
    TlsKeyParse(String),

    #[error("didn't find any TLS private key")]
    TlsKeyNotFound,

    #[error("failed to parse the signing key: {0:?}")]
    TssKeyParse(String),

    #[error("failed to retrieve the filename of the log file")]
    InvalidFileName,

    #[error(
        "port has been set to zero: although this means to let the OS decide it, the Client won't \
         have an efficient way to contact the server"
    )]
    UnreliablePort,

    #[error("expected a smaller amount of minutes")]
    TooManyMinutes,

    #[error(transparent)]
    TimeOracle(#[from] TimeOracleError),

    #[error(transparent)]
    SafeRead(#[from] SafeReadError),
}

impl Config {
    /// Parse a toml file to obtain a Config object.
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let raw_toml = String::from_utf8(safe_read(path, TOML_EXT)?)
            .map_err(|e| ConfigError::TomlNotInUtf8(e.to_string()))?;

        let conf: Config =
            toml::from_str(&raw_toml).map_err(|e| ConfigError::Parse(e.to_string()))?;

        Ok(conf)
    }

    pub fn get_ca_certificate(
        self,
    ) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, ServerConfigConversionError> {
        // --- load the certificate ---
        let ca_cert_bytes = safe_read(self.keys.ca_cert_path, PEM_EXT)?;
        let mut ca_cert_bytes_slice = ca_cert_bytes.as_slice();

        let certs = rustls_pemfile::certs(&mut ca_cert_bytes_slice)
            // hard way to just say "let rust figure it out on its own": tls_certs will just be a
            // result where the Ok() branch contains a vector of certificates. We don't care about
            // the error since it'll be mapped if any.
            .map(|cert| {
                cert.map_err(|e| ServerConfigConversionError::CertificateParse(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(certs)
    }

    /// Converts all raw info into something usable by the server.
    pub fn to_server_context(self) -> Result<ServerContext, ServerConfigConversionError> {
        let ip = self
            .network
            .ip
            .parse::<IpAddr>()
            .map_err(|e| ServerConfigConversionError::IpParse(e.to_string()))?;

        if self.network.port == 0 {
            return Err(ServerConfigConversionError::UnreliablePort);
        }

        let destination = match self.log {
            Some(path) => {
                let parent = path.parent().unwrap_or(Path::new(""));

                let dir = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };

                let filename = path
                    .file_name()
                    .ok_or(ServerConfigConversionError::InvalidFileName)?;

                LogDestination::File {
                    dir: dir.to_path_buf(),
                    filename: PathBuf::from(filename),
                }
            }
            None => LogDestination::Stdout,
        };

        // --- load the certificate ---
        let tls_cert_bytes = safe_read(self.keys.tls_cert_path, PEM_EXT)?;
        let mut tls_cert_bytes_slice = tls_cert_bytes.as_slice();
        let tls_certs = rustls_pemfile::certs(&mut tls_cert_bytes_slice)
            // read get_ca_certificate() for more info.
            .map(|cert| {
                cert.map_err(|e| ServerConfigConversionError::CertificateParse(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // --- load the tls private key ---
        let tls_key_bytes = safe_read(self.keys.tls_priv_path, PEM_EXT)?;
        let mut tls_key_bytes_slice = tls_key_bytes.as_slice();
        let tls_priv = rustls_pemfile::private_key(&mut tls_key_bytes_slice)
            .map_err(|e| ServerConfigConversionError::TlsKeyParse(e.to_string()))?
            .ok_or(ServerConfigConversionError::TlsKeyNotFound)?;

        // --- load the tss private key ---
        let tss_key_bytes = safe_read(self.keys.tss_priv_path, PEM_EXT)?;

        let pem_str = String::from_utf8(tss_key_bytes)
            .map_err(|e| ServerConfigConversionError::TssKeyParse(e.to_string()))?;

        let tss_priv = RsaPrivateKey::from_pkcs8_pem(&pem_str)
            .map_err(|e| ServerConfigConversionError::TssKeyParse(e.to_string()))?;

        // --- load the time oracle configurations ---

        let time_oracle = match self.synced_time_oracle {
            Some(time_oracle_config) => {
                let ntp_server_port = NetworkPort::from(time_oracle_config.ntp_server_port);

                let time_oracle_ip: IpAddr = IpAddr::from_str(&time_oracle_config.listener_ip)
                    .map_err(|e| ServerConfigConversionError::IpParse(e.to_string()))?;

                let time_oracle_address =
                    SocketAddr::new(time_oracle_ip, time_oracle_config.listener_port);

                let interval_in_seconds =
                    match time_oracle_config.sync_interval_in_minutes.checked_mul(60) {
                        None => return Err(ServerConfigConversionError::TooManyMinutes),
                        Some(sync_interval) => sync_interval,
                    };

                let bundle = TimeOracle::create_bundle(
                    time_oracle_config.ntp_server_host,
                    ntp_server_port,
                    time_oracle_address,
                    Duration::from_secs(interval_in_seconds as u64),
                )?;
                TimeOracleType::Synced(bundle)
            }
            None => {
                let build = TimeOracle::new_local();
                TimeOracleType::Local(build)
            }
        };

        Ok(ServerContext::new(
            SocketAddr::new(ip, self.network.port),
            RuntimeContext::new(
                self.runtime.working_threads,
                self.runtime.cryptography_threads,
            ),
            KeyContext::new(tls_certs, tls_priv, tss_priv),
            time_oracle,
            destination,
            DataBaseLocation::Memory,
        ))
    }
}
