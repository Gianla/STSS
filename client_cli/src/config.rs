use client_core::client::ClientContext;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use shared_library::safe_read::{SafeReadError, safe_read};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZero;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

const TOML_EXT: Option<&str> = Some(".toml");
const PEM_EXT: Option<&str> = Some(".pem");

/// Possible errors while reading the toml file.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid utf8 encoding of the .toml file: {0:?}")]
    TomlNotInUtf8(String),

    #[error("failed to parse the .toml file: {0:?}")]
    Parse(String),

    #[error(transparent)]
    SafeRead(#[from] SafeReadError),

    #[error("cannot automatically detect the port")]
    UnreliablePort,
}

/// Possible errors while reading the toml file.
#[derive(Error, Debug)]
pub enum ContextConversionError {
    #[error(transparent)]
    SafeRead(#[from] SafeReadError),

    #[error("failed to parse the given ip {0:?}")]
    IpParse(String),

    #[error("cannot automatically detect the port")]
    UnreliablePort,

    #[error("cannot parse the specified certificate: {0}")]
    CertificateParse(String),

    #[error("cannot parse the specified public key: it is not in UTF-8")]
    PublicKeyNotInUtf8,

    #[error("cannot parse the specified public key: {0:?}")]
    PublicKeyParse(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    timestamp: TimestampConfig,
    keys: KeyConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TimestampConfig {
    server_ip: String,
    server_port: u16,
    server_certificate_name: String,
    trust_roots_certificates: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyConfig {
    ca_cert_path: PathBuf,
    server_rsa_public_key_path: PathBuf,
}

impl Config {
    pub fn new(
        server_ip: String,
        server_port: NonZero<u16>,
        server_certificate_name: impl Into<String>,
        trust_roots_certificates: bool,
        ca_cert_path: impl Into<PathBuf>,
        server_rsa_public_key_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            timestamp: TimestampConfig {
                server_ip: "".to_string(),
                server_port: server_port.get(),
                server_certificate_name: server_certificate_name.into(),
                trust_roots_certificates,
            },
            keys: KeyConfig {
                ca_cert_path: ca_cert_path.into(),
                server_rsa_public_key_path: server_rsa_public_key_path.into(),
            },
        }
    }

    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let raw_toml = String::from_utf8(safe_read(path, TOML_EXT)?)
            .map_err(|e| ConfigError::TomlNotInUtf8(e.to_string()))?;

        let conf: Config =
            toml::from_str(&raw_toml).map_err(|e| ConfigError::Parse(e.to_string()))?;

        Ok(conf)
    }

    pub fn to_client_context(self) -> Result<ClientContext, ContextConversionError> {
        let ip = self
            .timestamp
            .server_ip
            .parse::<IpAddr>()
            .map_err(|e| ContextConversionError::IpParse(e.to_string()))?;

        if self.timestamp.server_port == 0 {
            return Err(ContextConversionError::UnreliablePort);
        }

        let server_address = SocketAddr::new(ip, self.timestamp.server_port);

        let ca_cert_bytes = safe_read(self.keys.ca_cert_path, PEM_EXT)?;
        let mut ca_cert_bytes_slice = ca_cert_bytes.as_slice();
        let ca_certs = rustls_pemfile::certs(&mut ca_cert_bytes_slice)
            .map(|cert| cert.map_err(|e| ContextConversionError::CertificateParse(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;

        let server_rsa_public_key_bytes = safe_read(self.keys.server_rsa_public_key_path, PEM_EXT)?;
        let server_rsa_public_key_str = str::from_utf8(&server_rsa_public_key_bytes)
            .map_err(|_| ContextConversionError::PublicKeyNotInUtf8)?;

        let server_rsa_public_key = RsaPublicKey::from_public_key_pem(server_rsa_public_key_str)
            .map_err(|e| ContextConversionError::PublicKeyParse(e.to_string()))?;

        Ok(ClientContext::new(
            server_address,
            self.timestamp.server_certificate_name,
            ca_certs,
            server_rsa_public_key,
            self.timestamp.trust_roots_certificates,
        ))
    }
}
