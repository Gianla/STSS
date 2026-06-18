#![allow(dead_code)]

use futures::{SinkExt, StreamExt};
use rcgen::{CertificateParams, DnType, DnValue, KeyPair, PKCS_ED25519};
use shared_library::ca_protocol::{Request, Response};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::{fs, io};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[derive(Error, Debug)]
pub enum RekeyClientError {
    #[error("invalid CA's address")]
    InvalidCaAddress,

    #[error("invalid server's ip address")]
    InvalidIp,

    #[error("invalid server's name address")]
    InvalidName,

    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum SignRequestError {
    #[error("error while creating the certificate: {0}")]
    CACertificateCreation(String),

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("connection closed by the CA")]
    ConnectionClosed,

    #[error("CA refused to sign the certificate: {0}")]
    Refused(String),

    #[error("unexpected response received from CA")]
    UnexpectedResponse,
}

struct RekeyClient {
    server_ip: IpAddr,
    organization_name: DnValue,
    server_name: DnValue,
    output: PathBuf,
    stream: Framed<TcpStream, LengthDelimitedCodec>,
}

impl RekeyClient {
    pub async fn new(
        server_ip: IpAddr,
        organization_name: DnValue,
        server_name: DnValue,
        output: impl Into<PathBuf>,
        address: SocketAddr,
    ) -> Result<Self, RekeyClientError> {
        let tcp_stream = TcpStream::connect(address).await?;
        let stream = Framed::new(tcp_stream, LengthDelimitedCodec::new());

        Ok(Self {
            server_ip,
            organization_name,
            server_name,
            output: output.into(),
            stream,
        })
    }

    pub async fn new_cert_sign_request(mut self) -> Result<(), SignRequestError> {
        let server_tls_keypair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| SignRequestError::CACertificateCreation(e.to_string()))?;

        let mut server_tls_params = CertificateParams::new(vec![self.server_ip.to_string()])
            .map_err(|e| SignRequestError::CACertificateCreation(e.to_string()))?;

        server_tls_params
            .distinguished_name
            .push(DnType::OrganizationName, self.organization_name.clone());

        server_tls_params
            .distinguished_name
            .push(DnType::CommonName, self.server_name.clone());

        let csr = server_tls_params
            .serialize_request(&server_tls_keypair)
            .map_err(|e| SignRequestError::CACertificateCreation(e.to_string()))?;

        let raw_cert = csr.der().to_vec();

        let request = Request::CertificateSign { raw_cert };

        let serialized_req = request
            .serialize()
            .map_err(|e| SignRequestError::Serialization(e.to_string()))?;

        self.stream
            .send(serialized_req)
            .await
            .map_err(|e| SignRequestError::NetworkError(e.to_string()))?;

        if let Some(response_result) = self.stream.next().await {
            let raw_frame =
                response_result.map_err(|e| SignRequestError::NetworkError(e.to_string()))?;

            let deserialized_response = Response::deserialize(&raw_frame)
                .map_err(|e| SignRequestError::Deserialization(e.to_string()))?;

            match deserialized_response {
                Response::Ok { pem_cert } => {
                    fs::write(&self.output, pem_cert).map_err(SignRequestError::IoError)?;
                    println!(
                        "[+] Signed certificate successfully received from CA and written to {}",
                        self.output.display()
                    );
                    Ok(())
                }
                Response::CanNotSignTheCertificate { reason } => {
                    Err(SignRequestError::Refused(reason))
                }
            }
        } else {
            Err(SignRequestError::ConnectionClosed)
        }
    }
}

#[derive(Error, Debug)]
pub enum RekeyClientManagerError {
    #[error(transparent)]
    RekeyClient(#[from] RekeyClientError),

    #[error(transparent)]
    SignRequest(#[from] SignRequestError),
}

pub struct RekeyClientManager {
    server_ip: IpAddr,
    organization_name: DnValue,
    server_name: DnValue,
    output: PathBuf,
    address: SocketAddr,
    runtime: tokio::runtime::Runtime,
}

impl RekeyClientManager {
    pub fn build(
        server_ip: IpAddr,
        organization_name: DnValue,
        server_name: DnValue,
        output: impl Into<PathBuf>,
        address: SocketAddr,
    ) -> Result<Self, io::Error> {
        let runtime = tokio::runtime::Runtime::new()?;

        Ok(Self {
            server_ip,
            organization_name,
            server_name,
            output: output.into(),
            address,
            runtime,
        })
    }

    pub fn rekey(self) -> Result<(), RekeyClientManagerError> {
        self.runtime.block_on(async move {
            let instance = RekeyClient::new(
                self.server_ip,
                self.organization_name,
                self.server_name,
                self.output,
                self.address,
            )
            .await?;

            instance.new_cert_sign_request().await?;

            Ok(())
        })
    }
}
