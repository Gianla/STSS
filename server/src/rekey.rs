#![allow(dead_code)]

use futures::{SinkExt, StreamExt};
use rcgen::{CertificateParams, DnType, DnValue, KeyPair, PKCS_ED25519};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use shared_library::ca_protocol::{Request, Response};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Errors that might arise while creating the small rekey client.
#[derive(Error, Debug)]
pub enum RekeyClientError {
    #[error("invalid CA's address")]
    InvalidCaAddress,

    #[error("invalid server's ip address")]
    InvalidIp,

    #[error("invalid server's name address")]
    InvalidName,

    #[error("invalid DNS name")]
    InvalidDnsName,

    #[error("TLS error: {0}")]
    Tls(String),

    #[error(transparent)]
    IoError(#[from] io::Error),
}

/// Errors that might arise during the certificate sign request process.
#[derive(Error, Debug)]
pub enum SignRequestError {
    #[error("error while setting up the tls connection: {0}")]
    Tls(String),

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

    #[error("connection closed by the server")]
    ConnectionClosed,

    #[error("unexpected response received from CA")]
    UnexpectedResponse,
}

/// The asynchronous Rekey Client.
pub struct RekeyClient {
    server_ip: IpAddr,
    organization_name: DnValue,
    server_name: DnValue,
    output: PathBuf,
    stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
}

impl RekeyClient {
    /// Establishes an asynchronous TLS connection to the CA and returns the initialized client.
    pub async fn new(
        server_ip: IpAddr,
        organization_name: DnValue,
        server_name: DnValue,
        ca_name: String,
        output: impl Into<PathBuf>,
        address: SocketAddr,
    ) -> Result<Self, RekeyClientError> {
        // 1. Initialize the Root Certificate Store
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // 2. Build the TLS Client Configuration
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(config));

        // 3. Parse the expected CA Server Name for SNI validation
        let domain = ServerName::try_from(ca_name)
            .map_err(|_| RekeyClientError::InvalidDnsName)?
            .to_owned();

        // 4. Establish the asynchronous TCP connection
        let tcp_stream = TcpStream::connect(address).await?;

        // 5. Perform the TLS handshake over the TCP stream
        let tls_stream = tls_connector.connect(domain, tcp_stream).await?;

        // 6. Wrap the TLS stream in a Framed codec
        let stream = Framed::new(tls_stream, LengthDelimitedCodec::new());

        Ok(Self {
            server_ip,
            organization_name,
            server_name,
            output: output.into(),
            stream,
        })
    }

    /// Generates a new Certificate Signing Request (CSR) and sends it to the CA.
    pub async fn new_cert_sign_request(mut self) -> Result<(), SignRequestError> {
        // 1. Generate the Server TLS KeyPair
        let server_tls_keypair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| SignRequestError::Tls(e.to_string()))?;

        // 2. Create the server's Certificate Params
        let mut server_tls_params = CertificateParams::new(vec![self.server_ip.to_string()])
            .map_err(|e| SignRequestError::CACertificateCreation(e.to_string()))?;

        server_tls_params
            .distinguished_name
            .push(DnType::OrganizationName, self.organization_name.clone());

        server_tls_params
            .distinguished_name
            .push(DnType::CommonName, self.server_name.clone());

        // 3. Serialize the request into DER format bytes
        let csr = server_tls_params
            .serialize_request(&server_tls_keypair)
            .map_err(|e| SignRequestError::CACertificateCreation(e.to_string()))?;

        let raw_cert = csr.der().to_vec();

        // 4. Build the protocol Request
        let request = Request::CertificateSign { raw_cert };

        // 5. Serialize the custom protocol request (mapping your schema errors)
        let serialized_req = request
            .serialize()
            .map_err(|e| SignRequestError::Serialization(e.to_string()))?;

        // 6. Send the request over the Framed stream
        self.stream
            .send(serialized_req)
            .await
            .map_err(|e| SignRequestError::NetworkError(e.to_string()))?;

        // 7. Await and process the Response
        if let Some(response_result) = self.stream.next().await {
            // Check if there was an I/O error reading the frame
            let raw_frame =
                response_result.map_err(|e| SignRequestError::NetworkError(e.to_string()))?;

            // Deserialize the payload into the Response enum
            let deserialized_response = Response::deserialize(&raw_frame)
                .map_err(|e| SignRequestError::Deserialization(e.to_string()))?;

            // Handle the response logic
            match deserialized_response {
                Response::Ok { pem_cert } => {
                    fs::write(self.output, pem_cert).map_err(SignRequestError::IoError)
                }
                _ => Err(SignRequestError::UnexpectedResponse),
            }
        } else {
            // The stream returned None, meaning the connection was closed cleanly but prematurely.
            Err(SignRequestError::ConnectionClosed)
        }
    }
}
