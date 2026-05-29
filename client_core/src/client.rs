use bytes::Bytes;
use futures::StreamExt;
use futures::sink::SinkExt;
use rsa::RsaPublicKey;
use rustls::pki_types::CertificateDer;
use shared_library::server_protocol::{
    DeserializeError, Request, Response, SerializeError, Sha256Hash, Timestamp,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct ClientContext {
    timestamp: TimestampContext,
    keys: KeyContext,
}

pub struct TimestampContext {
    server_address: SocketAddr,
    server_certificate_name: String,
}

pub struct KeyContext {
    ca_cert: Vec<CertificateDer<'static>>,
    server_rsa_public_key: RsaPublicKey,
    trust_roots_cert: bool,
}

impl ClientContext {
    pub fn new(
        server_address: impl Into<SocketAddr>,
        server_certificate_name: impl Into<String>,
        ca_cert: Vec<CertificateDer<'static>>,
        server_rsa_public_key: RsaPublicKey,
        trust_roots_cert: bool,
    ) -> Self {
        Self {
            timestamp: TimestampContext {
                server_address: server_address.into(),
                server_certificate_name: server_certificate_name.into(),
            },
            keys: KeyContext {
                ca_cert,
                server_rsa_public_key,
                trust_roots_cert,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampToken {
    pub hash: [u8; 32],
    pub timestamp: Timestamp,
    pub signature: Vec<u8>,
}

/// Errors returned by the client library.
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("invalid DNS/server name {0:?}")]
    InvalidServerName(String),

    #[error("invalid CA certificate: {0}")]
    InvalidCaCertificate(String),

    #[error("the CA certificate file does not contain any certificate")]
    EmptyCaCertificate,

    #[error("server closed the connection before sending a response")]
    ServerClosedConnection,

    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("expected a SHA-256 hash of 32 bytes, got {0} bytes")]
    InvalidHashLength(usize),

    #[error("unexpected response from server: {0:?}")]
    UnexpectedResponse(Response),

    #[error("the provided server name {0:?} is invalid")]
    InvalidDnsName(String),

    #[error(transparent)]
    Serialize(#[from] SerializeError),

    #[error(transparent)]
    Deserialize(#[from] DeserializeError),
}

pub struct STSSClient {
    stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    server_rsa_public_key: RsaPublicKey,
}

impl STSSClient {
    pub async fn connect_from_context(
        ClientContext { keys, timestamp }: ClientContext,
    ) -> Result<Self, ClientError> {
        let domain = ServerName::try_from(timestamp.server_certificate_name.as_str())
            .map_err(|_| ClientError::InvalidDnsName(timestamp.server_certificate_name.clone()))?
            .to_owned();

        let mut root_cert_store = RootCertStore::empty();

        let (_added, _ignored) = root_cert_store.add_parsable_certificates(keys.ca_cert);

        if keys.trust_roots_cert {
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(config));

        let tcp_stream = TcpStream::connect(timestamp.server_address).await?;
        let tls_stream = tls_connector.connect(domain, tcp_stream).await?;
        let framed_stream_stream = Framed::new(tls_stream, LengthDelimitedCodec::new());

        Ok(Self {
            stream: framed_stream_stream,
            server_rsa_public_key: keys.server_rsa_public_key,
        })
    }

    pub async fn close(self) -> Result<(), io::Error> {
        let mut tls_stream = self.stream.into_inner();
        tls_stream.shutdown().await
    }

    #[inline(always)]
    pub fn server_rsa_public_key(&self) -> &RsaPublicKey {
        &self.server_rsa_public_key
    }

    /// Sends one protocol send_request and waits for exactly one protocol response.
    #[inline(always)]
    pub async fn send_request(&mut self, request: Request) -> Result<Response, ClientError> {
        let serialized_request: Bytes = request.serialize()?;

        self.stream.send(serialized_request).await?;

        let raw_response = self
            .stream
            .next()
            .await
            .ok_or(ClientError::ServerClosedConnection)??;

        Ok(Response::deserialize(raw_response)?)
    }

    /// Authenticates as an existing user on the current connection.
    pub async fn login(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Response, ClientError> {
        self.send_request(Request::Login(username.into(), password.into()))
            .await
    }

    /// Registers as a new user.
    pub async fn signup(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Response, ClientError> {
        self.send_request(Request::SignUp(username.into(), password.into()))
            .await
    }

    /// Logs out from the current authenticated session.
    pub async fn logout(&mut self) -> Result<Response, ClientError> {
        self.send_request(Request::LogOut).await
    }

    /// Asks how many tokens the currently logged user owns.
    pub async fn how_many_tokens(&mut self) -> Result<Response, ClientError> {
        self.send_request(Request::HowManyTokensDoIHave).await
    }

    /// Purchases `amount` tokens.
    pub async fn purchase_tokens(&mut self, amount: u64) -> Result<Response, ClientError> {
        self.send_request(Request::PurchaseTokens(amount)).await
    }

    /// Requests a timestamp over an already-computed SHA-256 hash.
    pub async fn timestamp_hash(&mut self, hash: Sha256Hash) -> Result<Response, ClientError> {
        self.send_request(Request::SignHash(hash)).await
    }

    /// Requests the history of the signed hashes.
    pub async fn history(&mut self) -> Result<Response, ClientError> {
        self.send_request(Request::History).await
    }
}
