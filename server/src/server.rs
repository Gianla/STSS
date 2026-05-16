//! Contains the main component for the server, with network and cryptography utilities.

use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::connection_handler::{conn_handler, ApplicationError};
use crate::connection_handler::STSServerState;

/// The Config structure is useful only for unprocessed configuration's data. For example,
/// key's paths are just file paths and not the keys themselves.
pub struct ServerContext {
    address: SocketAddr,
    runtime_context: RuntimeContext,
    key_context: KeyContext,
}

pub struct RuntimeContext {
    working_threads: usize,
    cryptography_threads: usize,
}

impl RuntimeContext {
    pub fn new(working_threads: usize, cryptography_threads: usize) -> Self {
        Self {working_threads, cryptography_threads }
    }
}

/// Group keys for Servercontext.
pub struct KeyContext {
    tls_cert: Vec<CertificateDer<'static>>,
    tls_priv: PrivateKeyDer<'static>,
    tss_priv: RsaPrivateKey
}

impl KeyContext {
    pub fn new(
        tls_cert: Vec<CertificateDer<'static>>,
        tls_priv: PrivateKeyDer<'static>,
        tss_priv: RsaPrivateKey
    ) -> Self
    {
        Self { tls_cert, tls_priv, tss_priv }
    }
}

impl ServerContext {
    pub fn new(
        address: SocketAddr,
        runtime_context: RuntimeContext,
        key_context: KeyContext
    ) -> Self {
        Self {
            address,
            runtime_context,
            key_context,
        }
    }
}

/// Errors that might arise while building the server.
#[derive(Error, Debug)]
pub enum STSServerBuildError {
    #[error("zero working threads has been selected, while at least one is needed")]
    ZeroWorkingThreads,

    #[error("error while setting up the TLS logic for the server: {0:?}")]
    TLSSetup(String),
}

/// Errors that might arise while running the server. */
#[derive(Error, Debug)]
pub enum STSServerRunError {
    #[error("error while setting up the TLS layer of the server: {0:?}")]
    TLSSetup(String),

    #[error("port {0} already in use")]
    PortAlreadyInUse(u16),

    #[error("not enough permissions to open port {0}")]
    PermissionDenied(u16),

    #[error("address {0} not available")]
    AddrNotAvailable(SocketAddr),

    #[error("error while binding the address: {0:?}")]
    GenericBind(String),

    #[error("connection aborted: {0}")]
    ConnectionAborted(String),

    #[error("error while accepting new connections: {0}")]
    GenericAccept(String)
}

/// Data needed by the server at runtime.
pub struct STSServer {
    address: SocketAddr,
    runtime: Runtime,
    tls_acceptor: TlsAcceptor,
    state: STSServerState,
}

impl STSServer {
    pub fn build_from_context(
        ServerContext {
            address,
            runtime_context: RuntimeContext {
                working_threads,
                cryptography_threads,
            },
            key_context: KeyContext {
                tls_cert,
                tls_priv,
                tss_priv
            }
        }: ServerContext
    ) -> Result<Self, STSServerBuildError> {
        let mut rt = match working_threads {
            0 => return Err(STSServerBuildError::ZeroWorkingThreads),
            1 => tokio::runtime::Builder::new_current_thread(),
            n => {
                let mut inner_rt = tokio::runtime::Builder::new_multi_thread();
                inner_rt.worker_threads(n);
                inner_rt
            },
        };
        if cryptography_threads > 0 {
            rt.max_blocking_threads(cryptography_threads);
        }
        let rt = rt
            .enable_all()
            .build()
            .expect("This runtime should work everytime, except breaking changes");

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(tls_cert, tls_priv)
            .map_err(|e| STSServerBuildError::TLSSetup(e.to_string()))?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(config));
        let state = STSServerState::from_bundle(tss_priv);

        Ok(Self { runtime: rt, address, state, tls_acceptor })
    }

    pub fn run(&self) -> Result<(), STSServerRunError> {
        self.runtime.block_on(async {
            let listener = TcpListener::bind(self.address).await
                .map_err(|e|
                    match e.kind() {
                        ErrorKind::AddrInUse =>
                            STSServerRunError::PortAlreadyInUse(self.address.port()),
                        ErrorKind::PermissionDenied =>
                            STSServerRunError::PermissionDenied(self.address.port()),
                        ErrorKind::AddrNotAvailable =>
                            STSServerRunError::AddrNotAvailable(self.address),
                        _ => STSServerRunError::GenericBind(e.to_string())
                    }
                )?;

            loop {  /* here lays the server hotpath. */
                let (stream, new_address) = match listener.accept().await {
                    Ok(res) => res,
                    Err(e) => {
                        /* todo: log here, especially the conn aborted case */
                        match e.kind() {
                            ErrorKind::ConnectionAborted => continue,
                            _ => continue
                        }
                    }
                };

                /* thanks to rust's abstraction systems, we can implement a zero-cost copy. Arc is
                   just a smart pointer that increments its counter each time a clone is made:
                   real data is never cloned, keeping the hot path clear from memory-intensive
                   operations.
                   Sharing the state is necessary since the run function could expire while
                   coroutines are still running, however, thanks to the smart pointer, this will
                   be impossible. */
                let state_clone = self.state.clone();
                let tls_acceptor_clone = self.tls_acceptor.clone();

                tokio::spawn(async move {
                    match tls_acceptor_clone.accept(stream).await {
                        Ok(tls_stream) => {
                            /* if everything is okay, we further wrap the tls stream into a framed
                               stream. A framed stream is an abstraction of a stream, where the
                               first n bytes (usually n = 4) are used to identify the length of the
                               message coded after those bytes. This way, an unreliable stream
                               turns into an iterator yielding fixed messages. */
                            let codec = LengthDelimitedCodec::new();
                            let framed_stream = Framed::new(tls_stream, codec);

                            if let Err(e) = conn_handler(new_address, framed_stream, state_clone).await {
                                // todo: log e
                            }
                        }
                        Err(_e) => {
                            // todo: log the tls handshake error.
                        }
                    }
                });
            }
        })
    }
}
