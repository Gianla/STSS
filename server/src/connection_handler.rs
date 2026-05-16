//! Defines the standard function(s) to properly handle an async connection and apply the network
//! protocol of STSS.

use futures::StreamExt;
use rkyv::{access, Archived};
use rsa::RsaPrivateKey;
use shared_library::protocol::{ArchivedRequest, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use rkyv::rancor::Failure;
use rsa::pkcs1::der::Tag::Application;

/// In order to access the state of the server by a lot of coroutines, we need to abstract it into
/// a struct to create a shared reference with later.
#[derive(Clone)]
pub struct STSServerState {
    signing_key: Arc<RsaPrivateKey>,
}

impl STSServerState {
    /// Returns a STSServerState with all the required data, bundled into a single state.
    /// This method hides the complexity of dealing with Arcs and is useful only to untrusted_conn_handler.
    pub fn from_bundle(signing_key: RsaPrivateKey) -> Self {
        /* It's also true that this violates the DIP, because someone might want to use another
           type of smart pointer instead of Arc. In Rust, it's usually preferred to pass the
           argument indirectly and already wrapped into the smart pointer. But whatever, we only
           need this once. */
        Self {
            signing_key: Arc::new(signing_key)
        }
    }
}

/// Errors that may arise during an untrusted connection.
#[derive(Error, Debug)]
pub enum ApplicationError {
    #[error("the TCP, TLS or Framed stream produced an error: {0:?}")]
    Communication(String),

    #[error("error while parsing a received message: {0:?}")]
    Parsing(#[from] Failure)
}

/* Function untrusted_conn_handler() and other functions called by it must remain
   lightweight and non-intensive on the CPU; however, they can and should be I/O intensive
   while leveraging the asynchronous programming pattern. */
/// Main entry point for new incoming connections to the server.
/// This function is "untrusted" because connected users are not logged in yet.
/// That is, they're treated as untrusted, and they won't be able to perform any important
/// operation, apart from logging in or signing up.
#[inline(always)]
pub async fn conn_handler(
    address: SocketAddr,
    mut stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    STSServerState { signing_key: _signing_key }: STSServerState
) -> Result<(), ApplicationError> {
    while let Some(result) = stream.next().await {
        let raw_message = result.map_err(
            |e| ApplicationError::Communication(e.to_string())
        )?;

        let request = access::<ArchivedRequest, Failure>(&raw_message).map_err(
            |e| ApplicationError::Parsing(e)
        )?;

        if let ArchivedRequest::Login(username, password) = request {

        } else if let ArchivedRequest::SignUp(username, password) = request {

        }
    };

    /* here, stream.next() has returned None: the client correctly disconnected. */
    Ok(())
}

/// Errors that may arise during a trusted connection.
#[derive(Error, Debug)]
pub enum OperationalError {
    #[error("the TCP, TLS or Framed stream produced an error: {0:?}")]
    Communication(String),

    #[error("error while parsing a received message: {0:?}")]
    Parsing(#[from] Failure)
}

#[inline(always)]
pub async fn user_loop(
    address: SocketAddr,
    mut stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    STSServerState { signing_key: _signing_key }: STSServerState
) -> Result<(), OperationalError> {
    while let Some(result) = stream.next().await {
        let raw_message = result.map_err(
            |e| OperationalError::Communication(e.to_string())
        )?;

        let request = access::<ArchivedRequest, Failure>(&raw_message).map_err(
            |e| OperationalError::Parsing(e)
        )?;

        let response = match request {
            ArchivedRequest::Login(_, _) => {}
            ArchivedRequest::SignUp(_, _) => {}
            ArchivedRequest::SignHash(_) => {}
            ArchivedRequest::PurchaseTokens(_) => {}
            ArchivedRequest::HowManyTokensDoIHave => {}
        };
    };

    /* here, stream.next() has returned None: the client correctly disconnected. */
    Ok(())
}
