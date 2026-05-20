//! Defines the standard function(s) to properly handle an async connection and apply the network
//! protocol of STSS.

use std::fmt::{Display, Formatter};
use std::io::{ErrorKind};
use futures::{SinkExt, StreamExt};
use rsa::RsaPrivateKey;
use shared_library::protocol::{LoginError, Request, Response, SignInError};
use std::net::{SocketAddr};
use std::sync::Arc;
use dashmap::DashSet;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use tracing::info;
use shared_library::network_numbers::NetworkLongLong;

use crate::database::{AddTokensError, AuthenticationError, GetTokensError, InternalDataBaseError, RegistrationError, ServerDataBase, SubtractTokensError};

/// In order to access the state of the server by a lot of coroutines, we need to abstract it into
/// a struct to create a shared reference with later.
/// Therefore, the server state must contain only cheap-to-clone variables, that can call the 
/// .clone() method without allocating heap memory.
#[derive(Clone)]
pub struct STSServerState {
    database: ServerDataBase,
    cancel_token: CancellationToken,
    logged_users: Arc<DashSet<String>>,
    signing_key: Arc<RsaPrivateKey>,
}

impl STSServerState {
    /// Returns a STSServerState with all the required data, bundled into a single state.
    /// This method hides the complexity of dealing with Arcs and is useful only to conn_handler().
    pub fn from_bundle(
        database: ServerDataBase,
        cancel_token: &CancellationToken,
        signing_key: RsaPrivateKey,
    ) -> Self {
        // It's also true that this violates the DIP, because someone might want to use another
        // type of smart pointer instead of Arc. In Rust, it's usually preferred to pass the
        // argument indirectly and already wrapped into the smart pointer. But whatever, we only
        // need this once.
        Self {
            database,
            cancel_token: cancel_token.clone(),
            // We don't need to inject an empty map. We also probably don't want, since this may
            // lead to security problems.
            logged_users: Arc::new(DashSet::new()),
            signing_key: Arc::new(signing_key),
        }
    }

    /// In the server, there's one specific instance where we only need to retrieve the cancellation
    /// token. That is the run() function, in which we need the token in order to pass it to the
    /// interruption listener. This function exists only for this reason: to not clone the entire
    /// structure (which would be costless in any way, but whatever).
    pub fn clone_cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
}

/// Used when successfully closing a connection with a client, either because it has been requested
/// by them or because an interruption has been given.
pub enum ClosedStreamReason {
    InterruptReceived,
    ClientAsked,
}

/// Possible errors that might arise when framing the stream.
#[derive(Error, Debug)]
pub enum FramingError {
    #[error("Address {0} isn't respecting the protocol: they declared that a huge amount of data \
             (more than {1}) is coming. Either the user is not respecting the protocol, or it has \
             malicious intentions. Disconnecting.")]
    SizeSmashing(SocketAddr, usize),

    #[error("An error occurred while framing the communication with {0}: {1}.")]
    Generic(SocketAddr, String),
}

/// Possible errors that might arise when using wincode to parse a message.
#[derive(Error, Debug)]
pub enum ParsingError {
    #[error("wincode write error: {0}")]
    Serialize(#[from] wincode::WriteError),

    #[error("wincode write error: {0}")]
    Deserialize(#[from] wincode::ReadError),
}

/// Possible errors that may happen when communicating with a client.
#[derive(Error, Debug)]
pub enum CommunicationError {
    #[error("An error occurred while parsing a message from {0}: {1}.")]
    Parsing(SocketAddr, #[source] ParsingError),

    #[error("An error occurred while serializing a response: {0}")]
    Serialize(#[from] wincode::WriteError),

    #[error("An error occurred while deserializing a request: {0}")]
    Deserialize(#[from] wincode::ReadError),

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError),

    #[error(transparent)]
    Framing(#[from] FramingError)
}

// Function conn_handler() and other functions called by it must remain
// lightweight and non-intensive on the CPU; however, they can and should be I/O intensive
// while leveraging the asynchronous programming pattern.

/// Main entry point for new incoming connections to the server.
/// This function is "untrusted" because connected users are not logged in yet.
/// That is, they're treated as untrusted, and they won't be able to perform any important
/// operation, apart from logging in or signing up.
/// Returns a Result. The Ok branch reports the reason why the connection has been properly closed,
/// if so. The Error branch reports instead errors that shouldn't happen and that a superior
/// authority should decide on what to do. Some other types of errors, instead, are not fatal and
/// are, instead, very common (e.g. a client that types a wrong password, or tries to log in
/// with a non-existent username, etc.). Those are handled alone by the function.
#[inline(always)]
pub async fn conn_handler(
    address: SocketAddr,
    mut stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    state @ STSServerState {
        database,
        cancel_token,
        logged_users,
        signing_key: _signing_key,  // this function won't and doesn't have to use the signing key.
    }: &STSServerState,
) -> Result<ClosedStreamReason, CommunicationError> {
    loop {
        let framed_data = tokio::select! {
            result = stream.next() => result,
            _ = cancel_token.cancelled() => {
                // Server has been interrupted while waiting for client's command. There's no
                // pending operation in this case, therefore, we can end the connection.
                break Ok(ClosedStreamReason::InterruptReceived);
            },
        };

        let result = match framed_data {
            Some(res) => res,
            None => {
                // stream has ended properly because the client asked so (they sent 0 bytes).
                break Ok(ClosedStreamReason::ClientAsked);
            }
        };

        let raw_message = result
            .map_err(|e| match e.kind() {
                ErrorKind::InvalidData => FramingError::SizeSmashing(
                    address, stream.codec().max_frame_length()
                ),
                _ => FramingError::Generic(address, e.to_string())
            })?;

        let request = Request::deserialize(raw_message)
            .map_err(|e| CommunicationError::Parsing(address, e.into()))?;

        let mut started_session = None;

        let response: Response = match request {
            Request::Login(username, password) => {
                // Avoid user enumeration. We first control if the user exists and if the password
                // is correct. Only then, we control if the user is already logged in. This way,
                // an attacker can't understand if any user is online, without knowing the password.
                let result = database.verify_user_password(&username, password).await;

                match result {
                    Ok(()) => {
                        if logged_users.contains(&username) {
                            Response::LoginFailed(LoginError::AlreadyLoggedIn)
                        } else {
                            logged_users.insert(username.clone());
                            started_session = Some(Session::bundle(address, username));
                            Response::Ok
                        }
                    },

                    Err(AuthenticationError::InternalDataBase(e)) =>
                        return Err(CommunicationError::InternalDataBase(e)),

                    Err(AuthenticationError::UserNotFound(_)) =>
                        Response::LoginFailed(LoginError::UsernameNotFound),

                    Err(AuthenticationError::InvalidPassword) =>
                        Response::LoginFailed(LoginError::InvalidPassword),
                }
            },

            Request::SignUp(username, password) => {
                let result = database.try_register_user(username, password).await;

                match result {
                    Ok(()) => {
                        Response::Ok
                    }
                    Err(RegistrationError::InternalDataBase(e)) => {
                        return Err(CommunicationError::InternalDataBase(e))
                    },
                    Err(RegistrationError::UserAlreadyExists(_user)) =>
                        Response::SignInFailed(SignInError::UsernameAlreadyTaken)
                }
            },

            _ => Response::NotLoggedIn
        };

        match stream.send(response.serialize()?).await {
            Ok(_) => {}
            Err(e) => {}
        };

        if let Some(session) = started_session  {
            match session_handler(&session, &mut stream, state) { _ => {} };
        }
    }
}

/// Groups up the data of a single, complete and logged connection.
pub struct Session {
    address: SocketAddr,
    username: String,
}

impl Session {
    pub fn bundle(address: SocketAddr, username: String) -> Self {
        Self { address, username }
    }
}

/// Implements a pretty way to print it.
impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.username, self.address)
    }
}

/// Errors that may arise during a trusted connection.
#[derive(Error, Debug)]
pub enum OperationalError {
    #[error("the TCP, TLS or Framed stream produced an error: {0:?}")]
    Communication(String),

    #[error("An error occurred while parsing a message from {0}: {1}")]
    Parsing(SocketAddr, #[source] ParsingError),

    #[error("An error occurred while serializing a response: {0}")]
    Serialize(#[from] wincode::WriteError),

    #[error("An error occurred while deserializing a request: {0}")]
    Deserialize(#[from] wincode::ReadError),

    #[error(transparent)]
    GetTokens(#[from] GetTokensError),

    #[error(transparent)]
    AddTokens(#[from] AddTokensError),

    #[error(transparent)]
    SubtractTokens(#[from] SubtractTokensError),

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError),

    #[error(transparent)]
    Framing(#[from] FramingError),
}

/// Used when successfully closing a session with a logged user.
pub enum ClosedSessionReason {
    // session can end for the exact same reasons as a non-logged-in connection may end.
    ClosedStream(ClosedStreamReason)
}

/// Let's support .into() for ClosedStreamReason, in order to avoid redundant errors.
/// e.g. instead of
///     ClosedSessionReason::AReasonThatHappensAlsoInClosedStreamReason(ClosedStreamReason::Same)
/// it will suffice
///     ClosedStreamReason::Same.into()
impl From<ClosedStreamReason> for ClosedSessionReason {
    fn from(reason: ClosedStreamReason) -> Self {
        ClosedSessionReason::ClosedStream(reason)
    }
}

/// Handles a logged user. Differs from the untrusted counterpart because, here, all the operations
/// can be requested.
#[inline(always)]
pub async fn session_handler(
    session @ Session {
        address,
        username,
    }: &Session,
    stream: &mut Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    STSServerState {
        database,
        cancel_token,
        logged_users,
        signing_key,
    }: &STSServerState,
) -> Result<ClosedSessionReason, OperationalError> {
    loop {
        let framed_data = tokio::select! {
            result = stream.next() => result,
            _ = cancel_token.cancelled() => {
                // Server has been interrupted while waiting for client's command. There's no
                // pending operation in this case, therefore, we can end the connection.
                break Ok(ClosedStreamReason::InterruptReceived.into());
            },
        };

        let result = match framed_data {
            Some(res) => res,
            None => {
                // stream has ended properly because the client asked so (they sent 0 bytes).
                break Ok(ClosedStreamReason::ClientAsked.into());
            }
        };

        let raw_message = result
            .map_err(|e| match e.kind() {
                ErrorKind::InvalidData => FramingError::SizeSmashing(
                    session.address, stream.codec().max_frame_length()
                ),
                _ => FramingError::Generic(session.address, e.to_string())
            })?;

        let request = Request::deserialize(raw_message)
            .map_err(|e| OperationalError::Parsing(session.address, e.into()))?;

        let response : Response = match request {
            // Let's not use "username" because it would shadow the outer variable.
            Request::Login(received_username, received_password) => {
                info!("User {} tried to log in with username \"{}\" and password \"{}\", but they \
                       were logged in before.", session, received_username, received_password);
                Response::LoginFailed(LoginError::AlreadyLoggedIn)
            },

            Request::SignUp(received_username, received_password) => {
                info!("User {} tried to sign up with username \"{}\" and password \"{}\", but they \
                       were logged in before.", session, received_username, received_password);
                Response::SignInFailed(SignInError::AlreadyLoggedIn)
            },

            Request::SignHash(_) => {unreachable!()},

            Request::PurchaseTokens(be_tokens) => {
                let tokens = be_tokens.to_host();

                match database.add_user_tokens(&username, tokens).await {
                    Ok(new_token_count) => {
                        info!("{} updated their tokens: {}.", username, new_token_count);
                        // In this case, we do not send a simple Ok to the client, but we
                        // send a stronger confirmation that its tokens have been updated.
                        Response::TokenCount(NetworkLongLong::from(new_token_count))
                    }
                    Err(token_add_error) => {
                        match token_add_error {
                            AddTokensError::TokenOverflow => {
                                Response::TokenAmountTooHigh(be_tokens)
                            },
                            AddTokensError::UserDoesNotExist |
                            AddTokensError::InternalDataBase(_) => {
                                return Err(token_add_error.into())
                            }
                        }
                    }
                }
            },

            Request::HowManyTokensDoIHave => {
                match database.get_user_tokens(&username).await {
                    Ok(n_tokens) => {
                        info!("{} requested their tokens: {}.", username, n_tokens);
                        Response::TokenCount(NetworkLongLong::from(n_tokens))
                    }
                    Err(get_tokens_error) => {
                        // get_user_tokens() fails only when integrity is violated. This case does
                        // not have to be handled by the connection handlers, but by the server.
                        return Err(get_tokens_error.into())
                    }
                }
            }
        };

        if let Err(send_err) = stream.send(response.serialize()?).await {
            match send_err.kind() {
                _ => todo!()
            }
        };
    }
}
