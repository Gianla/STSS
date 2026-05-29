//! Defines the standard function(s) to properly handle an async connection and apply the network
//! protocol of STSS.

use dashmap::DashSet;
use futures::{SinkExt, StreamExt};
use rsa::RsaPrivateKey;
use shared_library::server_protocol::{
    DeserializeError, LoginError, Request, Response, SerializeError, SignInError, Timestamp,
};
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::database::{
    AddRecordError, AddTokensError, AuthenticationError, GetTokensError, InternalDataBaseError,
    RegistrationError, ServerDataBase, SubtractTokensError, UserHistoryError,
};
use crate::server::{AcceleratedSigner, NoSignerYet, SignError, Signer, SlowSigner};
use crate::time_oracle::TimeOracle;

/// In order to access the state of the server by a lot of coroutines, we need to abstract it into
/// a struct to create a shared reference with later.
/// Therefore, the server state must contain only cheap-to-clone variables, that can call the
/// .clone() method without allocating heap memory.
#[derive(Clone)]
pub struct STSServerState<S: Signer> {
    database: ServerDataBase,
    cancel_token: CancellationToken,
    logged_users: Arc<DashSet<String>>,
    signing_key: Arc<RsaPrivateKey>,
    time_oracle: TimeOracle,
    signer: S,
}

impl<S> STSServerState<S>
where
    S: Signer,
{
    /// In the server, there's one specific instance where we only need to retrieve the cancellation
    /// token. That is the run() function, in which we need the token in order to pass it to the
    /// various coroutines. This function exists only for this reason: to not clone the entire
    /// structure (which would be costless in any way, but whatever).
    pub fn clone_cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
}

/// Builds the server state while being mindful of the signer.
#[derive(Clone)]
pub struct STSServerStateBuilder<S> {
    database: ServerDataBase,
    cancel_token: CancellationToken,
    logged_users: Arc<DashSet<String>>,
    signing_key: Arc<RsaPrivateKey>,
    time_oracle: TimeOracle,
    signer: PhantomData<S>,
}

impl STSServerStateBuilder<NoSignerYet> {
    /// Returns a STSServerStateBuilder with all the required data, bundled into a single state.
    /// This method hides the complexity of dealing with Arcs and is useful only to conn_handler().
    pub fn from_bundle(
        database: ServerDataBase,
        cancel_token: &CancellationToken,
        signing_key: RsaPrivateKey,
        time_oracle: TimeOracle,
    ) -> Self {
        // It's also true that this violates the DIP, because someone might want to use another
        // type of smart pointer instead of Arc. In Rust, it's usually preferred to pass the
        // argument indirectly and already wrapped into the smart pointer. However, we need this
        // method to hide to the caller the complexity of the state.
        Self {
            database,
            cancel_token: cancel_token.clone(),
            // We don't need to inject an empty map. We also probably don't want, since this may
            // lead to security problems.
            logged_users: Arc::new(DashSet::new()),
            signing_key: Arc::new(signing_key),
            time_oracle,
            signer: PhantomData,
        }
    }

    /// Finalize the initialization by enriching the state with an accelerated signer.
    pub fn get_accelerated_build(self) -> STSServerState<AcceleratedSigner> {
        STSServerState {
            database: self.database,
            cancel_token: self.cancel_token,
            logged_users: self.logged_users,
            signing_key: self.signing_key,
            time_oracle: self.time_oracle,
            signer: AcceleratedSigner,
        }
    }

    /// Finalize the initialization by enriching the state with a slow signer.
    pub fn get_slow_build(self) -> STSServerState<SlowSigner> {
        STSServerState {
            database: self.database,
            cancel_token: self.cancel_token,
            logged_users: self.logged_users,
            signing_key: self.signing_key,
            time_oracle: self.time_oracle,
            signer: SlowSigner,
        }
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
    #[error(
        "error with {0}: a huge amount of data (more than {1}) is coming and that can't be handled"
    )]
    SizeSmashing(SocketAddr, usize),

    #[error("error while framing the communication with {0}: {1}.")]
    Generic(SocketAddr, String),
}

/// Errors that indicate a physical or structural failure in the network connection.
/// These errors are fatal for the specific socket and must break the connection loop.
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("connection abruptly dropped by the client or broken pipe")]
    ConnectionDropped,

    #[error("no connection")]
    ServerNetworkDown,

    #[error(transparent)]
    Generic(#[from] std::io::Error),

    #[error("framing error with address {0:?}: {source}", address)]
    Framing {
        address: SocketAddr,
        #[source]
        source: FramingError,
    },

    #[error(transparent)]
    Deserialize(#[from] DeserializeError),
}

/// Errors related to the business logic and application state.
#[derive(Error, Debug)]
pub enum InternalError {
    #[error("internal database error occurred")]
    Database(#[from] InternalDataBaseError),

    #[error("user does not exist or was deleted during session")]
    UserShouldExistButWasNotFound,

    #[error("system clock is out of sync")]
    ClockStaggered,

    #[error("data integrity violation: {0}")]
    IntegrityViolation(String),

    #[error(transparent)]
    Serialize(#[from] SerializeError),
}

/// The overarching error type for the connection/session handlers.
#[derive(Error, Debug)]
pub enum HandlerError {
    #[error("network failure: {0}")]
    Network(#[from] NetworkError),

    #[error("fatal domain error (user: {username:?}): {source}")]
    Domain {
        username: Option<String>, // "None" if the user wasn't logged in yet
        #[source]
        source: InternalError,
    },
}

/// Handles a send()'s error and log the proper error message. If the network is down, returns
/// network_down_err in order to be furtherly forwarded upwards.
fn send_error_logger(send_err: std::io::Error, address: &SocketAddr) -> Result<(), NetworkError> {
    match send_err.kind() {
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
            info!("Connection dropped by {}. Disconnecting.", address);
            Err(NetworkError::ConnectionDropped)
        }
        ErrorKind::TimedOut => {
            info!("Address {} has timed out. Disconnecting.", address);
            Err(NetworkError::ConnectionDropped)
        }
        ErrorKind::NetworkDown => {
            error!("[CRITICAL] Server's local network interface is down.");
            Err(NetworkError::ServerNetworkDown)
        }
        generic_error => {
            warn!(
                "An error occurred while sending a message to {}: {}.",
                address, generic_error
            );
            Err(NetworkError::Generic(send_err))
        }
    }
}

/// Extracts the next send_request from a framed stream, properly adapting to the function's type
/// ecosystem by the use of generics.
async fn fetch_next_request<S>(
    stream: &mut Framed<S, LengthDelimitedCodec>,
    cancel_token: &CancellationToken,
    address: SocketAddr,
) -> Result<Option<Request>, NetworkError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let framed_data = tokio::select! {
        result = stream.next() => result,
        _ = cancel_token.cancelled() => {
            // Server interrupted gracefully
            return Ok(None);
        },
    };

    let result = match framed_data {
        Some(res) => res,
        None => {
            // Client closed the connection gracefully
            return Ok(None);
        }
    };

    let raw_message = match result {
        Ok(bytes) => bytes,
        Err(e) => {
            return match e.kind() {
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof => {
                    Err(NetworkError::ConnectionDropped)
                }
                ErrorKind::InvalidData => Err(NetworkError::Framing {
                    address,
                    source: FramingError::SizeSmashing(address, stream.codec().max_frame_length()),
                }),
                _ => Err(NetworkError::Framing {
                    address,
                    source: FramingError::Generic(address, e.to_string()),
                }),
            };
        }
    };
    // The ? operator automatically converts ParsingError into NetworkError::Parsing
    let request = Request::deserialize(raw_message)?;

    Ok(Some(request))
}

// Function conn_handler() and other functions called by it must remain lightweight and
// non-intensive on the CPU; however, they can and should be I/O intensive while leveraging the
// asynchronous programming pattern.

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
pub async fn conn_handler<S>(
    address: SocketAddr,
    stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    state: &STSServerState<S>,
) -> Result<ClosedStreamReason, HandlerError>
where
    S: Signer + Send + Sync,
{
    conn_handler_core(address, stream, state).await
}

/// Stream-type agnostic version of the conn_handler. They are separated because we want to expose
/// to the other module only the rigid version, while we want to keep a flexible version for
/// ourselves in order to test it with simulated streams (read the end of the file to find the
/// tests). Although making the exposed function generic-less is against a bunch of programming
/// principles, we believe that it adds points to security. That's because conn_handler() will only
/// be callable with a ciphered stream (semantically secure) that wraps a TCP stream (type safety).
#[inline(always)]
async fn conn_handler_core<S, T>(
    address: SocketAddr,
    mut stream: Framed<T, LengthDelimitedCodec>,
    state @ STSServerState {
        database,
        cancel_token,
        logged_users,
        signing_key: _signing_key, // This function won't and doesn't have to use the signing key.
        time_oracle: _time_oracle, // Same.
        signer: _signer,           // Same.
    }: &STSServerState<S>,
) -> Result<ClosedStreamReason, HandlerError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    S: Signer + Send + Sync,
{
    loop {
        let request = match fetch_next_request(&mut stream, cancel_token, address).await? {
            Some(req) => req,
            None => {
                let reason = if cancel_token.is_cancelled() {
                    info!("{} disconnected after interrupt.", address);
                    ClosedStreamReason::InterruptReceived
                } else {
                    info!("{} disconnected.", address);
                    ClosedStreamReason::ClientAsked
                };
                break Ok(reason);
            }
        };

        let mut started_session = None;

        let response: Response = match request {
            Request::Login(username, password) => {
                // Avoid user enumeration. We first control if the user exists and if the password
                // is correct. Only then, we control if the user is already logged in. This way,
                // an attacker can't understand if any user is online, without knowing the password.
                let result = database.verify_user_password(&username, &password).await;

                match result {
                    Ok(()) => {
                        // .insert() returns true if the username has been successfully added
                        // inside the hashmap. Furthermore, is atomic. This means that we don't
                        // need to lock on it to perform a .contains() and then an .insert() if the
                        // first was false. If this split operation wasn't locked, it would lead to
                        // race conditions and security vulnerabilities (a user would have been able
                        // to log twice).
                        if logged_users.insert(username.clone()) {
                            started_session = Some(Session::bundle(address, username));
                            Response::Ok
                        } else {
                            info!(
                                "{} attempted to login with username {:?} and password {:?}.",
                                address, username, password
                            );
                            Response::LoginFailed(LoginError::AlreadyLoggedIn)
                        }
                    }

                    Err(AuthenticationError::UserNotFound(_)) => {
                        info!("{} tried to log in with a non-existent username.", &address);
                        Response::LoginFailed(LoginError::InvalidCredentials)
                    }

                    Err(AuthenticationError::InvalidPassword) => {
                        info!(
                            "{} tried to log in with username {:?}, but inserted the wrong \
                             password {:?}.",
                            &address, username, password
                        );
                        Response::LoginFailed(LoginError::InvalidCredentials)
                    }

                    Err(AuthenticationError::InternalDataBase(e)) => {
                        // This is an assertion error. An internal problem of the database is out
                        // of the connection handler's responsibility, so we move it to the caller.
                        return Err(HandlerError::Domain {
                            username: None, // The user is not logged in yet
                            source: InternalError::Database(e),
                        });
                    }
                }
            }

            Request::SignUp(username, password) => {
                let result = database
                    .try_register_user(&username, password, address.ip())
                    .await;

                match result {
                    Ok(()) => {
                        info!("New user registered: {}.", username);
                        Response::Ok
                    }

                    Err(RegistrationError::InternalDataBase(e)) => {
                        return Err(HandlerError::Domain {
                            username: None, // The user is not logged in yet, so we use None.
                            source: InternalError::Database(e),
                        });
                    }

                    Err(RegistrationError::UserAlreadyExists(already_existing_username)) => {
                        info!(
                            "{} tried to sign in as {}, but the username was already taken.",
                            address, already_existing_username
                        );
                        Response::SignInFailed(SignInError::UsernameAlreadyTaken)
                    }
                }
            }

            // At this stage, to any other request, we have to answer that the user is not logged.
            _ => Response::NotLoggedIn,
        };

        let serialized_response = response.serialize().map_err(|e| HandlerError::Domain {
            username: None,
            source: InternalError::Serialize(e),
        })?;

        if let Err(send_err) = stream.send(serialized_response).await {
            send_error_logger(send_err, &address)?;
        };

        if let Some(session) = started_session {
            info!("{} has logged in.", session);

            match session_handler(&session, &mut stream, state).await {
                Err(error) => {
                    // Propagate the error, but make sure to unlock the username first.
                    state.logged_users.remove(&session.username);
                    return Err(error);
                }

                Ok(ClosedSessionReason::LoggedOut) => {
                    info!("User {} logged out.", session);
                    state.logged_users.remove(&session.username);
                    // Do nothing else: the loop continues and they can log in again.
                }

                Ok(ClosedSessionReason::ClosedStream(reason)) => {
                    // Message is already logged inside of session_handler().
                    state.logged_users.remove(&session.username);
                    // Break the loop: the stream is dead or the server is shutting down.
                    return Ok(reason);
                }
            }
        }
    }
}

/// Groups up the data of a single, complete and logged connection.
#[derive(Debug)]
pub struct Session {
    address: SocketAddr,
    username: String,
}

impl Session {
    /// Returns a new Session bundled from an address and a username.
    pub fn bundle(address: SocketAddr, username: impl AsRef<str>) -> Self {
        Self {
            address,
            username: username.as_ref().to_string(),
        }
    }
}

/// Implements a pretty way to print it.
impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.username, self.address)
    }
}

/// Used when successfully closing a session with a logged user.
pub enum ClosedSessionReason {
    // Session can end for the exact same reasons as a non-logged-in connection may end.
    ClosedStream(ClosedStreamReason),
    LoggedOut,
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
/// Also, this function does not need the division between a generic "core" and a strict, public
/// API. This is because this function does not have to be called from outside this module.
#[inline(always)]
async fn session_handler<S, T>(
    session @ Session { address, username }: &Session,
    stream: &mut Framed<T, LengthDelimitedCodec>,
    STSServerState {
        database,
        cancel_token,
        logged_users: _logged_users, // No need to access to this inside session_handler().
        signing_key,
        time_oracle,
        signer,
    }: &STSServerState<S>,
) -> Result<ClosedSessionReason, HandlerError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    S: Signer + Send + Sync,
{
    loop {
        let request = match fetch_next_request(stream, cancel_token, *address).await? {
            Some(req) => req,
            None => {
                let reason = if cancel_token.is_cancelled() {
                    info!("{} disconnected after interrupt.", session);
                    ClosedStreamReason::InterruptReceived
                } else {
                    info!("{} disconnected.", session);
                    ClosedStreamReason::ClientAsked
                };
                break Ok(reason.into());
            }
        };

        let mut has_to_logout = false;

        let response: Response = match request {
            // Let's not use "username" because it would shadow the outer variable.
            Request::Login(received_username, received_password) => {
                info!(
                    "User {} tried to log in with username \"{}\" and password \"{}\", but they \
                     were logged in before.",
                    session, received_username, received_password
                );
                Response::LoginFailed(LoginError::AlreadyLoggedIn)
            }

            Request::SignUp(received_username, received_password) => {
                info!(
                    "User {} tried to sign up with username \"{}\" and password \"{}\", but they \
                     were logged in before.",
                    session, received_username, received_password
                );
                Response::SignInFailed(SignInError::AlreadyLoggedIn)
            }

            Request::LogOut => {
                has_to_logout = true; // a bit dirty but that's what we need for now.
                Response::Ok
            }

            Request::SignHash(raw_hash) => {
                if let Err(e) = database.subtract_user_tokens(username, 1).await {
                    match e {
                        SubtractTokensError::InsufficientTokens => {
                            // Normal case that the session handler can work with, since
                            // it perfectly fits into its responsibilities. A user asked
                            // to sign a hash, but they have no tokens.
                            Response::NotEnoughTokens
                        }

                        SubtractTokensError::UserDoesNotExist => {
                            // Assertion error. The user MUST exist in the database if they're
                            // logged in. So we return the responsibility to the caller.
                            return Err(HandlerError::Domain {
                                username: Some(session.username.clone()),
                                source: InternalError::UserShouldExistButWasNotFound,
                            });
                        }

                        SubtractTokensError::InternalDataBase(e) => {
                            return Err(HandlerError::Domain {
                                username: Some(session.username.clone()),
                                source: InternalError::Database(e),
                            });
                        }
                    }
                } else {
                    // if token subtraction was successful...
                    let timestamp = match time_oracle.time_now().duration_since(UNIX_EPOCH) {
                        Ok(ts) => Timestamp::new(ts.as_nanos()),
                        Err(_) => {
                            return Err(HandlerError::Domain {
                                username: Some(session.username.clone()),
                                source: InternalError::ClockStaggered,
                            })
                        }
                    };

                    // Here we are using the generic signer, that can be both slow or accelerated.
                    // The check is performed at compile time, super easy and fast.
                    match signer
                        .generate_timestamp_signature(signing_key, raw_hash, timestamp)
                        .await
                    {
                        Ok(sign) => {
                            info!(
                                "User {} required to sign the hash {}.",
                                address,
                                hex::encode(raw_hash)
                            );

                            if let Err(db_err) =
                                database.add_user_record(username, timestamp, &sign).await
                            {
                                return match db_err {
                                    AddRecordError::UserDoesNotExist => Err(HandlerError::Domain {
                                        username: Some(session.username.clone()),
                                        source: InternalError::UserShouldExistButWasNotFound,
                                    }),

                                    AddRecordError::InternalDataBase(e) => {
                                        Err(HandlerError::Domain {
                                            username: Some(session.username.clone()),
                                            source: InternalError::Database(e),
                                        })
                                    }
                                };
                            };

                            Response::Token {
                                sign: Box::new(sign),
                                timestamp,
                            }
                        }

                        Err(sign_err) => {
                            match sign_err {
                                SignError::Crypto(_) => error!(
                                    "[Critical] An hashing operation returned an error: {}. \
                                     This should be impossible and thus a serious issue, \
                                     please consider restarting the server.",
                                    sign_err.to_string()
                                ),

                                SignError::ThreadPanic(_) => error!(
                                    "[Critical] Using a new thread caused an error: {}. This \
                                     is a serious issue, please consider restarting the \
                                     server.",
                                    sign_err.to_string()
                                ),
                            }

                            if let Err(refund_err) = database.add_user_tokens(username, 1).await {
                                // We at least log this. If the hash operation fails, and the
                                // database operation fails too, an operator has to manually
                                // rollback this.
                                error!(
                                    "Failed to refund a token to user {} after a signing \
                                    failure: {:?}",
                                    username, refund_err
                                );
                            }

                            Response::OperationError(
                                "Error while performing the operation.".to_string(),
                            )
                        }
                    }
                }
            }

            Request::PurchaseTokens(tokens) => {
                match database.add_user_tokens(&username, tokens).await {
                    Ok(new_token_count) => {
                        info!("{} updated their tokens: {}.", username, new_token_count);
                        // In this case, we do not send a simple Ok to the client, but we
                        // send a stronger confirmation that its tokens have been updated.
                        Response::TokenCount(new_token_count)
                    }

                    Err(token_add_error) => match token_add_error {
                        AddTokensError::TokenOverflow => {
                            info!(
                                "{} tried to buy {} tokens but the amount is too high.",
                                session, tokens
                            );
                            Response::TokenAmountTooHigh
                        }
                        AddTokensError::UserDoesNotExist => {
                            return Err(HandlerError::Domain {
                                username: Some(session.username.clone()),
                                source: InternalError::UserShouldExistButWasNotFound,
                            });
                        }
                        AddTokensError::InternalDataBase(e) => {
                            return Err(HandlerError::Domain {
                                username: Some(session.username.clone()),
                                source: InternalError::Database(e),
                            });
                        }
                    },
                }
            }

            Request::HowManyTokensDoIHave => match database.get_user_tokens(&username).await {
                Ok(n_tokens) => {
                    info!("{} requested their tokens: {}.", username, n_tokens);
                    Response::TokenCount(n_tokens)
                }

                Err(GetTokensError::UserDoesNotExist) => {
                    return Err(HandlerError::Domain {
                        username: Some(session.username.clone()),
                        source: InternalError::UserShouldExistButWasNotFound,
                    });
                }

                Err(GetTokensError::TokenIntegrityCheckViolated(user, amount)) => {
                    return Err(HandlerError::Domain {
                        username: Some(session.username.clone()),
                        source: InternalError::IntegrityViolation(format!(
                            "invalid token amount for user {}: {}",
                            user, amount
                        )),
                    });
                }

                Err(GetTokensError::InternalDataBase(e)) => {
                    return Err(HandlerError::Domain {
                        username: Some(session.username.clone()),
                        source: InternalError::Database(e),
                    });
                }
            },

            Request::History => match database.get_user_history(username).await {
                Ok(history) => {
                    info!("{} requested their history.", session);
                    Response::History(history)
                }

                Err(history_err) => {
                    return match history_err {
                        UserHistoryError::UserDoesNotExist => Err(HandlerError::Domain {
                            username: Some(session.username.clone()),
                            source: InternalError::UserShouldExistButWasNotFound,
                        }),

                        UserHistoryError::TimestampIntegrityViolated(token) => {
                            Err(HandlerError::Domain {
                                username: Some(session.username.clone()),
                                source: InternalError::IntegrityViolation(format!(
                                    "invalid timestamp of {}",
                                    token
                                )),
                            })
                        }

                        UserHistoryError::HashIntegrityViolated(hash) => {
                            Err(HandlerError::Domain {
                                username: Some(session.username.clone()),
                                source: InternalError::IntegrityViolation(format!(
                                    "invalid hash: {}",
                                    hash
                                )),
                            })
                        }

                        UserHistoryError::InternalDataBase(e) => Err(HandlerError::Domain {
                            username: Some(session.username.clone()),
                            source: InternalError::Database(e),
                        }),
                    }
                }
            },
        };

        let serialized_response = response.serialize().map_err(|e| HandlerError::Domain {
            username: None,
            source: InternalError::Serialize(e),
        })?;

        if let Err(send_err) = stream.send(serialized_response).await {
            send_error_logger(send_err, address)?;
        };

        if has_to_logout {
            return Ok(ClosedSessionReason::LoggedOut);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use rsa::RsaPrivateKey;
    use shared_library::server_protocol::{LoginError, Request, Response, Sha256Hash, SignInError};
    use std::net::SocketAddr;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};
    use tokio_util::sync::CancellationToken;

    use crate::database::{DataBaseLocation, ServerDataBaseBuilder};

    /// Sets up an in-memory database for testing purposes.
    async fn setup_memory_db() -> ServerDataBase {
        ServerDataBaseBuilder::build(DataBaseLocation::Memory)
            .await
            .expect("Failed to create in-memory database")
    }

    /// Helper function to bootstrap a test environment.
    /// Returns a mocked client stream, the cancellation token, and the server state.
    async fn setup_test_env() -> (
        Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        CancellationToken,
        STSServerState<AcceleratedSigner>,
    ) {
        let (client, server) = tokio::io::duplex(4096);
        let client_framed = Framed::new(client, LengthDelimitedCodec::new());
        let server_framed = Framed::new(server, LengthDelimitedCodec::new());

        let cancel_token = CancellationToken::new();
        let database = setup_memory_db().await;

        // Generate a fast, small key for testing to avoid slowing down the test suite
        let signing_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let time_oracle = TimeOracle::_new_local();

        let state =
            STSServerStateBuilder::from_bundle(database, &cancel_token, signing_key, time_oracle)
                .get_accelerated_build();

        let dummy_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let state_clone = state.clone();

        // Spawn the server in the background
        tokio::spawn(async move {
            let _ = conn_handler_core(dummy_addr, server_framed, &state_clone).await;
        });

        (client_framed, cancel_token, state)
    }

    #[tokio::test]
    async fn test_full_user_lifecycle() {
        let (mut client, _, _) = setup_test_env().await;

        // 1. Sign Up
        client
            .send(
                Request::SignUp("alice".to_string(), "supersecret".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp, Response::Ok));

        // 2. Login
        client
            .send(
                Request::Login("alice".to_string(), "supersecret".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp, Response::Ok));

        // 3. Check token count right after registration (must be 0)
        client
            .send(Request::HowManyTokensDoIHave.serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();

        if let Response::TokenCount(count) = resp {
            assert_eq!(count, 0);
        } else {
            panic!("Expected TokenCount, received: {:?}", resp);
        }

        // 4. Log Out
        client
            .send(Request::LogOut.serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp, Response::Ok));

        // 5. Request token count after logout (must fail because the user is Guest again)
        client
            .send(Request::HowManyTokensDoIHave.serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp, Response::NotLoggedIn));
    }

    #[tokio::test]
    async fn test_unauthorized_operations_enforcement() {
        let (mut client, _, _) = setup_test_env().await;

        // --- PHASE 1: UNLOGGED ---
        // Try to ask for tokens without credentials
        client
            .send(Request::HowManyTokensDoIHave.serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp, Response::NotLoggedIn));

        let raw_hash = [0u8; 32];
        let hash = Sha256Hash::from(&raw_hash);

        // Try to sign a dummy hash
        client
            .send(Request::SignHash(hash).serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp, Response::NotLoggedIn));

        // --- PHASE 2: LOGGED ---
        // Register and login first
        client
            .send(
                Request::SignUp("bob".to_string(), "pass123".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = client.next().await.unwrap().unwrap();
        client
            .send(
                Request::Login("bob".to_string(), "pass123".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = client.next().await.unwrap().unwrap();

        // Now that we are logged in, try to Sign Up again with another username
        client
            .send(
                Request::SignUp("hacker".to_string(), "pass123".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(
            resp,
            Response::SignInFailed(SignInError::AlreadyLoggedIn)
        ));

        // Try to log in again while already logged in
        client
            .send(
                Request::Login("bob".to_string(), "pass123".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(
            resp,
            Response::LoginFailed(LoginError::AlreadyLoggedIn)
        ));
    }

    #[tokio::test]
    async fn test_token_transactions_and_math() {
        let (mut client, _, _) = setup_test_env().await;

        // Quick setup: register and login
        client
            .send(
                Request::SignUp("charles".to_string(), "secure_pass".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = client.next().await.unwrap().unwrap();
        client
            .send(
                Request::Login("charles".to_string(), "secure_pass".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = client.next().await.unwrap().unwrap();

        // 1. Buy 10 tokens
        client
            .send(Request::PurchaseTokens(10).serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();

        if let Response::TokenCount(count) = resp {
            assert_eq!(count, 10);
        } else {
            panic!("Expected TokenCount, received: {:?}", resp);
        }

        // 2. Request a hash signature (consumes 1 token)
        let raw_fake_hash = [5u8; 32];
        let fake_hash = Sha256Hash::from(&raw_fake_hash);

        client
            .send(Request::SignHash(fake_hash).serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp, Response::Token { .. })); // Signature generated successfully

        // 3. Verify that exactly 9 tokens are left
        client
            .send(Request::HowManyTokensDoIHave.serialize().unwrap())
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();
        if let Response::TokenCount(count) = resp {
            assert_eq!(count, 9);
        } else {
            panic!("Expected TokenCount, received: {:?}", resp);
        }
    }

    #[tokio::test]
    async fn test_graceful_shutdown_propagation() {
        // We set up manually here because we need the JoinHandle of the server task
        let (client, server) = tokio::io::duplex(1024);
        let mut client_framed = Framed::new(client, LengthDelimitedCodec::new());
        let server_framed = Framed::new(server, LengthDelimitedCodec::new());

        let cancel_token = CancellationToken::new();
        let database = setup_memory_db().await;

        let state = STSServerStateBuilder::from_bundle(
            database,
            &cancel_token,
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
            TimeOracle::_new_local(),
        )
        .get_accelerated_build();

        let dummy_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Spawn the server and keep track of the JoinHandle
        let server_handle =
            tokio::spawn(async move { conn_handler_core(dummy_addr, server_framed, &state).await });

        // The client logs in normally
        client_framed
            .send(
                Request::SignUp("diana".to_string(), "pass123".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = client_framed.next().await;
        client_framed
            .send(
                Request::Login("diana".to_string(), "pass123".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = client_framed.next().await;

        // SIMULATING CTRL+C: The server triggers the global cancellation token
        cancel_token.cancel();

        // Await the server closure and analyze the result
        let server_output = server_handle.await.unwrap();

        // Verify that the server exited gracefully due to the interrupt
        assert!(matches!(
            server_output,
            Ok(ClosedStreamReason::InterruptReceived)
        ));
    }

    #[tokio::test]
    async fn test_concurrent_login_protection() {
        let (client_a, server_a) = tokio::io::duplex(1024);
        let (client_b, server_b) = tokio::io::duplex(1024);

        let mut client_a_framed = Framed::new(client_a, LengthDelimitedCodec::new());
        let mut client_b_framed = Framed::new(client_b, LengthDelimitedCodec::new());

        let cancel_token = CancellationToken::new();
        let database = setup_memory_db().await;

        let state = STSServerStateBuilder::from_bundle(
            database,
            &cancel_token,
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
            TimeOracle::_new_local(),
        )
        .get_accelerated_build();

        // Register the "victim" directly into the shared DB
        state
            .database
            .try_register_user(
                "victim".to_string(),
                "safe_password".to_string(),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .unwrap();

        // Start handler for Client A
        let state_a = state.clone();

        tokio::spawn(async move {
            let _ = conn_handler_core(
                "127.0.0.1:1111".parse().unwrap(),
                Framed::new(server_a, LengthDelimitedCodec::new()),
                &state_a,
            )
            .await;
        });

        // Start handler for Client B (the attacker)
        let state_b = state.clone();

        tokio::spawn(async move {
            let _ = conn_handler_core(
                "127.0.0.1:2222".parse().unwrap(),
                Framed::new(server_b, LengthDelimitedCodec::new()),
                &state_b,
            )
            .await;
        });

        // 1. Client A logs in successfully
        client_a_framed
            .send(
                Request::Login("victim".to_string(), "safe_password".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp_a = Response::deserialize(client_a_framed.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp_a, Response::Ok));

        // 2. Client B tries to log in with the SAME credentials while A is active
        client_b_framed
            .send(
                Request::Login("victim".to_string(), "safe_password".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp_b = Response::deserialize(client_b_framed.next().await.unwrap().unwrap()).unwrap();

        // The server must reject Client B since the user is already logged in
        assert!(matches!(
            resp_b,
            Response::LoginFailed(LoginError::AlreadyLoggedIn)
        ));

        // 3. Verify that Client A is still connected and operational
        client_a_framed
            .send(Request::HowManyTokensDoIHave.serialize().unwrap())
            .await
            .unwrap();

        let response = client_a_framed.next().await.unwrap().unwrap();

        let resp_a_still_alive = Response::deserialize(response).unwrap();

        assert!(matches!(resp_a_still_alive, Response::TokenCount(_)));
    }

    #[tokio::test]
    async fn test_token_exhaustion_blocking() {
        let (client, server) = tokio::io::duplex(1024);
        let mut client_framed = Framed::new(client, LengthDelimitedCodec::new());

        let cancel_token = CancellationToken::new();
        let database = setup_memory_db().await;

        let state = STSServerStateBuilder::from_bundle(
            database,
            &cancel_token,
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
            TimeOracle::_new_local(),
        )
        .get_slow_build();

        // Prepare the "poor_user" directly in the DB with EXACTLY 1 token
        state
            .database
            .try_register_user(
                "poor_user".to_string(),
                "123".to_string(),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .unwrap();

        state
            .database
            .add_user_tokens("poor_user", 1)
            .await
            .unwrap();

        tokio::spawn(async move {
            let _ = conn_handler_core(
                "127.0.0.1:12345".parse().unwrap(),
                Framed::new(server, LengthDelimitedCodec::new()),
                &state,
            )
            .await;
        });

        // Login
        client_framed
            .send(
                Request::Login("poor_user".to_string(), "123".to_string())
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = client_framed.next().await;

        // First signature send_request (Consumes the only available token)
        let hash = Sha256Hash::from(&[1u8; 32]);

        client_framed
            .send(Request::SignHash(hash).serialize().unwrap())
            .await
            .unwrap();

        let resp1 = Response::deserialize(client_framed.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp1, Response::Token { .. })); // Success!

        // Second signature send_request (Token balance is now zero)
        let hash = Sha256Hash::from(&[1u8; 32]);

        client_framed
            .send(Request::SignHash(hash).serialize().unwrap())
            .await
            .unwrap();

        let resp2 = Response::deserialize(client_framed.next().await.unwrap().unwrap()).unwrap();

        // The server must block the operation
        assert!(matches!(resp2, Response::NotEnoughTokens));
    }
}
