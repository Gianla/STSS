//! Defines the standard function(s) to properly handle an async connection and apply the network
//! protocol of STSS.

use dashmap::DashSet;
use futures::{SinkExt, StreamExt};
use rsa::RsaPrivateKey;
use shared_library::network_numbers::NetworkLongLong;
use shared_library::protocol::{LoginError, Request, Response, SignInError, Timestamp};
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
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
    AddTokensError, AuthenticationError, GetTokensError, InternalDataBaseError, RegistrationError,
    ServerDataBase, SubtractTokensError,
};
use crate::server::{ServerSigner, Signer};
use crate::time_oracle::TimeOracle;

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
    time_oracle: TimeOracle,
    signer: ServerSigner,
}

impl STSServerState {
    /// Returns a STSServerState with all the required data, bundled into a single state.
    /// This method hides the complexity of dealing with Arcs and is useful only to conn_handler().
    pub fn from_bundle(
        database: ServerDataBase,
        cancel_token: &CancellationToken,
        signing_key: RsaPrivateKey,
        time_oracle: TimeOracle,
        signer: ServerSigner,
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
            time_oracle,
            signer,
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
    #[error(
        "Address {0} isn't respecting the protocol: they declared that a huge amount of data \
             (more than {1}) is coming. Either the user is not respecting the protocol, or it has \
             malicious intentions. Disconnecting."
    )]
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
    #[error("Error from user {0}: {1}")]
    Operational(String, String),

    #[error("An error occurred while parsing a message from {0}: {1}.")]
    Parsing(SocketAddr, #[source] ParsingError),

    #[error("An error occurred while serializing a response: {0}")]
    Serialize(#[from] wincode::WriteError),

    #[error("An error occurred while deserializing a request: {0}")]
    Deserialize(#[from] wincode::ReadError),

    #[error("No connection")]
    NetworkDown,

    #[error(transparent)]
    InternalDataBase(#[from] InternalDataBaseError),

    #[error(transparent)]
    Framing(#[from] FramingError),
}

/// Handles a send()'s error and log the proper error message. If the network is down, returns
/// network_down_err in order to be furtherly forwarded upwards.
fn send_error_logger<E>(
    send_err: std::io::Error,
    address: &SocketAddr,
    network_down_err: E,
) -> Result<(), E> {
    match send_err.kind() {
        ErrorKind::BrokenPipe => {
            info!(
                "Connection was unexpectedly closed while the server tried to send a \
                 message to {}. Disconnecting.",
                address,
            );
        }
        ErrorKind::ConnectionReset => {
            info!(
                "Connection has been reset by {}. Closing the connection.",
                address
            );
        }
        ErrorKind::TimedOut => {
            info!(
                "Address {} has timed out while receiving a server's message. Disconnecting.",
                address
            );
        }
        ErrorKind::NetworkDown => {
            return Err(network_down_err);
        }
        generic_error => {
            warn!(
                "Error while sending a message to the client: {}.",
                generic_error
            );
        }
    }

    Ok(())
}

/// Result given by the request fetcher from a framed stream.
pub enum FetchResult<E> {
    /// Data flow has closed successfully.
    GracefulClose(ClosedStreamReason),
    /// Network error or a parsing error.
    Fatal(E),
}

/// Extracts the next request from a framed stream, properly adapting to the function's type
/// ecosystem by the use of generics.
async fn fetch_next_request<S, E, F>(
    stream: &mut Framed<S, LengthDelimitedCodec>,
    cancel_token: &CancellationToken,
    address: SocketAddr,
    map_parsing_err: F,
) -> Result<Request, FetchResult<E>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    E: From<FramingError>,
    F: FnOnce(wincode::ReadError) -> E,
{
    let framed_data = tokio::select! {
        result = stream.next() => result,
        _ = cancel_token.cancelled() => {
            return Err(FetchResult::GracefulClose(ClosedStreamReason::InterruptReceived));
        },
    };

    let result = match framed_data {
        Some(res) => res,
        None => {
            return Err(FetchResult::GracefulClose(ClosedStreamReason::ClientAsked));
        }
    };

    let raw_message = result.map_err(|e| {
        let framing_err = match e.kind() {
            ErrorKind::InvalidData => {
                FramingError::SizeSmashing(address, stream.codec().max_frame_length())
            }
            _ => FramingError::Generic(address, e.to_string()),
        };

        FetchResult::Fatal(framing_err.into())
    })?;

    let request =
        Request::deserialize(raw_message).map_err(|e| FetchResult::Fatal(map_parsing_err(e)))?;

    Ok(request)
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
pub async fn conn_handler(
    address: SocketAddr,
    stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    state: &STSServerState,
) -> Result<ClosedStreamReason, CommunicationError> {
    conn_handler_core(address, stream, state).await
}

/// Stream-type agnostic version of the conn_handler. They are separated because we want to expose
/// to the other module only the rigid version, while we want to keep a flexible version for
/// ourselves in order to test it with simulated streams (read the end of the file to find the
/// tests). Although making the exposed function generic-less is against a bunch of programming
/// principles, we believe that it adds points to security. That's because conn_handler() will only
/// be callable with a ciphered stream (semantically secure) that wraps a TCP stream (type safety).
#[inline(always)]
async fn conn_handler_core<S>(
    address: SocketAddr,
    mut stream: Framed<S, LengthDelimitedCodec>,
    state @ STSServerState {
        database,
        cancel_token,
        logged_users,
        signing_key: _signing_key, // This function won't and doesn't have to use the signing key.
        time_oracle: _time_oracle, // Same.
        signer: _signer,           // Same.
    }: &STSServerState,
) -> Result<ClosedStreamReason, CommunicationError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let request = match fetch_next_request(&mut stream, cancel_token, address, |e| {
            CommunicationError::Parsing(address, e.into())
        })
        .await
        {
            Ok(req) => req,
            Err(FetchResult::GracefulClose(reason)) => break Ok(reason),
            Err(FetchResult::Fatal(err)) => return Err(err),
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
                        // race conditions and security vulnerability (a user would have been able
                        // to log twice).
                        if logged_users.insert(username.clone()) {
                            started_session = Some(Session::bundle(address, username));
                            Response::Ok
                        } else {
                            Response::LoginFailed(LoginError::AlreadyLoggedIn)
                        }
                    }

                    Err(AuthenticationError::InternalDataBase(e)) => {
                        // This is an assertion error. An internal problem of the database is out
                        // of the connection handler's responsibility, so we move it to the caller.
                        return Err(CommunicationError::InternalDataBase(e));
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
                }
            }

            Request::SignUp(username, password) => {
                let result = database
                    .try_register_user(username, password, address.ip())
                    .await;

                match result {
                    Ok(()) => Response::Ok,
                    Err(RegistrationError::InternalDataBase(e)) => {
                        // Same as before (check above comments).
                        return Err(CommunicationError::InternalDataBase(e));
                    }
                    Err(RegistrationError::UserAlreadyExists(_user)) => {
                        Response::SignInFailed(SignInError::UsernameAlreadyTaken)
                    }
                }
            }

            // To everything else, we have to answer that, at this stage, the user is not logged.
            _ => Response::NotLoggedIn,
        };

        if let Err(send_err) = stream.send(response.serialize()?).await {
            send_error_logger(send_err, &address, CommunicationError::NetworkDown)?;
        };

        if let Some(session) = started_session {
            match session_handler(&session, &mut stream, state).await {
                Err(error) => {
                    return Err(CommunicationError::Operational(
                        session.username.clone(),
                        error.to_string(),
                    ))
                }
                Ok(closed_reason) => {
                    let reason = match closed_reason {
                        ClosedSessionReason::ClosedStream(r) => match r {
                            ClosedStreamReason::InterruptReceived => "server interruption",
                            ClosedStreamReason::ClientAsked => "client asked",
                        },
                        ClosedSessionReason::LoggedOut => "logged out",
                    };
                    info!(
                        "User {} is disconnected from logged connection, reason: {}",
                        reason, &session,
                    )
                }
            }
            logged_users.remove(&session.username);
        }
    }
}

/// Groups up the data of a single, complete and logged connection.
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

#[derive(Error, Debug)]
pub enum OperationalError {
    #[error(transparent)]
    Communication(#[from] CommunicationError),

    #[error(transparent)]
    GetTokens(#[from] GetTokensError),

    #[error(transparent)]
    AddTokens(#[from] AddTokensError),

    #[error(transparent)]
    SubtractTokens(#[from] SubtractTokensError),

    #[error("Clock staggered")]
    ClockStaggered,
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
async fn session_handler<S>(
    session @ Session { address, username }: &Session,
    stream: &mut Framed<S, LengthDelimitedCodec>,
    STSServerState {
        database,
        cancel_token,
        logged_users: _logged_users, // No need to access to this inside a session_handler().
        signing_key,
        time_oracle,
        signer,
    }: &STSServerState,
) -> Result<ClosedSessionReason, OperationalError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let request = match fetch_next_request(stream, cancel_token, session.address, |e| {
            CommunicationError::Parsing(session.address, e.into())
        })
        .await
        {
            Ok(req) => req,
            Err(FetchResult::GracefulClose(reason)) => break Ok(reason.into()),
            Err(FetchResult::Fatal(err)) => return Err(OperationalError::from(err)),
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
                        // Both of these are assertion errors. The user MUST exist in the
                        // database if they're logged in. So we return the responsibility
                        // to the caller.
                        SubtractTokensError::UserDoesNotExist
                        | SubtractTokensError::InternalDataBase(_) => {
                            return Err(OperationalError::from(e))
                        }
                    }
                } else {
                    let timestamp = match time_oracle.time_now().duration_since(UNIX_EPOCH) {
                        Ok(ts) => Timestamp::from(ts.as_nanos()),
                        Err(_) => return Err(OperationalError::ClockStaggered),
                    };

                    match signer
                        .generate_timestamp_signature(signing_key, &raw_hash, timestamp)
                        .await
                    {
                        Ok(sign) => {
                            info!(
                                "User {} required to sign the hash {}.",
                                address,
                                hex::encode(raw_hash)
                            );
                            Response::Token { sign, timestamp }
                        }
                        Err(e) => {
                            error!(
                                "[Critical] An hashing operation returned an error: {}. \
                                 This should be impossible.",
                                e.to_string()
                            );

                            if let Err(refund_err) = database.add_user_tokens(username, 1).await {
                                // We at least log this. If the hash operation fails, and the
                                // database operation fails too, an operator has to manually
                                // rollback this.
                                error!(
                                    "Failed to refund 1 token to user {} after a signing failure: \
                                     {:?}",
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

            Request::PurchaseTokens(be_tokens) => {
                let tokens = be_tokens.to_host();

                match database.add_user_tokens(&username, tokens).await {
                    Ok(new_token_count) => {
                        info!("{} updated their tokens: {}.", username, new_token_count);
                        // In this case, we do not send a simple Ok to the client, but we
                        // send a stronger confirmation that its tokens have been updated.
                        Response::TokenCount(NetworkLongLong::from(new_token_count))
                    }
                    Err(token_add_error) => match token_add_error {
                        AddTokensError::TokenOverflow => Response::TokenAmountTooHigh(be_tokens),
                        AddTokensError::UserDoesNotExist | AddTokensError::InternalDataBase(_) => {
                            return Err(token_add_error.into());
                        }
                    },
                }
            }

            Request::HowManyTokensDoIHave => {
                match database.get_user_tokens(&username).await {
                    Ok(n_tokens) => {
                        info!("{} requested their tokens: {}.", username, n_tokens);
                        Response::TokenCount(NetworkLongLong::from(n_tokens))
                    }
                    Err(get_tokens_error) => {
                        // get_user_tokens() fails only when integrity is violated. This case does
                        // not have to be handled by the connection handlers, but by the server.
                        return Err(get_tokens_error.into());
                    }
                }
            }
        };

        let serialized_response = response
            .serialize()
            .map_err(CommunicationError::Serialize)?;

        if let Err(send_err) = stream.send(serialized_response).await {
            send_error_logger(send_err, address, CommunicationError::NetworkDown)?;
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
    use shared_library::network_numbers::NetworkLongLong;
    use shared_library::protocol::{LoginError, Request, Response, SignInError};
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
        STSServerState,
    ) {
        let (client, server) = tokio::io::duplex(4096);
        let client_framed = Framed::new(client, LengthDelimitedCodec::new());
        let server_framed = Framed::new(server, LengthDelimitedCodec::new());

        let cancel_token = CancellationToken::new();
        let database = setup_memory_db().await;

        // Generate a fast, small key for testing to avoid slowing down the test suite
        let signing_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let time_oracle = TimeOracle::dummy();
        let dummy_signer = ServerSigner::dummy();

        let state = STSServerState::from_bundle(
            database,
            &cancel_token,
            signing_key,
            time_oracle,
            dummy_signer,
        );

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
            assert_eq!(count.to_host(), 0);
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

        // Try to sign a dummy hash
        client
            .send(Request::SignHash([0u8; 32]).serialize().unwrap())
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
            .send(
                Request::PurchaseTokens(NetworkLongLong::from(10))
                    .serialize()
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = Response::deserialize(client.next().await.unwrap().unwrap()).unwrap();

        if let Response::TokenCount(count) = resp {
            assert_eq!(count.to_host(), 10);
        } else {
            panic!("Expected TokenCount, received: {:?}", resp);
        }

        // 2. Request a hash signature (consumes 1 token)
        let fake_hash = [5u8; 32];
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
            assert_eq!(count.to_host(), 9);
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

        let state = STSServerState::from_bundle(
            database,
            &cancel_token,
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
            TimeOracle::dummy(),
            ServerSigner::dummy(),
        );

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

        let state = STSServerState::from_bundle(
            database,
            &cancel_token,
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
            TimeOracle::dummy(),
            ServerSigner::dummy(),
        );

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

        let state = STSServerState::from_bundle(
            database,
            &cancel_token,
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
            TimeOracle::dummy(),
            ServerSigner::dummy(),
        );

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

        // First signature request (Consumes the only available token)
        client_framed
            .send(Request::SignHash([1u8; 32]).serialize().unwrap())
            .await
            .unwrap();

        let resp1 = Response::deserialize(client_framed.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp1, Response::Token { .. })); // Success!

        // Second signature request (Token balance is now zero)
        client_framed
            .send(Request::SignHash([1u8; 32]).serialize().unwrap())
            .await
            .unwrap();

        let resp2 = Response::deserialize(client_framed.next().await.unwrap().unwrap()).unwrap();

        // The server must block the operation
        assert!(matches!(resp2, Response::NotEnoughTokens));
    }
}
