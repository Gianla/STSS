//! Contains the main component for the server, with network and cryptography utilities.

use crate::connection_handler::conn_handler;
use crate::connection_handler::{HandlerError, NetworkError, ParsingError, STSServerState};
use crate::database::{DataBaseBuildError, DataBaseLocation, ServerDataBaseBuilder};
use crate::server::NetworkPort::{AnyFreePort, Port};
use crate::time_oracle::{TimeOracleBundle, TimeSyncWorker};
use rsa::sha2::{Digest, Sha256};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use shared_library::protocol::Timestamp;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task;
use tokio::task::JoinError;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;

/// Where to write logs. For the moment, we support stdout and a filepath.
pub enum LogDestination {
    Stdout,
    File { dir: PathBuf, filename: PathBuf },
}

/// Port configurations: can both be 0, which means to let the OS decide, or be more than it.
#[derive(Debug)]
pub enum NetworkPort {
    AnyFreePort,
    Port(NonZero<u16>),
}

/// Simple logic to handle ports.
impl NetworkPort {
    pub fn from(port: u16) -> Self {
        match NonZero::new(port) {
            None => AnyFreePort,
            Some(p) => Port(p),
        }
    }

    pub fn get(&self) -> u16 {
        match self {
            AnyFreePort => 0,
            Port(p) => p.get(),
        }
    }
}

/// The Config structure is useful only for unprocessed configuration's data. For example,
/// key's paths are just file paths and not the keys themselves.
pub struct ServerContext {
    address: SocketAddr,
    runtime_context: RuntimeContext,
    key_context: KeyContext,
    time_oracle_bundle: TimeOracleBundle,
    log_output: LogDestination,
    database_location: DataBaseLocation,
}

pub struct RuntimeContext {
    working_threads: usize,
    cryptography_threads: usize,
}

impl RuntimeContext {
    pub fn new(working_threads: usize, cryptography_threads: usize) -> Self {
        Self {
            working_threads,
            cryptography_threads,
        }
    }
}

/// Group keys for Servercontext.
pub struct KeyContext {
    tls_cert: Vec<CertificateDer<'static>>,
    tls_priv: PrivateKeyDer<'static>,
    tss_priv: RsaPrivateKey,
}

impl KeyContext {
    pub fn new(
        tls_cert: Vec<CertificateDer<'static>>,
        tls_priv: PrivateKeyDer<'static>,
        tss_priv: RsaPrivateKey,
    ) -> Self {
        Self {
            tls_cert,
            tls_priv,
            tss_priv,
        }
    }
}

impl ServerContext {
    pub fn new(
        address: SocketAddr,
        runtime_context: RuntimeContext,
        key_context: KeyContext,
        time_oracle_bundle: TimeOracleBundle,
        log_output: LogDestination,
        database_location: DataBaseLocation,
    ) -> Self {
        Self {
            address,
            runtime_context,
            key_context,
            time_oracle_bundle,
            log_output,
            database_location,
        }
    }
}

/// Errors that might arise when signing with a signer.
#[derive(Debug, Error)]
pub enum SignError {
    #[error(transparent)]
    Crypto(#[from] rsa::Error),

    #[error(transparent)]
    ThreadPanic(#[from] JoinError),
}

/// A signer implements an RSA signature function.
pub trait Signer {
    fn generate_timestamp_signature(
        &self,
        signing_key: &Arc<RsaPrivateKey>,
        hash_to_sign: &[u8; 32],
        timestamp: Timestamp,
    ) -> impl Future<Output = Result<Vec<u8>, SignError>> + Send;
}

/// Main function used to sign a hash.
#[inline(always)]
fn generate_timestamp_signature_core(
    signing_key: &Arc<RsaPrivateKey>,
    hash_to_sign: &[u8; 32],
    timestamp: Timestamp,
) -> Result<Vec<u8>, SignError> {
    let mut hasher = Sha256::new();

    hasher.update(hash_to_sign);
    hasher.update(timestamp.get().to_be_bytes());

    let combined_hash: [u8; 32] = hasher.finalize().into();
    let padding = Pkcs1v15Sign::new::<Sha256>();

    signing_key
        .sign(padding, &combined_hash)
        .map_err(SignError::Crypto)
}

/// The Accelerated Signer is used when the cryptography threads are zero, because the system
/// supports hardware acceleration. For this reason, it simply wraps the signature function
/// without other operations. Thanks to rust's zero-cost abstraction systems, this will be compiled
/// down to a very cheap operation and the function will be inlined.
#[derive(Clone)]
pub struct AcceleratedSigner;

impl Signer for AcceleratedSigner {
    async fn generate_timestamp_signature(
        &self,
        signing_key: &Arc<RsaPrivateKey>,
        hash_to_sign: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<Vec<u8>, SignError> {
        generate_timestamp_signature_core(signing_key, hash_to_sign, timestamp)
    }
}

/// The Slow Signer is used when the cryptography threads are more than zero, because the system
/// does not support hardware acceleration. For this reason, it uses the current tokio runtime to
/// spawn a blocking thread that performs the sign. Tokio will be configured to use a blocking
/// threadpool if the configuration requires the use of SlowSigner.
#[derive(Clone)]
pub struct SlowSigner;

impl Signer for SlowSigner {
    async fn generate_timestamp_signature(
        &self,
        signing_key: &Arc<RsaPrivateKey>,
        hash_to_sign: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<Vec<u8>, SignError> {
        let key_clone = Arc::clone(signing_key);
        let hash_copy = *hash_to_sign; // just copy it.

        let task_result = task::spawn_blocking(move || {
            generate_timestamp_signature_core(&key_clone, &hash_copy, timestamp)
        })
        .await;

        task_result.map_err(SignError::ThreadPanic)?
    }
}

/// "Generic" signer.
#[derive(Clone)]
pub enum ServerSigner {
    Accelerated(AcceleratedSigner),
    Slow(SlowSigner),
}

impl ServerSigner {
    pub fn dummy() -> Self {
        Self::Accelerated(AcceleratedSigner {})
    }
}

impl Signer for ServerSigner {
    async fn generate_timestamp_signature(
        &self,
        signing_key: &Arc<RsaPrivateKey>,
        hash_to_sign: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<Vec<u8>, SignError> {
        match self {
            ServerSigner::Accelerated(s) => {
                s.generate_timestamp_signature(signing_key, hash_to_sign, timestamp)
                    .await
            }
            ServerSigner::Slow(s) => {
                s.generate_timestamp_signature(signing_key, hash_to_sign, timestamp)
                    .await
            }
        }
    }
}

/// Errors that might arise while building the server.
#[derive(Error, Debug)]
pub enum STSServerBuildError {
    #[error("zero working threads has been selected, while at least one is needed")]
    ZeroWorkingThreads,

    #[error("error while setting up the TLS logic for the server: {0}")]
    TLSSetup(String),

    #[error(
        "error with the logger: {0}; likely, the logger was already built (and so the server)"
    )]
    Logger(String),

    #[error(transparent)]
    DataBase(#[from] DataBaseBuildError),
}

/// Errors that might arise while running the server.
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
    GenericAccept(String),
}

/// Data needed by the server at runtime.
pub struct STSServer {
    address: SocketAddr,
    runtime: Runtime,
    tls_acceptor: TlsAcceptor,
    state: STSServerState,
    time_oracle_worker: Option<TimeSyncWorker>,
    _log_guard: WorkerGuard,
}

impl STSServer {
    pub fn build_from_context(
        ServerContext {
            address,
            runtime_context:
                RuntimeContext {
                    working_threads,
                    cryptography_threads,
                },
            key_context:
                KeyContext {
                    tls_cert,
                    tls_priv,
                    tss_priv,
                },
            time_oracle_bundle,
            log_output,
            database_location,
        }: ServerContext,
    ) -> Result<Self, STSServerBuildError> {
        let (non_blocking_writer, _log_guard, startup_msg) = match log_output {
            LogDestination::Stdout => {
                let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
                (writer, guard, "Logger initialized on stdout".to_string())
            }
            LogDestination::File { dir, filename } => {
                let file_appender = tracing_appender::rolling::never(&dir, &filename);
                let (writer, guard) = tracing_appender::non_blocking(file_appender);

                let full_path = Path::new(&dir).join(&filename);

                let msg = match full_path.to_str() {
                    Some(utf8_path) => format!("Logger initialized to file: {}", utf8_path),
                    None => {
                        "Logger initialized to the specified file (non-UTF-8 path).".to_string()
                    }
                };

                (writer, guard, msg)
            }
        };

        tracing_subscriber::fmt()
            .with_writer(non_blocking_writer)
            .try_init()
            .map_err(|e| STSServerBuildError::Logger(e.to_string()))?;

        info!(startup_msg);

        let mut rt = match working_threads {
            0 => return Err(STSServerBuildError::ZeroWorkingThreads),
            1 => tokio::runtime::Builder::new_current_thread(),
            n => {
                let mut inner_rt = tokio::runtime::Builder::new_multi_thread();
                inner_rt.worker_threads(n);
                inner_rt
            }
        };

        let signer = if cryptography_threads > 0 {
            rt.max_blocking_threads(cryptography_threads);
            info!(
                "Using a threadpool-based and slow signer of {} threads. This solution is better \
                 if this system doesn't support hardware acceleration. If it is desired to use \
                 the faster signer, please set the variable cryptography_threads in the \
                 configuration file to be more than zero.",
                cryptography_threads,
            );
            ServerSigner::Slow(SlowSigner)
        } else {
            debug!("Using an accelerated signer for cryptography operations.");
            ServerSigner::Accelerated(AcceleratedSigner)
        };

        let rt = rt
            .enable_all()
            .build()
            .expect("This runtime should work everytime, except breaking changes");

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(tls_cert, tls_priv)
            .map_err(|e| STSServerBuildError::TLSSetup(e.to_string()))?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(config));

        let database =
            rt.block_on(async { ServerDataBaseBuilder::build(database_location).await })?;

        let cancel_token = CancellationToken::new();
        let (time_oracle, worker) = time_oracle_bundle.into_parts();
        let time_oracle_worker = Some(worker);

        let state =
            STSServerState::from_bundle(database, &cancel_token, tss_priv, time_oracle, signer);

        debug!("Server correctly built.");

        Ok(Self {
            runtime: rt,
            address,
            state,
            tls_acceptor,
            time_oracle_worker,
            _log_guard,
        })
    }

    /// Wrapper around the more complex run_with_signal(). run_with_signal() is needed in order to
    /// test the server with different stopping signals than ctrl+c. This function calls it with
    /// only the only shutdown option ctrl+c, furthermore, it can be used in the future to update
    /// the shutdown methods.
    pub fn run(self) -> Result<(), STSServerRunError> {
        self.run_with_signal(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }

    /// Mainly, it does three things:
    /// 1. spawns the asynchronous time oracle worker, used to sync the clock;
    /// 2. spawns the asynchronous shutdown signal listener, whatever that signal can be (default:
    ///    ctrl+c), used to shut down the connected clients and the server gracefully;
    /// 3. calls the asynchronous client acceptor loop.
    #[inline(always)]
    fn run_with_signal<F>(mut self, shutdown_signal: F) -> Result<(), STSServerRunError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let token_for_signal = self.state.clone_cancel_token();
        let token_for_run = self.state.clone_cancel_token();
        let token_for_sync = self.state.clone_cancel_token();

        let mut time_oracle_worker = self.time_oracle_worker.take();

        self.runtime.block_on(async {
            if let Some(worker) = time_oracle_worker.take() {
                tokio::spawn(async move {
                    if let Err(e) = worker.start_syncing().await {
                        error!(
                            "[Critical] Fatal syncing error: {}. Interrupting the server.",
                            e.to_string()
                        );
                        token_for_sync.cancel();
                    }
                });
            } else {
                error!(
                    "[Critical] Worker was already taken, but this should be impossible. \
                     Interrupting the server."
                );
                token_for_sync.cancel();
            }

            tokio::spawn(async move {
                shutdown_signal.await;
                info!("Detected interruption, sending cancel command to the tasks.");
                token_for_signal.cancel();
            });

            self.accept_loop(token_for_run).await?;

            Ok(())
        })
    }

    async fn accept_loop(&self, cancel_token: CancellationToken) -> Result<(), STSServerRunError> {
        let listener = TcpListener::bind(self.address)
            .await
            .map_err(|e| match e.kind() {
                ErrorKind::AddrInUse => STSServerRunError::PortAlreadyInUse(self.address.port()),
                ErrorKind::PermissionDenied => {
                    STSServerRunError::PermissionDenied(self.address.port())
                }
                ErrorKind::AddrNotAvailable => STSServerRunError::AddrNotAvailable(self.address),
                _ => STSServerRunError::GenericBind(e.to_string()),
            })?;

        info!(
            "Address {} bounded, listening for incoming connections.",
            self.address
        );

        // Instead of spawning coroutines randomly, we use a tracker. A tracker is also useful to
        // spawn coroutines, except it can wait for them to end properly. The challenge becomes to
        // make them end in some way. We believe that this has been addressed properly inside
        // connection_handler(), therefore, a tracker can only make our server more resilient.
        let tracker = TaskTracker::new();

        let mut _unanswered_syn_count: u64 = 0;

        loop {
            // Here lays the server hotpath.
            let task_cancel_token = cancel_token.clone();

            let accept_result = tokio::select! {
                res = listener.accept() => res,
                _ = task_cancel_token.cancelled() => break,
            };

            let (stream, new_address) = match accept_result {
                Ok(res) => res,
                Err(e) => {
                    match e.kind() {
                        ErrorKind::ConnectionAborted => {
                            // Maybe this variable can be used in some network management
                            // operation, but it's not our priority right now.
                            let _ = _unanswered_syn_count.checked_add(1);
                            continue;
                        }
                        _ => continue,
                    }
                }
            };

            // Thanks to rust's abstraction systems, we can implement a zero-cost copy. Arc is
            // just a smart pointer that increments its counter each time a clone is made:
            // real data is never cloned, keeping the hot path clear from memory-intensive
            // operations.
            // Sharing the state is necessary since the run function could expire while
            // coroutines are still running; however, thanks to the smart pointers, this will
            // be impossible.
            let state_clone = self.state.clone();
            let tls_acceptor_clone = self.tls_acceptor.clone();

            tracker.spawn(async move {
                // Wrapping the newbie stream into a tls_stream will perform the TLS handshake.
                // The TLS acceptor is interpreted as the server-side of the handshake, where we
                // loaded certificates and configurations before.
                let tls_stream =
                    tls_acceptor_clone
                        .accept(stream)
                        .await
                        .inspect_err(|tls_error| {
                            info!(
                                "Address {} performed a wrong TLS handshake: {}.",
                                new_address,
                                tls_error.to_string()
                            )
                        })?;

                // if the TLS handshake was successful, we further wrap the tls stream into a framed
                // stream. A framed stream is an abstraction of a stream, where the first n bytes
                // (usually n = 4) are used to identify the length of the message coded after those
                // bytes. This way, an unreliable stream turns into an iterator yielding
                // fixed-length messages.
                let codec = LengthDelimitedCodec::new();
                let framed_stream = Framed::new(tls_stream, codec);

                info!(
                    "Address {} connected and performed the TLS handshake. Waiting for commands.",
                    new_address
                );

                // Pass the correct, encrypted and framed stream to the main connection manager.
                if let Err(e) = conn_handler(new_address, framed_stream, &state_clone).await {
                    match e {
                        HandlerError::Domain { username, source } => {
                            // Determine if the user was logged in or if they were still a guest
                            let user_context =
                                username.unwrap_or_else(|| "[Not Logged]".to_string());

                            error!(
                                "A serious issue was reported for user '{}': {}. \
                                 Potentially, this can lead to problems with all the other current \
                                 sessions. This one has been closed, but expect others to do so \
                                 too.",
                                user_context, source
                            );
                        }

                        HandlerError::Network(network_err) => match network_err {
                            NetworkError::ConnectionDropped => {
                                info!("{} disconnected.", new_address);
                            }

                            NetworkError::ServerNetworkDown => {
                                error!(
                                    "[CRITICAL] Server's local network interface is down. \
                                     Shutting the server."
                                );
                                task_cancel_token.clone().cancel();
                            }

                            NetworkError::Framing { address, source } => {
                                warn!(
                                    "Framing error with {}: {}. Probably, a huge incoming \
                                     amount of data has been detected (likely a DOS attack) \
                                     and the message has been refused. Connection closed.",
                                    address, source
                                );
                            }

                            NetworkError::Parsing(parsing_err) => match parsing_err {
                                ParsingError::Serialize(error) => {
                                    error!(
                                        "Error while serializing a response to send to a \
                                         client: {}. Likely, this will happen for all this \
                                         kind of responses, for all sessions. This \
                                         connection has been closed, but expect others to \
                                         do so too.",
                                        error,
                                    )
                                }

                                ParsingError::Deserialize(error) => {
                                    warn!(
                                        "Protocol parsing/serialization error with {}: {}. \
                                         The client might not be respecting the protocol \
                                         or sent an unrecognized pattern. Connection \
                                         closed.",
                                        new_address, error
                                    );
                                }
                            },

                            NetworkError::Generic(io_err) => {
                                error!(
                                    "Generic network error from address {}: {}. Connection \
                                     closed.",
                                    new_address, io_err
                                );
                            }
                        },
                    }
                }

                // tokio cannot infer types properly, so we must help it with a turbofish operator.
                Ok::<(), std::io::Error>(())
            });
        }

        tracker.close();

        info!("Interrupt requested. Waiting for clients to disconnect...");

        tracker.wait().await;

        info!("Done. Exiting gracefully.");

        Ok(())
    }
}


