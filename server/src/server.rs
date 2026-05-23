//! Contains the main component for the server, with network and cryptography utilities.

use crate::connection_handler::STSServerState;
use crate::connection_handler::{conn_handler, CommunicationError};
use crate::database::{DataBaseBuildError, DataBaseLocation, ServerDataBaseBuilder};
use crate::server::NetworkPort::{AnyFreePort, Port};
use crate::time_oracle::{TimeOracleBundle, TimeSyncWorker};
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
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

        let database =
            rt.block_on(async { ServerDataBaseBuilder::build(database_location).await })?;

        let cancel_token = CancellationToken::new();
        let (time_oracle, worker) = time_oracle_bundle.into_parts();
        let time_oracle_worker = Some(worker);

        let state = STSServerState::from_bundle(database, &cancel_token, tss_priv, time_oracle);

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

    pub fn run(mut self) -> Result<(), STSServerRunError> {
        let token_for_signal = self.state.clone_cancel_token();
        let token_for_run = self.state.clone_cancel_token();
        let token_for_sync = self.state.clone_cancel_token();

        let mut time_oracle_worker = self.time_oracle_worker.take();

        self.runtime.block_on(async {
            if let Some(worker) = time_oracle_worker.take() {
                tokio::spawn(async move {
                    if let Err(e) = worker.start_syncing().await {
                        error!(
                            "Fatal syncing error: {}. Interrupting the server.",
                            e.to_string()
                        );
                        token_for_sync.cancel();
                    }
                });
            } else {
                error!(
                    "Assertion: worker was already taken, but this should be impossible. \
                     Interrupting the server."
                );
                token_for_sync.cancel();
            }

            tokio::spawn(async move {
                if let Ok(()) = tokio::signal::ctrl_c().await {
                    info!("Detected interruption, sending cancel command to the tasks.");
                    token_for_signal.cancel();
                }
            });

            self.internal_run(token_for_run).await?;

            info!("Clients disconnected, server closing.");

            Ok(())
        })
    }

    async fn internal_run(&self, cancel_token: CancellationToken) -> Result<(), STSServerRunError> {
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
        let mut _unanswered_syn_count: u64 = 0;

        loop {
            // here lays the server hotpath.
            let accept_result = tokio::select! {
                res = listener.accept() => res,
                _ = cancel_token.cancelled() => break,
            };

            let (stream, new_address) = match accept_result {
                Ok(res) => res,
                Err(e) => {
                    match e.kind() {
                        ErrorKind::ConnectionAborted => {
                            // maybe this variable can be used in some network management
                            // operation, but it's not our priority right now.
                            let _ = _unanswered_syn_count.checked_add(1);
                            continue;
                        }
                        _ => continue,
                    }
                }
            };

            // thanks to rust's abstraction systems, we can implement a zero-cost copy. Arc is
            // just a smart pointer that increments its counter each time a clone is made:
            // real data is never cloned, keeping the hot path clear from memory-intensive
            // operations.
            // Sharing the state is necessary since the run function could expire while
            // coroutines are still running; however, thanks to the smart pointers, this will
            // be impossible.
            let state_clone = self.state.clone();
            let tls_acceptor_clone = self.tls_acceptor.clone();

            tokio::spawn(async move {
                // wrapping the newbie stream into a tls_stream will perform the TLS handshake.
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

                // pass the correct, encrypted and framed stream to the main connection manager.
                if let Err(e) = conn_handler(new_address, framed_stream, &state_clone).await {
                    match e {
                        // todo
                        CommunicationError::Operational(_, _) => {}
                        CommunicationError::Parsing(_, _) => {}
                        CommunicationError::Serialize(_) => {}
                        CommunicationError::Deserialize(_) => {}
                        CommunicationError::NetworkDown => {}
                        CommunicationError::InternalDataBase(_) => {}
                        CommunicationError::Framing(_) => {}
                    }
                };
                /*
                match frame_error.kind() {
                    ErrorKind::InvalidData => {
                        warn!("Address {} isn't respecting the protocol: they declared that a huge \
                               amount of data (more than {}) is coming. Either the user is not \
                               respecting the protocol, or it has malicious intentions. \
                               Disconnecting.", address, stream.codec().max_frame_length());
                    }
                    _ => {
                        info!("Problem with address {} while extracting the message from the \
                               stream: {}.", address, frame_error.to_string())
                    }
                }
                */

                // tokio cannot infer types properly, so we must help it with a turbofish operator.
                Ok::<(), std::io::Error>(())
            });
        }
        debug!("Outside of server's loop, stopping the internal run.");

        Ok(())
    }
}
