//! Contains the main component for the server, with network and cryptography utilities.

use crate::connection_handler::{conn_handler, STSServerStateBuilder};
use crate::connection_handler::{HandlerError, NetworkError, STSServerState};
use crate::database::{DataBaseBuildError, DataBaseLocation, ServerDataBaseBuilder};
use crate::server::NetworkPort::{AnyFreePort, Port};
use crate::time_oracle::{TimeOracleBundle, TimeSyncWorker};

use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use shared_library::server_protocol::{sign_with_timestamp, RsaSignature, Sha256Hash, Timestamp};
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

/// Where to write logs. For the moment, we support stdout and a filepath (or no logs).
pub enum LogDestination {
    None,
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
        hash_to_sign: Sha256Hash,
        timestamp: Timestamp,
    ) -> impl Future<Output = Result<RsaSignature, SignError>> + Send;
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
        hash_to_sign: Sha256Hash,
        timestamp: Timestamp,
    ) -> Result<RsaSignature, SignError> {
        let hash_copy = hash_to_sign;

        sign_with_timestamp(signing_key, hash_copy, timestamp).map_err(SignError::Crypto)
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
        hash_to_sign: Sha256Hash,
        timestamp: Timestamp,
    ) -> Result<RsaSignature, SignError> {
        let key_clone = Arc::clone(signing_key);
        let hash_copy = hash_to_sign; // just copy it.

        // In this case, we instruct the threadpool to take in charge of the calculation.
        let task_result =
            task::spawn_blocking(move || sign_with_timestamp(&key_clone, hash_copy, timestamp))
                .await
                .map_err(SignError::ThreadPanic)?;

        task_result.map_err(SignError::Crypto)
    }
}

/// Only needed to keep the builder stateful.
pub struct NoSignerYet;

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

/// Public point of entry for the server.
pub enum STSServer {
    Accelerated(STSServerInstance<AcceleratedSigner>),
    Slow(STSServerInstance<SlowSigner>),
}

/// Support .into() for accelerated instances.
impl From<STSServerInstance<AcceleratedSigner>> for STSServer {
    fn from(value: STSServerInstance<AcceleratedSigner>) -> Self {
        STSServer::Accelerated(value)
    }
}

/// Support .into() for slow instances.
impl From<STSServerInstance<SlowSigner>> for STSServer {
    fn from(value: STSServerInstance<SlowSigner>) -> Self {
        STSServer::Slow(value)
    }
}

/// Data needed by the server at runtime.
pub struct STSServerInstance<S: Signer> {
    address: SocketAddr,
    runtime: Runtime,
    tls_acceptor: TlsAcceptor,
    state: STSServerState<S>,
    time_oracle_worker: Option<TimeSyncWorker>,
    _log_guard: Option<WorkerGuard>,
}

impl STSServer {
    /// Builds a STSServerInstance starting from a context.
    /// This method abstracts the complexity of handling a slow or an accelerated signer, creating
    /// either one or the other instance based on the config file (specifically,
    /// cryptography_threads).
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
        let log_setup = match log_output {
            LogDestination::None => None,
            LogDestination::Stdout => {
                let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
                Some((writer, guard, "Logger initialized on stdout".to_string()))
            }
            LogDestination::File { dir, filename } => {
                let file_appender = tracing_appender::rolling::never(&dir, &filename);
                let (writer, guard) = tracing_appender::non_blocking(file_appender);

                let msg = if let Some(utf8_path) = Path::new(&dir).join(&filename).to_str() {
                    format!("Logger initialized to file: {}", utf8_path)
                } else {
                    "Logger initialized to the specified file (non-UTF-8 path).".to_string()
                };

                Some((writer, guard, msg))
            }
        };

        let mut _log_guard = None;

        if let Some((writer, guard, startup_msg)) = log_setup {
            tracing_subscriber::fmt()
                .with_writer(writer)
                .try_init()
                .map_err(|e| STSServerBuildError::Logger(e.to_string()))?;

            _log_guard = Some(guard);

            info!(startup_msg);
        }

        let mut rt_builder = match working_threads {
            0 => return Err(STSServerBuildError::ZeroWorkingThreads),
            1 => tokio::runtime::Builder::new_current_thread(),
            n => {
                let mut inner_rt = tokio::runtime::Builder::new_multi_thread();
                inner_rt.worker_threads(n);
                inner_rt
            }
        };

        rt_builder.enable_all();

        let do_not_use_hardware_acceleration = cryptography_threads > 0;

        if do_not_use_hardware_acceleration {
            rt_builder.max_blocking_threads(cryptography_threads);
        }

        let rt = rt_builder
            .build()
            .expect("this should work everytime, except breaking changes");

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
            STSServerStateBuilder::from_bundle(database, &cancel_token, tss_priv, time_oracle);

        debug!("Server correctly built.");

        if do_not_use_hardware_acceleration {
            info!(
                "Using a slow signer that uses a threadpool of {} threads. This solution is better \
                 if this system doesn't support hardware acceleration. If it is desired to use \
                 the faster signer, please set the variable cryptography_threads in the \
                 configuration file to zero.",
                cryptography_threads,
            );

            let build = STSServerInstance {
                runtime: rt,
                address,
                state: state.get_slow_build(),
                tls_acceptor,
                time_oracle_worker,
                _log_guard,
            };

            Ok(build.into())
        } else {
            debug!("Using an accelerated signer for cryptography operations.");

            let build = STSServerInstance {
                runtime: rt,
                address,
                state: state.get_accelerated_build(),
                tls_acceptor,
                time_oracle_worker,
                _log_guard,
            };

            Ok(build.into())
        }
    }

    /// Public entry point to start the server in a blocking fashion.
    /// Abstracts the complexity of having an accelerated or slow signer.
    pub fn run(self) -> Result<(), STSServerRunError> {
        match self {
            STSServer::Accelerated(server) => server.run(),
            STSServer::Slow(server) => server.run(),
        }
    }
}

impl<S> STSServerInstance<S>
where
    S: Signer + Clone + Send + 'static + Sync,
{
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

    /// Runs the TCP acceptor and handles the TLS handshake and the proper creation of each stream.
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

                // If the TLS handshake was successful, we further wrap the tls stream into a framed
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
                            // conn_handler() returns an HandlerError::Domain only when a server's
                            // serious issue was found. It does not return it if, for example, a
                            // user drops it connection or logs out: these cases are handled in the
                            // other error branch.
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
                            // Classical errors that might appear when a user misbehave in some way.
                            NetworkError::ConnectionDropped => {
                                info!("{} abruptly disconnected.", new_address);
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

                            NetworkError::Deserialize(deserialize_err) => {
                                warn!(
                                    "Protocol parsing/serialization error with {}: {}. \
                                     The client might not be respecting the protocol \
                                     or sent an unrecognized pattern. Connection \
                                     closed.",
                                    new_address, deserialize_err
                                );
                            }

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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use shared_library::server_protocol::RSA_KEY_SIZE_IN_BITS;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsConnector;

    /// Let tests start the server with their custom signals.
    impl STSServer {
        fn run_with_signal<F>(self, shutdown_signal: F) -> Result<(), STSServerRunError>
        where
            F: Future<Output = ()> + Send + 'static,
        {
            match self {
                STSServer::Accelerated(server) => server.run_with_signal(shutdown_signal),
                STSServer::Slow(server) => server.run_with_signal(shutdown_signal),
            }
        }
    }

    impl ServerContext {
        /// Generates a valid, in-memory ServerContext strictly for testing purposes.
        /// This bypasses the filesystem completely, generating self-signed certificates
        /// and RSA keys on the fly using the exact same logic of the environment generator.
        pub fn dummy(port: u16) -> Self {
            use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};
            use rustls::pki_types::{CertificateDer, PrivateKeyDer};
            use std::net::{IpAddr, Ipv4Addr};

            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

            // 1 working thread, 0 cryptography threads (so it uses the AcceleratedSigner)
            let runtime_context = RuntimeContext::new(1, 0);

            let server_tls_keypair = KeyPair::generate_for(&PKCS_ED25519)
                .expect("Failed to generate TLS keypair in tests");

            let mut server_tls_params = CertificateParams::new(vec!["127.0.0.1".to_string()])
                .expect("Failed to create certificate params");

            server_tls_params
                .distinguished_name
                .push(DnType::OrganizationName, "University of Pisa");
            server_tls_params
                .distinguished_name
                .push(DnType::CommonName, "TSA Server Mock");

            let server_tls_cert = server_tls_params
                .self_signed(&server_tls_keypair)
                .expect("Failed to self-sign certificate in tests");

            let tls_cert = vec![CertificateDer::from(server_tls_cert.der().to_vec())];

            let tls_priv = PrivateKeyDer::try_from(server_tls_keypair.serialize_der())
                .expect("Failed to parse the private key DER into rustls PrivateKeyDer");

            let mut rng = rand::thread_rng();
            let tss_priv = rsa::RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE_IN_BITS)
                .expect("Failed to generate RSA private key in tests");

            let key_context = KeyContext::new(tls_cert, tls_priv, tss_priv);

            Self {
                address,
                runtime_context,
                key_context,
                time_oracle_bundle: TimeOracleBundle::dummy(),
                log_output: LogDestination::None,
                database_location: DataBaseLocation::Memory,
            }
        }
    }

    /// A custom verifier that blindly accepts any server certificate.
    /// This is strictly required for testing because our mock server generates
    /// a new self-signed certificate on the fly, which the client wouldn't trust.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    async fn connect_with_retry(addr: &str) -> TcpStream {
        let mut attempts: u32 = 0;
        loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => return stream,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    attempts = attempts.wrapping_add(1);
                    if attempts > 100 {
                        panic!("Server didn't open the port in time: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("Unexpected error during TCP connection: {}", e),
            }
        }
    }

    /// Creates a tokio-rustls TlsConnector that accepts any certificate.
    fn create_test_tls_connector() -> TlsConnector {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();

        TlsConnector::from(Arc::new(config))
    }

    // =========================================================================
    // TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let test_port = 8081;
        let (tx, rx) = oneshot::channel();
        let context = ServerContext::dummy(test_port);

        // Spawn the server in a blocking thread to avoid the "runtime within a runtime" panic.
        let server_handle = tokio::task::spawn_blocking(move || {
            let server = STSServer::build_from_context(context).expect("Server failed to build");

            server
                .run_with_signal(async {
                    let _ = rx.await;
                })
                .expect("Server encountered a run error");
        });

        // Give the server enough time to bind the TCP listener.
        let addr = format!("127.0.0.1:{}", test_port);
        let stream = connect_with_retry(&addr).await;

        // Brutally drop it.
        drop(stream);

        // Now we can send the end signal.
        tx.send(()).expect("Failed to send shutdown signal");

        let result = tokio::time::timeout(Duration::from_secs(3), server_handle).await;

        assert!(
            result.is_ok(),
            "The server did not shut down gracefully within the timeout period"
        );
    }

    #[tokio::test]
    async fn test_non_tls_garbage_connection() {
        let test_port = 8082;
        let (tx, rx) = oneshot::channel();

        let context = ServerContext::dummy(test_port);

        let server_handle = tokio::task::spawn_blocking(move || {
            let server = STSServer::build_from_context(context).unwrap();
            server
                .run_with_signal(async {
                    let _ = rx.await;
                })
                .unwrap();
        });

        // Connect using RAW TCP (bypassing TLS entirely)
        let addr = format!("127.0.0.1:{}", test_port);
        let mut stream = connect_with_retry(&addr).await;

        // Send raw garbage bytes instead of a valid TLS Client Hello
        stream
            .write_all(b"HELLO SERVER THIS IS NOT TLS")
            .await
            .expect("Failed to write garbage data");
        let mut buffer = [0; 1024];
        let bytes_read = stream.read(&mut buffer).await.unwrap_or(0);

        assert!(
            bytes_read == 0 || bytes_read == 7,
            "Server should have dropped the connection or sent a 7-byte TLS Alert, but sent {} \
             bytes",
            bytes_read
        );

        if bytes_read == 7 {
            assert_eq!(
                buffer[0],
                0x15, // 0x15 = 21 (TLS Alert Content Type)
                "The 7 bytes received should be a TLS Alert packet starting with 0x15"
            );
        }

        // Let's see if the stream is really closed.
        let eof_read = stream.read(&mut buffer).await.unwrap_or(0);
        assert_eq!(
            eof_read, 0,
            "Connection should be completely closed after the alert"
        );

        // Clean up
        tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
    }

    #[tokio::test]
    async fn test_tls_sudden_disconnection() {
        let test_port = 8083;
        let (tx, rx) = oneshot::channel();
        let context = ServerContext::dummy(test_port);

        let server_handle = tokio::task::spawn_blocking(move || {
            let server = STSServer::build_from_context(context).unwrap();
            server
                .run_with_signal(async {
                    let _ = rx.await;
                })
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(200)).await;

        // 1. Establish a RAW TCP connection
        let addr = format!("127.0.0.1:{}", test_port);
        let stream = connect_with_retry(&addr).await;

        // 2. Perform the TLS Handshake using our test connector
        let connector = create_test_tls_connector();
        let domain = ServerName::try_from("127.0.0.1").unwrap();

        let _tls_stream = connector
            .connect(domain, stream)
            .await
            .expect("TLS Handshake failed");

        // We are now fully connected via TLS. The server is waiting for framed data.

        // 3. Brutally drop the connection without sending a CloseNotify
        drop(_tls_stream);

        // Give the server time to process the sudden drop and clear the TaskTracker
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 4. Ensure the server hasn't panicked and can shut down cleanly
        tx.send(()).unwrap();
        let shutdown_result = tokio::time::timeout(Duration::from_secs(3), server_handle).await;

        assert!(
            shutdown_result.is_ok(),
            "Server crashed or hung up after a client suddenly disconnected"
        );
    }
}
