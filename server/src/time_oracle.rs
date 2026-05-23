use std::net::{SocketAddr, UdpSocket, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use sntpc::{NtpContext, StdTimestampGen, get_time};
use sntpc_net_tokio::UdpSocketWrapper;
use tracing::{info, warn};

use crate::server::NetworkPort;

/// Groups up the time oracle and its related worker.
pub struct TimeOracleBundle {
    oracle: TimeOracle,
    worker: TimeSyncWorker,
}

/// This implementation purposely avoid to access to the bundle from outside in order to create
/// an unsafe and not-correlated one. Only the TimeOracle::create_bundle() method will be able to
/// return such bundle. At the same time, we add a into_parts() method in order to force the caller
/// to get both owned and to handle them properly at the same time, so that they won't be lost.
impl TimeOracleBundle {
    fn internal_new(oracle: TimeOracle, worker: TimeSyncWorker ) -> Self {
        Self { oracle, worker }
    }

    pub fn into_parts(self) -> (TimeOracle, TimeSyncWorker) {
        (self.oracle, self.worker)
    }
}

#[derive(Debug, Error)]
pub enum TimeOracleError {
    #[error("cannot set nonblocking mode for the udp socket: {0}")]
    SocketSetNonBlocking(String),

    #[error("error while binding {0}: {1}")]
    ListenerError(SocketAddr, String),

    #[error("error while converting the listener to asynchronous: {0}")]
    ListenerConversionError(String),

    #[error("dns returned an error for {0:?}: {1:?}")]
    NoDnsAddress(String, String),

    #[error("the specified address {0:?} is probably empty")]
    NoAddressSpecified(String),

    #[error("hostname {0:?} has no associated IP address in the DNS server")]
    HostnameNotFound(String),

    #[error("error while resolving the hostname: {0:?}")]
    GenericNetworkError(String),

    #[error("clock time")]
    TimeWentBackwards,

    #[error("port has been set to zero, but this is unreliable")]
    UnreliablePort,
}

/// Builds an oracle that can sync with an external NTP server and tell the time.
/// This struct is cheap to clone and can be passed safely across multiple coroutines.
#[derive(Clone)]
pub struct TimeOracle {
    offset_nanos: Arc<AtomicI64>,
}

impl TimeOracle {
    /// Initialize the TimeOracle. This function can also be called from outside the tokio runtime.
    /// Returns a tuple containing the cloneable oracle and the background sync worker.
    pub fn create_bundle(
        ntp_server_host: String,
        ntp_server_port: NetworkPort,
        listener_address: SocketAddr,
        sync_interval: Duration,
    ) -> Result<TimeOracleBundle, TimeOracleError> {
        let port = match ntp_server_port {
            NetworkPort::AnyFreePort => return Err(TimeOracleError::UnreliablePort),
            NetworkPort::Port(p) => p.get(),
        };

        let ntp_server_addr = (ntp_server_host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e|
                TimeOracleError::NoDnsAddress(
                    format!("{}:{}", ntp_server_host, port),
                    e.to_string()
                )
            )?
            .next()
            .ok_or_else(||
                TimeOracleError::NoAddressSpecified(format!("{}:{}", ntp_server_host, port))
            )?;

        let listener = UdpSocket::bind(listener_address)
            .map_err(|e| TimeOracleError::ListenerError(listener_address, e.to_string()))?;

        listener.set_nonblocking(true)
            .map_err(|e| TimeOracleError::SocketSetNonBlocking(e.to_string()))?;

        let sntpc_context = NtpContext::new(StdTimestampGen::default());
        let offset_nanos = Arc::new(AtomicI64::new(0));

        let oracle = Self {
            offset_nanos: offset_nanos.clone(),
        };

        let worker = TimeSyncWorker {
            ntp_server_addr,
            listener,
            sntpc_context,
            sync_interval,
            offset_nanos,
        };

        Ok( TimeOracleBundle::internal_new(oracle, worker) )
    }

    /// Returns the current time, adjusted with the outside NTP server's clock.
    pub fn time_now(&self) -> SystemTime {
        let local_now = SystemTime::now();
        let offset = self.offset_nanos.load(Ordering::Relaxed);

        if offset > 0 {
            local_now + Duration::from_nanos(offset as u64)
        } else {
            local_now - Duration::from_nanos((-offset) as u64)
        }
    }
}

/// Background worker responsible for maintaining the NTP synchronization.
/// This should be spawned in a dedicated Tokio task.
pub struct TimeSyncWorker {
    ntp_server_addr: SocketAddr,
    listener: UdpSocket,
    sntpc_context: NtpContext<StdTimestampGen>,
    sync_interval: Duration,
    offset_nanos: Arc<AtomicI64>,
}

impl TimeSyncWorker {
    /// Syncs each sync_interval with the specified NTP server.
    /// This function will panic if a tracing subscriber hasn't been set up yet.
    /// Note: This method consumes `self`, taking exclusive ownership of the socket.
    pub async fn start_syncing(self) -> Result<(), TimeOracleError> {
        let async_listener = tokio::net::UdpSocket::from_std(self.listener)
            .map_err(|e| TimeOracleError::ListenerConversionError(e.to_string()))?;

        let sntpc_wrapper = UdpSocketWrapper::from(async_listener);

        let mut interval = tokio::time::interval(self.sync_interval);

        loop {
            interval.tick().await;

            let addr = match tokio::net::lookup_host(&self.ntp_server_addr).await {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => return Err(
                        TimeOracleError::HostnameNotFound(self.ntp_server_addr.to_string())
                    ),
                },
                Err(e) => return Err( TimeOracleError::GenericNetworkError(e.to_string()) ),
            };

            match get_time(addr, &sntpc_wrapper, self.sntpc_context).await {
                Ok(ntp_time) => {
                    let ntp_secs = ntp_time.sec() as u64;
                    let ntp_nanos = sntpc::fraction_to_nanoseconds(ntp_time.sec_fraction());
                    let total_ntp_nanos = (ntp_secs * 1_000_000_000) + ntp_nanos as u64;

                    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
                        let total_local_nanos = duration.as_nanos() as u64;
                        let offset = total_ntp_nanos as i64 - total_local_nanos as i64;

                        self.offset_nanos.store(offset, Ordering::Relaxed);
                    } else {
                        return Err( TimeOracleError::TimeWentBackwards )
                    }
                },
                Err(error) => match error {
                    sntpc::Error::Network => {
                        info!(
                            "Network problem while syncing with the NTP server {}, retrying later.",
                            &self.ntp_server_addr
                        )
                    }

                    sntpc::Error::AddressResolve => {
                        warn!(
                            "Cannot resolve {}, however, it was solved before. Retrying later. If \
                             this keeps happening, consider to change the configurations or check \
                             your connection.",
                            &self.ntp_server_addr
                        )
                    }

                    _ => {
                        // sntpc doesn't support the Display trait for their errors, so we must
                        // format it on our own.
                        let error_string = format!("{:?}", error);

                        return Err( TimeOracleError::GenericNetworkError(error_string) )
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU16;
    use tokio::net::UdpSocket as TokioUdpSocket;
    use tokio::time::{sleep, Duration};

    // We implement a helper method available only during tests to read the internal offset.
    impl TimeOracle {
        pub fn get_offset_for_testing(&self) -> i64 {
            self.offset_nanos.load(Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn test_sync_worker_updates_offset_from_mock_server() {
        // Set up the mock server on a random local port.
        let mock_server = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        // Convert the port to the expected type.
        let port = NetworkPort::Port(NonZeroU16::new(server_addr.port()).unwrap());
        let listener_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sync_interval = Duration::from_millis(50);

        // Create the bundle using the mock server address.
        let bundle = TimeOracle::create_bundle(
            "127.0.0.1".to_string(),
            port,
            listener_addr,
            sync_interval,
        ).unwrap();

        let (oracle, worker) = bundle.into_parts();

        // Spawn the worker in a background task.
        let worker_handle = tokio::spawn(async move {
            let _ = worker.start_syncing().await;
        });

        // Wait for the client request.
        let mut buf = [0u8; 1024];
        let (size, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

        assert!(size >= 48, "The client should send at least a 48 byte payload.");

        // Build the mock response based on the client request.
        let mut response = [0u8; 48];
        response.copy_from_slice(&buf[0..48]);

        // Set version to 4 and mode to server.
        response[0] = 0x24;

        // Set stratum to a valid level.
        response[1] = 2;

        // Move the client transmit timestamp to the origin timestamp.
        response[24..32].copy_from_slice(&buf[40..48]);

        // Create fake receive and transmit timestamps.
        response[32..40].copy_from_slice(&buf[40..48]);
        response[40..48].copy_from_slice(&buf[40..48]);

        // Add an arbitrary delay to the transmit timestamp to simulate an offset.
        response[40] = response[40].wrapping_add(1);

        // Send the response back to the client.
        mock_server.send_to(&response, client_addr).await.unwrap();

        // Allow the worker some time to process the response.
        sleep(Duration::from_millis(100)).await;

        // Verify that the offset has been updated.
        let offset = oracle.get_offset_for_testing();
        assert_ne!(offset, 0, "The offset should have been updated by the mock server.");

        // Abort the background task to cleanly exit the test.
        worker_handle.abort();
    }
}
