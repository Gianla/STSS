use sntpc::{get_time, NtpContext, StdTimestampGen};
use sntpc_net_tokio::UdpSocketWrapper;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
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
    fn internal_new(oracle: TimeOracle, worker: TimeSyncWorker) -> Self {
        Self { oracle, worker }
    }

    pub fn into_parts(self) -> (TimeOracle, TimeSyncWorker) {
        (self.oracle, self.worker)
    }
}

/// A dummy implementation for tests only.
#[cfg(test)]
impl TimeOracleBundle {
    /// Creates a dummy TimeOracleBundle strictly for testing purposes.
    /// It binds a UDP socket to a random local port to satisfy the worker's structural
    /// requirements without performing actual network requests.
    pub(crate) fn dummy() -> Self {
        use sntpc::{NtpContext, StdTimestampGen};
        use std::net::UdpSocket;
        use std::sync::atomic::AtomicI64;
        use std::sync::Arc;
        use std::time::Duration;

        let listener = UdpSocket::bind("127.0.0.1:0")
            .expect("Failed to bind a dummy UDP socket for the testing time oracle");

        listener.set_nonblocking(true).unwrap();

        let offset_nanos = Arc::new(AtomicI64::new(0));

        let oracle = TimeOracle {
            offset_nanos: offset_nanos.clone(),
        };

        let worker = TimeSyncWorker {
            ntp_server_addr: "127.0.0.1:123".parse().unwrap(),
            listener,
            sntpc_context: NtpContext::new(StdTimestampGen::default()),
            sync_interval: Duration::from_secs(3600), // Very long interval, won't trigger in tests
            offset_nanos,
        };

        Self::internal_new(oracle, worker)
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
            .map_err(|e| {
                TimeOracleError::NoDnsAddress(
                    format!("{}:{}", ntp_server_host, port),
                    e.to_string(),
                )
            })?
            .next()
            .ok_or_else(|| {
                TimeOracleError::NoAddressSpecified(format!("{}:{}", ntp_server_host, port))
            })?;

        let listener = UdpSocket::bind(listener_address)
            .map_err(|e| TimeOracleError::ListenerError(listener_address, e.to_string()))?;

        listener
            .set_nonblocking(true)
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

        Ok(TimeOracleBundle::internal_new(oracle, worker))
    }

    /// Returns the current time, adjusted with the outside NTP server's clock.
    pub fn time_now(&self) -> SystemTime {
        let local_now = SystemTime::now();
        let offset = self.offset_nanos.load(Ordering::Relaxed);

        if offset >= 0 {
            local_now
                .checked_add(Duration::from_nanos(offset as u64))
                .unwrap_or(local_now)
        } else {
            // unsigned_abs() handles i64::MIN in a secure way. That's really paranoid, but heh...
            local_now
                .checked_sub(Duration::from_nanos(offset.unsigned_abs()))
                .unwrap_or(local_now)
        }
    }
}

/// An implementation useful when signatures requires a time oracle, but we don't want to create
/// a "real" one since it isn't needed.
#[cfg(test)]
impl TimeOracle {
    /// We don't need the functionality of a time oracle inside these tests. That's why we just
    /// implement a function that returns a dummy to shut up the compiler.
    pub(crate) fn dummy() -> Self {
        use std::sync::atomic::AtomicI64;
        use std::sync::Arc;

        Self {
            offset_nanos: Arc::new(AtomicI64::new(0)),
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
                    None => {
                        return Err(TimeOracleError::HostnameNotFound(
                            self.ntp_server_addr.to_string(),
                        ))
                    }
                },
                Err(e) => return Err(TimeOracleError::GenericNetworkError(e.to_string())),
            };

            // No unchecked (aka without over/underflow protection) math is allowed in this project.
            // Therefore, what follows is the complex way to say "get the offset from the NTP server
            // to your local clock".
            match get_time(addr, &sntpc_wrapper, self.sntpc_context).await {
                Ok(ntp_time) => {
                    // Get the seconds in u32, so convert it to u64 is safe.
                    let ntp_secs = ntp_time.sec() as u64;
                    // fraction_to_nanoseconds() returns u32, so again, it's safe.
                    let ntp_nanos = sntpc::fraction_to_nanoseconds(ntp_time.sec_fraction()) as u64;

                    // Take the NTP server's seconds.
                    let total_ntp_nanos = ntp_secs
                        // Multiply it for 10^9 to get it into milliseconds.
                        .checked_mul(1_000_000_000)
                        // Safely add the NTP server's nanoseconds.
                        .and_then(|ns| ns.checked_add(ntp_nanos))
                        // If the sum was not successful (overflow), return an error. Note that this
                        // behavior is so drastic only because this is a really hard case, however,
                        // we might want to handle that differently in the future (e.g. use a
                        // fallback value).
                        .ok_or_else(|| {
                            TimeOracleError::GenericNetworkError("NTP timestamp overflow".into())
                        })?;

                    // Get the duration since 1 Jan 1970.
                    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
                        // If not negative, get it as nanoseconds.
                        let total_local_nanos: u128 = duration.as_nanos();

                        // Converts safely a u64 into a i128.
                        let ntp_128 = i128::from(total_ntp_nanos);

                        // Try to downcast a u128 into a i128, otherwise, cap it to its maximum.
                        let local_128 = i128::try_from(total_local_nanos).unwrap_or(i128::MAX);

                        // Calculate the offset. Shouldn't panic, but we set the default at 0
                        // anyway.
                        let offset_128 = ntp_128.checked_sub(local_128).unwrap_or(0);

                        // We try to extract the offset into a u64, otherwise capping it to its
                        // max/min value depending on the limit.
                        let capped = offset_128.clamp(i64::MIN as i128, i64::MAX as i128);
                        let offset_i64 = capped as i64;

                        self.offset_nanos.store(offset_i64, Ordering::Relaxed);
                    } else {
                        return Err(TimeOracleError::TimeWentBackwards);
                    }
                }
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

                        return Err(TimeOracleError::GenericNetworkError(error_string));
                    }
                },
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
        let bundle =
            TimeOracle::create_bundle("127.0.0.1".to_string(), port, listener_addr, sync_interval)
                .unwrap();

        let (oracle, worker) = bundle.into_parts();

        // Spawn the worker in a background task.
        let worker_handle = tokio::spawn(async move {
            let _ = worker.start_syncing().await;
        });

        // Wait for the client request.
        let mut buf = [0u8; 1024];
        let (size, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

        assert!(
            size >= 48,
            "The client should send at least a 48 byte payload."
        );

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
        assert_ne!(
            offset, 0,
            "The offset should have been updated by the mock server."
        );

        // Abort the background task to cleanly exit the test.
        worker_handle.abort();
    }
}
