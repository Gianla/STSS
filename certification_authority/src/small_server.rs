use crate::config::CaContext;
use futures_util::{SinkExt, StreamExt};
use shared_library::ca_protocol::{Request, Response};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, warn};

const MAX_CA_FRAME_LENGTH: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SmallServerRunError {
    #[error("cannot bind CA listener: {0}")]
    Bind(std::io::Error),

    #[error("cannot accept incoming CA connection: {0}")]
    Accept(std::io::Error),
}

#[derive(Debug, Error)]
enum ClientHandlingError {
    #[error("network/framing error: {0}")]
    Network(#[from] std::io::Error),

    #[error("cannot deserialize CA request: {0}")]
    Decode(String),

    #[error("cannot serialize CA response: {0}")]
    Encode(String),
}

pub struct SmallServer {
    context: CaContext,
}

impl SmallServer {
    pub fn build(context: CaContext) -> Self {
        Self { context }
    }

    pub async fn run(self) -> Result<(), SmallServerRunError> {
        let listener = TcpListener::bind(self.context.address)
            .await
            .map_err(SmallServerRunError::Bind)?;

        info!(
            address = %self.context.address,
            "Certification Authority listening for requests"
        );

        info!(
            ca_cert_bytes = self.context.ca_cert_pem.len(),
            ca_key_bytes = self.context.ca_key_pem.len(),
            "CA key material loaded"
        );

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted
                        .map_err(SmallServerRunError::Accept)?;

                    info!(
                        %peer,
                        "incoming connection accepted by Certification Authority"
                    );

                    let context = self.context.clone();

                    tokio::spawn(async move {
                        match handle_client(stream, context).await {
                            Ok(()) => {
                                info!(
                                    %peer,
                                    "CA client connection closed cleanly"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    %peer,
                                    error = %e,
                                    "CA client connection closed with an error"
                                );
                            }
                        }
                    });
                }

                shutdown_result = tokio::signal::ctrl_c() => {
                    match shutdown_result {
                        Ok(()) => {
                            info!("shutdown signal received, stopping Certification Authority");
                        }
                        Err(e) => {
                            error!(
                                error = %e,
                                "failed to listen for shutdown signal"
                            );
                        }
                    }

                    return Ok(());
                }
            }
        }
    }
}

async fn handle_client(stream: TcpStream, context: CaContext) -> Result<(), ClientHandlingError> {
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_CA_FRAME_LENGTH)
        .new_codec();

    let mut framed = Framed::new(stream, codec);

    while let Some(frame_result) = framed.next().await {
        let raw_message = frame_result?;

        debug!(
            request_size = raw_message.len(),
            "raw CA protocol message received"
        );

        let request = Request::deserialize(&raw_message)
            .map_err(|e| ClientHandlingError::Decode(e.to_string()))?;

        let response = handle_request(request, &context).await;

        let serialized_response = response
            .serialize()
            .map_err(|e| ClientHandlingError::Encode(e.to_string()))?;

        framed.send(serialized_response).await?;

        debug!("CA response sent successfully");
    }

    Ok(())
}

async fn handle_request(request: Request, context: &CaContext) -> Response {
    match request {
        Request::CertificateSign { raw_cert } => {
            info!(
                request_size = raw_cert.len(),
                ca_cert_bytes = context.ca_cert_pem.len(),
                ca_key_bytes = context.ca_key_pem.len(),
                "certificate-signing request received"
            );

            /*
                For now we cannot return a signed certificate because the shared
                CA protocol currently defines only:

                    Response::Ok

                The real signing logic can be added here later, after deciding
                what `raw_request` contains:

                    - CSR bytes,
                    - server public key plus subject data,
                    - or a custom serialized STSS structure.

                Until then, the CA safely acknowledges the request.
            */

            Response::Ok {
                pem_cert: "".to_string(),
            }
        }
    }
}
