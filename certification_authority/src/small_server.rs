use crate::config::CaContext;
use futures_util::{SinkExt, StreamExt};
use rcgen::{CertificateSigningRequestParams, Issuer, KeyPair};
use rustls_pki_types::CertificateSigningRequestDer;
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

    #[error("CA key material is not valid UTF-8: {0}")]
    KeyNotUtf8(String),

    #[error("CA certificate is not valid UTF-8: {0}")]
    CertNotUtf8(String),

    #[error("cannot parse CA private key: {0}")]
    CaKey(String),

    #[error("cannot build CA issuer: {0}")]
    CaIssuer(String),

    #[error("cannot parse certificate signing request: {0}")]
    Csr(String),

    #[error("cannot sign certificate signing request: {0}")]
    Sign(String),
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

            match sign_certificate_request(raw_cert, context) {
                Ok(pem_cert) => {
                    info!(
                        pem_cert_bytes = pem_cert.len(),
                        "certificate signed successfully by CA"
                    );

                    Response::Ok { pem_cert }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "certificate-signing request rejected"
                    );

                    Response::CanNotSignTheCertificate {
                        reason: e.to_string(),
                    }
                }
            }
        }
    }
}

fn sign_certificate_request(
    raw_csr: Vec<u8>,
    context: &CaContext,
) -> Result<String, ClientHandlingError> {
    let ca_key_pem = std::str::from_utf8(&context.ca_key_pem)
        .map_err(|e| ClientHandlingError::KeyNotUtf8(e.to_string()))?;

    let ca_cert_pem = std::str::from_utf8(&context.ca_cert_pem)
        .map_err(|e| ClientHandlingError::CertNotUtf8(e.to_string()))?;

    let ca_key_pair =
        KeyPair::from_pem(ca_key_pem).map_err(|e| ClientHandlingError::CaKey(e.to_string()))?;

    let ca_issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key_pair)
        .map_err(|e| ClientHandlingError::CaIssuer(e.to_string()))?;

    let csr_der = CertificateSigningRequestDer::from(raw_csr);
    let csr_params = CertificateSigningRequestParams::from_der(&csr_der)
        .map_err(|e| ClientHandlingError::Csr(e.to_string()))?;

    let signed_certificate = csr_params
        .signed_by(&ca_issuer)
        .map_err(|e| ClientHandlingError::Sign(e.to_string()))?;

    Ok(signed_certificate.pem())
}
