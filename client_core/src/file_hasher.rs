use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use shared_library::safe_read::{SafeFileReader, SafeReadError};
use sha2::{Sha256, Digest};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use shared_library::server_protocol::Timestamp;
use crate::client::STSSClient;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("Error while reading the file to hash: {0:?}")]
    SafeRead(#[from] SafeReadError),
}

pub fn hash_file(
    raw_path: impl Into<PathBuf>,
    expected_extension: Option<&str>,
) -> Result<[u8; 32], SafeReadError> {
    let mut reader = SafeFileReader::new(raw_path, expected_extension)?;

    let mut hasher = Sha256::new();

    while let Some(chunk_result) = reader.next_chunk() {
        hasher.update(chunk_result?);
    }

    let hash_result = hasher.finalize();

    Ok(hash_result.into())
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Error while verifying the sign: {0:?}")]
    Crypto(#[from] rsa::errors::Error),
}

impl STSSClient {
    /// Verify a signature.
    #[inline(always)]
    pub fn verify_timestamp_signature(
        &self,
        hash_to_verify: &[u8; 32],
        timestamp: Timestamp,
        signature: &[u8],
    ) -> Result<(), VerifyError> {
        let mut hasher = Sha256::new();
        
        hasher.update(hash_to_verify);
        hasher.update(timestamp.get().to_be_bytes());

        let combined_hash: [u8; 32] = hasher.finalize().into();

        let padding = Pkcs1v15Sign::new::<Sha256>();

        self.server_rsa_public_key()
            .verify(padding, &combined_hash, signature)
            .map_err(VerifyError::Crypto)
    }
}