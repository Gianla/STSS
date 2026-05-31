use sha2::{Digest, Sha256};
use shared_library::safe_read::{SafeFileReader, SafeReadError};
use shared_library::server_protocol::Sha256Hash;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("Error while reading the file to hash: {0:?}")]
    SafeRead(#[from] SafeReadError),
}

pub fn hash_file(
    raw_path: impl Into<PathBuf>,
    expected_extension: Option<&str>,
) -> Result<Sha256Hash, SafeReadError> {
    let mut reader = SafeFileReader::new(raw_path, expected_extension)?;

    let mut hasher = Sha256::new();

    while let Some(chunk_result) = reader.next_chunk() {
        hasher.update(chunk_result?);
    }

    let hash_result = Sha256Hash::from(hasher.finalize().as_ref());

    Ok(hash_result)
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Error while verifying the sign: {0:?}")]
    Crypto(#[from] rsa::errors::Error),
}
