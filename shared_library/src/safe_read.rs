//! Utils for file's safe reading, properly documenting the errors that might arise, without
//! panicking for too large files while handling this case too.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{ErrorKind, Take};
use std::io::Read;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that may arise while opening and reading a file.
#[derive(Error, Debug)]
pub enum SafeReadError {
    // These operations will be performed multiple times by the server (e.g. loading its
    // configurations, loading the keys, loading the database...) so it might be wanted to document
    // this process in the correct way.
    #[error("the specified file {0:?} is not a {1:?} file")]
    WrongExtension(PathBuf, OsString),

    #[error("the specified file {0:?} was not found")]
    OpenNotFound(PathBuf),

    #[error("cannot access the specified file {0:?}: permission denied")]
    OpenPermissionDenied(PathBuf),

    #[error("an error occurred while opening {0:?}: {1:?}")]
    OpenGeneric(PathBuf, String),

    // this can only happen if open was successful, but the file is deleted immediately later.
    #[error(
        "cannot read metadata from the specified configuration file {0:?}: {1:?} (probably, \
             the file has been deleted in the process)"
    )]
    Metadata(PathBuf, String),

    #[error("memory error while reading {0:?}: {1:?}")]
    Memory(PathBuf, String),

    #[error("error reading the file {0:?}: {1:?}")]
    Read(PathBuf, String),
}

/// A memory-safe file reader that processes files in fixed-size chunks
/// without allocating memory dynamically during iteration.
pub struct GenericSafeFileReader<const CHUNK_SIZE: usize = 8192> {
    // The file wrapper limited to its declared metadata size.
    reader: Take<File>,
    // The internal fixed-size buffer rewritten at each step.
    buffer: [u8; CHUNK_SIZE],
    // Saved path for descriptive error reporting.
    filepath: PathBuf,
    // Total size extracted from metadata, useful for full allocation in safe_read().
    total_size: u64,
}

pub type SafeFileReader = GenericSafeFileReader<8192>;

impl<const CHUNK_SIZE: usize> GenericSafeFileReader<CHUNK_SIZE> {
    /// Creates a new `SafeFileReader` after validating the file extension and metadata.
    pub fn new(
        raw_path: impl Into<PathBuf>,
        expected_extension: Option<impl AsRef<OsStr>>,
    ) -> Result<Self, SafeReadError> {
        let filepath = raw_path.into();

        // 1. Validate file extension if provided.
        if let Some(e_extension) = expected_extension {
            let e_extension_ref = e_extension.as_ref();
            if filepath.extension().is_none_or(|ext| ext != e_extension_ref) {
                return Err(SafeReadError::WrongExtension(
                    filepath,
                    e_extension_ref.into(),
                ));
            }
        }

        // 2. Open the file safely.
        let file = File::open(&filepath).map_err(|e| match e.kind() {
            ErrorKind::NotFound => SafeReadError::OpenNotFound(filepath.clone()),
            ErrorKind::PermissionDenied => SafeReadError::OpenPermissionDenied(filepath.clone()),
            _ => SafeReadError::OpenGeneric(filepath.clone(), e.to_string()),
        })?;

        // 3. Extract and validate metadata length.
        let metadata = file
            .metadata()
            .map_err(|e| SafeReadError::Metadata(filepath.clone(), e.to_string()))?;
        let file_len = metadata.len();

        Ok(Self {
            // Protect against infinite streams by limiting the reader to the metadata size.
            reader: file.take(file_len),
            buffer: [0u8; CHUNK_SIZE],
            filepath,
            total_size: file_len,
        })
    }

    /// Fetches the next chunk of the file.
    /// This acts as a "Lending Iterator" method, reusing the internal fixed buffer.
    pub fn next_chunk(&mut self) -> Option<Result<&[u8], SafeReadError>> {
        match self.reader.read(&mut self.buffer) {
            Ok(0) => None, // End of File reached successfully.
            Ok(bytes_read) => {
                // Return only the slice of bytes actually read in this turn.
                Some(Ok(&self.buffer[..bytes_read]))
            }
            Err(e) => {
                let err_string = e.to_string();
                Some(Err(SafeReadError::Read(self.filepath.clone(), err_string)))
            },
        }
    }

    /// Consumes the reader and performs an ultra-safe full read of the file,
    /// leveraging the pre-calculated metadata length and safe memory allocation.
    pub fn safe_read(mut self) -> Result<Vec<u8>, SafeReadError> {
        // Architecture check for 32-bit platforms to prevent overflow.
        #[cfg(target_pointer_width = "32")]
        let allocation_size = usize::try_from(self.total_size).map_err(|_| {
            SafeReadError::Memory(
                self.filepath.clone(),
                "File is too large for a 32-bit architecture allocation".to_string(),
            )
        })?;

        #[cfg(not(target_pointer_width = "32"))]
        let allocation_size = self.total_size as usize;

        // Securely pre-allocate the final vector.
        let mut full_buffer = Vec::new();
        full_buffer
            .try_reserve(allocation_size)
            .map_err(|e| SafeReadError::Memory(self.filepath.clone(), e.to_string()))?;

        // Stream all remaining chunks into the pre-allocated vector.
        while let Some(chunk_result) = self.next_chunk() {
            let chunk = chunk_result?;
            full_buffer.extend_from_slice(chunk);
        }

        Ok(full_buffer)
    }
}

/// Complexity-less convenience wrapper around SafeFileReader.
pub fn safe_read(
    raw_path: impl Into<PathBuf>,
    expected_extension: Option<impl AsRef<OsStr>>,
) -> Result<Vec<u8>, SafeReadError> {
    let reader = SafeFileReader::new(raw_path, expected_extension)?;
    reader.safe_read()
}
