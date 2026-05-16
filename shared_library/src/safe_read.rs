//! Utils for file's safe reading, properly documenting the errors that might arise, without
//! panicking for too large files while handling this case too.

use std::io::Read;
use std::fs::File;
use std::io::ErrorKind;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use thiserror::Error;

/// Errors that may arise while opening and reading a file.
#[derive(Error, Debug)]
pub enum SafeReadError {
    /* These operations will be performed multiple times by the server (e.g. loading its
       configurations, loading the keys, loading the database...) so it might be wanted to document
       this process in the correct way. */
    #[error("the specified file {0:?} is not a {1:?} file")]
    WrongExtension(PathBuf, OsString),

    #[error("the specified file {0:?} was not found")]
    OpenNotFound(PathBuf),

    #[error("cannot access the specified file {0:?}: permission denied")]
    OpenPermissionDenied(PathBuf),

    #[error("an error occurred while opening {0:?}: {1:?}")]
    OpenGeneric(PathBuf, String),

    /* this can only happen if open was successful, but the file is deleted immediately later. */
    #[error("cannot read metadata from the specified configuration file {0:?}: {1:?} (probably, \
             the file has been deleted in the process)")]
    Metadata(PathBuf, String),

    #[error("memory error while reading {0:?}: {1:?}")]
    Memory(PathBuf, String),

    #[error("error reading the file {0:?}: {1:?}")]
    Read(PathBuf, String),
}

/// Given a file path and an extension it should have, performs an ultra memory-safe read operation
/// on the file, properly documenting any possible exception even with memory allocation. If no
/// extension is provided, the check isn't performed at all.
pub fn safe_read(
    raw_path: impl Into<PathBuf>,
    expected_extension: Option<impl AsRef<OsStr>>
) -> Result<Vec<u8>, SafeReadError> {
    let filepath = raw_path.into();

    /* perform the check only if there's an extension. */
    if let Some(e_extension) = expected_extension {
        /* if the file has an extension, it checks if it is expected_extension. If not,
           it simply returns false. This is just a necessary condition, but not sufficient,
           since extensions are just metadata. */
        let e_extension_ref = e_extension.as_ref();
        if !filepath.extension().map_or(false, |ext| ext == e_extension.as_ref()) {
            return Err(SafeReadError::WrongExtension(filepath, e_extension_ref.into()));
        }
    }

    let file = File::open(&filepath).map_err(|e| match e.kind() {
        ErrorKind::NotFound => SafeReadError::OpenNotFound(filepath.clone()),
        ErrorKind::PermissionDenied => SafeReadError::OpenPermissionDenied(filepath.clone()),
        _ => SafeReadError::OpenGeneric(filepath.clone(), e.to_string()),
    })?;

    /* the opened file has some dimension, that we try to extract from its metadata
       without reading the entire content. This is done in order to prevent memory attacks
       with a file that is too big: it is better to crash gracefully before any operation. */
    let metadata = file.metadata().map_err(|e| {
        SafeReadError::Metadata(filepath.clone(), e.to_string())
    })?;
    let file_len = metadata.len();

    #[cfg(target_pointer_width = "32")]
    /* for 32 bits architectures, we can't be sure that an u64 can be strictly converted into
       a usize without loss of information. However, in case there's a conversion error, the
       file would still be too large, so we return that instead of a custom error. */
    let filesize = usize::try_from(file_len)
        .map_err(|_| SafeReadError::Memory(
            filepath.clone(), "file is too large (around 4 GB or more)".to_string()
        ))?;

    #[cfg(not(target_pointer_width = "32"))]
    /* otherwise, on 64 bits architectures, there's no problem. */
    let filesize = file_len as usize;

    let mut buffer: Vec<u8> = Vec::new();
    /* here try_reserve will crash if the filesize is really large and memory wouldn't hold it. */
    buffer.try_reserve(filesize).map_err(|e| {
        SafeReadError::Memory(filepath.clone(), e.to_string())
    })?;

    /* safe_reader is a wrapper around file that is limited to filesize. The file in question
       declared in its metadata to be filesize bytes large: if it's not, the parsing will
       likely return an error. */
    let mut safe_reader = file.take(file_len);
    safe_reader.read_to_end(&mut buffer).map_err(|e| {
        SafeReadError::Read(filepath.clone(), e.to_string())
    })?;

    Ok(buffer)
}
