//! Errors specific to reading, writing or modifying a PE image.

use std::str::Utf8Error;

use thiserror::Error;

/// Error that can occur when reading and parsing bytes.
#[derive(Error, Debug)]
#[error("{0}")]
pub struct ReadError(pub String);

/// Errors that can occur when reading a PE image.
#[derive(Error, Debug)]
pub enum ImageReadError {
    #[error("invalid utf8: {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("invalid bytes: {0}")]
    InvalidBytes(#[from] ReadError),
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    #[error("missing section: {0}")]
    MissingSection(String),
    #[error("invalid section: {0}")]
    InvalidSection(String),
}

/// Errors that can occur when writing a PE image.
#[derive(Error, Debug)]
pub enum ImageWriteError {
    #[error("not enough space in file header")]
    NotEnoughSpaceInHeader,
    #[error("section points outside image: {0} > {1}")]
    InvalidSectionRange(u64, u64),
}
