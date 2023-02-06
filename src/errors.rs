//! Errors specific to reading, writing or modifying a PE image.

use std::{io::Error as IOError, str::Utf8Error};

use thiserror::Error;

#[cfg(feature = "image")]
use image::ImageError;

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

/// Errors that can occur when modifying resource data.
#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("invalid table: {0}")]
    InvalidTable(String),
    #[error("invalid data: {0}")]
    InvalidData(#[from] IOError),
    #[cfg(feature = "image")]
    #[error("invalid icon: {0}")]
    InvalidIconResource(#[from] ImageError),
    #[error("invalid bytes: {0}")]
    InvalidBytes(#[from] ReadError),
}
