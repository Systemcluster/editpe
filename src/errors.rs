//! Errors specific to reading, writing or modifying a PE image.

use alloc::string::{String, ToString};
use core::str::Utf8Error;

#[cfg(feature = "image")]
use image::ImageError;
#[cfg(feature = "image")]
use std::io::Error as IOError;

/// Error that can occur when reading and parsing bytes.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[cfg_attr(feature = "std", error("{0}"))]
pub struct ReadError(pub String);

/// Errors that can occur when reading a PE image.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ImageReadError {
    #[cfg_attr(feature = "std", error("invalid utf8: {0}"))]
    Utf8Error(Utf8Error),
    #[cfg_attr(feature = "std", error("invalid bytes: {0}"))]
    InvalidBytes(ReadError),
    #[cfg_attr(feature = "std", error("invalid header: {0}"))]
    InvalidHeader(String),
    #[cfg_attr(feature = "std", error("missing section: {0}"))]
    MissingSection(String),
    #[cfg_attr(feature = "std", error("invalid section: {0}"))]
    InvalidSection(String),
    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    IOError(IOError),
}
impl From<Utf8Error> for ImageReadError {
    fn from(error: Utf8Error) -> Self { ImageReadError::Utf8Error(error) }
}
impl From<ReadError> for ImageReadError {
    fn from(error: ReadError) -> Self { ImageReadError::InvalidBytes(error) }
}
#[cfg(feature = "std")]
impl From<IOError> for ImageReadError {
    fn from(error: IOError) -> Self { ImageReadError::IOError(error) }
}

/// Errors that can occur when writing a PE image.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ImageWriteError {
    #[cfg_attr(feature = "std", error("not enough space in file header"))]
    NotEnoughSpaceInHeader,
    #[cfg_attr(feature = "std", error("section points outside image: {0} > {1}"))]
    InvalidSectionRange(u64, u64),
    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    IOError(IOError),
}
#[cfg(feature = "std")]
impl From<IOError> for ImageWriteError {
    fn from(error: IOError) -> Self { ImageWriteError::IOError(error) }
}

/// Errors that can occur when modifying resource data.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ResourceError {
    #[cfg_attr(feature = "std", error("invalid table: {0}"))]
    InvalidTable(String),
    #[cfg_attr(feature = "std", error("invalid bytes: {0}"))]
    InvalidBytes(ReadError),
    #[cfg(feature = "image")]
    #[error("invalid icon: {0}")]
    InvalidIconResource(ImageError),
    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    IOError(IOError),
}
impl From<ReadError> for ResourceError {
    fn from(error: ReadError) -> Self { ResourceError::InvalidBytes(error) }
}
#[cfg(feature = "image")]
impl From<ImageError> for ResourceError {
    fn from(error: ImageError) -> Self { ResourceError::InvalidIconResource(error) }
}
#[cfg(feature = "std")]
impl From<IOError> for ResourceError {
    fn from(error: IOError) -> Self { ResourceError::IOError(error) }
}
