//! Resource **edit**or for **p**ortable **e**xecutables.
//!
//! Supports:
//! * Parsing and introspection of portable executables
//! * Resource editing and icon replacement
//! * Resource transfer between files
//!
//! See [`Image`] for the main entry point for parsing, querying and updating a portable executable image.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub(crate) mod errors;
pub(crate) mod image;
pub(crate) mod resource;
pub(crate) mod util;

pub mod constants;
pub mod types;

pub use crate::{errors::*, image::*, resource::*};
