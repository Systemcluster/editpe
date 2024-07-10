//! Resource **edit**or for **p**ortable **e**xecutables.
//!
//! Supports:
//! * Parsing and introspection of portable executables
//! * Resource editing and icon replacement
//! * Resource transfer between files
//!
//! See [`Image`] for the main entry point for parsing, querying and updating a portable executable image.
//!
//! # Examples
//!
//! ### Icon replacement
//! ```
//! use editpe::Image;
//!
//! let data = std::fs::read(BINARY_PATH)?;
//! let icon = std::fs::read(ICON_PATH)?;
//!
//! // parse the executable image
//! let mut image = Image::parse(&data)?;
//!
//! // get the resource directory
//! let mut resources = image.resource_directory().cloned().unwrap_or_default();
//!
//! // set the icon in the resource directory
//! resources.set_icon(&icon)?;
//!
//! // set the resource directory in the image
//! image.set_resource_directory(resources)?;
//!
//! // build an executable image with all changes applied
//! let target = image.data();
//! ```
//!
//! ### Resource transfer
//! ```
//! use editpe::Image;
//!
//! let source = std::fs::read(SOURCE_PATH)?;
//! let target = std::fs::read(TARGET_PATH)?;
//!
//! // parse the source executable image
//! let image = Image::parse(&source)?;
//!
//! // get the source resource directory
//! let resources = image.resource_directory()?;
//!
//! // parse the target executable image
//! let mut image = Image::parse(&target)?;
//!
//! // set the resource directory in the target image
//! image.set_resource_directory(resources)?;
//!
//! // build an executable image with all changes applied
//! let target = image.data();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg_hide))]
#![cfg_attr(docsrs, doc(cfg_hide(doc)))]

extern crate alloc;

pub(crate) mod errors;
pub(crate) mod image;
pub(crate) mod resource;
pub(crate) mod util;

pub mod constants;
pub mod types;

pub use crate::{errors::*, image::*, resource::*};
