//! Resource **edit**or for **p**ortable **e**xecutables.
//!
//! Supports:
//! * Parsing and modification of portable executables
//! * Resource editing including icons, manifests, subsystem, version info and more!
//! * Resource transfer between files
//!
//! See [`Image`] for the main entry point and [`ResourceDirectory`] for working with resource directories.
//!
//! # Examples
//!
//! ### Adding an icon or manifest to an executable
//! ```
//! # use editpe::Image;
//! let mut image = Image::parse_file("damocles.exe")?;
//! let mut resources = image.resource_directory().cloned().unwrap_or_default();
//!
//! resources.set_main_icon_file("sword.png")?;
//!
//! let manifest = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
//! resources.set_manifest(manifest)?;
//!
//! image.set_resource_directory(resources)?;
//! image.write_file("damocles.exe");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Transferring resources between executables
//! ```
//! # use editpe::Image;
//! let source = Image::parse_file("damocles.exe")?;
//! let resources = source.resource_directory().unwrap();
//!
//! let mut target = Image::parse_file("fortuna.exe")?;
//! target.set_resource_directory(resources.clone())?;
//! target.write_file("fortuna.exe");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Cargo features
//!
//! ### Default features
//!
//! - `std`: Enables standard library features, including reading and writing files.
//! - `images`: Enables support for converting and resizing images in other formats when setting icons. Also enables `std`.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]

extern crate alloc;

pub(crate) mod errors;
pub(crate) mod image;
pub(crate) mod resource;
pub(crate) mod util;

pub mod constants;
pub mod types;

pub use crate::{errors::*, image::*, resource::*};
