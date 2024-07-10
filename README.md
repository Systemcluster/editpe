# editpe

[![Crates.io](https://img.shields.io/crates/v/editpe)](https://crates.io/crates/editpe)
[![Docs.rs](https://img.shields.io/docsrs/editpe)](https://docs.rs/editpe)
[![Tests & Checks](https://img.shields.io/github/actions/workflow/status/Systemcluster/editpe/tests.yml?label=tests%20%26%20checks)](https://github.com/Systemcluster/editpe/actions/workflows/tests.yml)

Resource **edit**or for **p**ortable **e**xecutables.

Enables cross-platform parsing and modification of Windows executables and their resources.

## Features

* Parsing and modification of portable executables
* Resource editing including icons, manifests, version info and more
* Resource transfer between files

Compared to other resource editors like [rcedit](https://github.com/electron/rcedit), editpe takes great care to keep the modified executable in a valid state. It does this by parsing and rebuilding the complete resource directory as well as all file and section headers, keeping existing sections intact, and leaving any additional data at the end of the file in place.

<sub>Note that packed executables (like packed with [UPX](https://github.com/upx/upx)) might not start with a modified resource table and might have compressed resources that can not be read. If you need a packed executable with modified resources, edit the resources first, and pack it afterwards.</sub>

## Usage

### Library

See the [tests](./tests/tests.rs) for additional usage examples.

#### Example: Adding an icon to an executable

```rust
use editpe::Image;

let data = std::fs::read(BINARY_PATH)?;
let icon = std::fs::read(ICON_PATH)?;

// parse the executable image
let mut image = Image::parse(&data)?;

// get the resource directory
let mut resources = image.resource_directory().cloned().unwrap_or_default();

// set the icon in the resource directory
resources.set_icon(&icon)?;

// set the resource directory in the image
image.set_resource_directory(resources)?;

// build an executable image with all changes applied
let target = image.data();
```

#### Example: Resource transfer

```rust
use editpe::Image;

let source = std::fs::read(SOURCE_PATH)?;
let target = std::fs::read(TARGET_PATH)?;

// parse the source executable image
let image = Image::parse(&source)?;

// get the source resource directory
let resources = image.resource_directory()?;

// parse the target executable image
let mut image = Image::parse(&target)?;

// set the resource directory in the target image
image.set_resource_directory(resources)?;

// build an executable image with all changes applied
let target = image.data();
```
