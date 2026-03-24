# editpe

[![Crates.io](https://img.shields.io/crates/v/editpe)](https://crates.io/crates/editpe)
[![Docs.rs](https://img.shields.io/docsrs/editpe)](https://docs.rs/editpe)
[![Tests & Checks](https://img.shields.io/github/actions/workflow/status/Systemcluster/editpe/tests.yml?label=tests%20%26%20checks)](https://github.com/Systemcluster/editpe/actions/workflows/tests.yml)

Resource **edit**or for **p**ortable **e**xecutables.

Enables cross-platform parsing and modification of Windows executables and their resources.

## Features

* Parsing and modification of portable executables
* Resource editing including icons, manifests, subsystem, version info and more!
* Resource transfer between files

Compared to other resource editors like [rcedit](https://github.com/electron/rcedit), editpe takes great care to keep the modified executable in a valid state. It does this by parsing and rebuilding the complete resource directory as well as all file and section headers, keeping existing sections intact, and leaving any additional data at the end of the file in place.

## Usage

### Library

Add `editpe` as a dependency. The `std` and `images` features are enabled by default and can be disabled for `no-std` support.

```toml
editpe = "0.2"
image = { version = "*", features = ["png"] } # to support additional icon file types
```


#### Examples

##### Adding an icon or manifest to an executable

```rust
let mut image = Image::parse_file("damocles.exe")?;
let mut resources = image.resource_directory().cloned().unwrap_or_default();

resources.set_main_icon_file("sword.png")?;

let manifest = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
resources.set_manifest(manifest)?;

image.set_resource_directory(resources)?;
image.write_file("damocles.exe");
```

##### Transferring resources between executables

```rust
let source = Image::parse_file("damocles.exe")?;
let resources = image.resource_directory().unwrap();

let mut target = Image::parse_file("fortuna.exe")?;
target.set_resource_directory(resources.clone())?;
target.write_file("fortuna.exe");
```

See the [tests](./tests/tests.rs) for other usage examples.

<sub>Note that packed executables (like packed with [UPX](https://github.com/upx/upx)) might not allow resource replacement. Edit the resources before packing if required.</sub>
