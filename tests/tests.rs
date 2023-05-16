use editpe::*;
use std::sync::Once;

static BINARY_PATH_SMALL: &str = "./tests/assets/smallbin.exe";
static BINARY_PATH_LARGE: &str = "./tests/assets/smallbin-large.exe";
static BINARY_PATH_UPX: &str = "./tests/assets/smallbin-large-upx.exe";
static BINARY_PATH_WRAPPE: &str = "./tests/assets/smallbin-wrappe.exe";
static BINARY_PATH_ICON: &str = "./tests/assets/icon.png";

static INIT_LOGGER: Once = Once::new();
fn init_logger() {
    INIT_LOGGER.call_once(|| {
        env_logger::builder()
            .is_test(false)
            .filter_level(log::LevelFilter::Info)
            .format_timestamp(None)
            .format_module_path(false)
            .format_level(true)
            .format_target(false)
            .write_style(env_logger::WriteStyle::Auto)
            .init();
    });
}

#[test]
fn parse_image() {
    init_logger();

    let data = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image = Image::parse(&data[..]);
    assert!(image.is_ok(), "image successfully parsed");
}

#[test]
fn query_resource_section() {
    init_logger();

    let data = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image = Image::parse(&data[..]).unwrap();

    let directory = image.resource_directory().unwrap();
    let section = image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .unwrap();

    println!("table size: {}", directory.root().tables_size());
    println!("strings size: {}", directory.root().strings_size());
    println!("descriptions size: {}", directory.root().descriptions_size());
    println!("data size: {}", directory.root().data_size());
    println!("root size: {}", directory.root().size());

    println!(
        "{:#x?} {:#x?} {:#x?}",
        directory.size(),
        section.size_of_raw_data,
        section.virtual_size
    );
}

#[test]
fn build_resource_section() {
    init_logger();

    let data = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image = Image::parse(&data[..]).unwrap();

    let directory = image.resource_directory().unwrap();
    let section = image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .unwrap();
    let data = directory.build(directory.virtual_address());

    assert_eq!(
        data.len(),
        directory.size() as usize,
        "built resource size equals computed size"
    );

    let aligned_data_len = data.len() as u32
        - (data.len() as u32 % image.windows_header().file_alignment())
        + image.windows_header().file_alignment();

    println!("strings size: {:?}", directory.root().strings_size());
    assert_eq!(
        aligned_data_len, section.size_of_raw_data,
        "built resource size equals original size"
    );

    let directory2 = ResourceDirectory::parse(&data, 0, directory.virtual_address()).unwrap();

    assert_eq!(
        directory.root().tables_size(),
        directory2.root().tables_size(),
        "parsed and built tables directories equal"
    );
    assert_eq!(
        directory.root().strings_size(),
        directory2.root().strings_size(),
        "parsed and built strings directories equal"
    );
    assert_eq!(
        directory.root().descriptions_size(),
        directory2.root().descriptions_size(),
        "parsed and built descriptions directories equal"
    );
    assert_eq!(
        directory.root().data_size(),
        directory2.root().data_size(),
        "parsed and built data directories equal"
    );
    assert_eq!(
        directory.root().size(),
        directory2.root().size(),
        "parsed and built root directories equal"
    );
    assert_eq!(directory, &directory2, "parsed and built directories equal");

    let original_data = &image.data()[image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .unwrap()
        .pointer_to_raw_data as usize
        ..image
            .section_header_for_data_directory(DataDirectoryType::ResourceTable)
            .unwrap()
            .pointer_to_raw_data as usize
            + image
                .section_header_for_data_directory(DataDirectoryType::ResourceTable)
                .unwrap()
                .size_of_raw_data as usize];

    println!(
        "original data len: {}, aligned data len: {}",
        original_data.len(),
        aligned_data_len
    );
    assert_eq!(original_data.len(), aligned_data_len as usize, "resource data lengths equal");
}

#[test]
fn set_resource_section() {
    init_logger();

    let data = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let mut image = Image::parse(&data[..]).unwrap();

    let old_section = image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .cloned()
        .unwrap();

    let resource_directory = image.resource_directory().cloned().unwrap();
    image.set_resource_directory(resource_directory).unwrap();


    let new_section = image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .cloned()
        .unwrap();

    assert_eq!(old_section, new_section, "resource sections equal");

    let new_data = image.data();

    assert_eq!(data.len(), new_data.len(), "original and rebuilt data size equal");

    let new_image = Image::parse(new_data).unwrap();
    assert_eq!(image, new_image, "original and rebuilt images equal");
}

#[test]
fn transfer_resource_section_small() {
    init_logger();

    let data_small = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let image_small = Image::parse(&data_small[..]).unwrap();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let mut image_large = Image::parse(&data_large[..]).unwrap();

    let mut target_resource_directory = image_large.resource_directory().cloned().unwrap();
    let source_resource_directory = image_small.resource_directory().cloned().unwrap();

    assert!(
        target_resource_directory.size() > source_resource_directory.size(),
        "target resource directory is larger than source resource directory"
    );

    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(3),
        source_resource_directory.root().get(&ResourceEntryName::ID(3)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(14),
        source_resource_directory
            .root()
            .get(&ResourceEntryName::ID(14))
            .unwrap()
            .clone(),
    );

    image_large.set_resource_directory(target_resource_directory).unwrap();

    let data_large_rebuilt = image_large.data();
    let image_large_rebuilt = Image::parse(data_large_rebuilt).unwrap();
    assert_eq!(
        image_large.resource_directory().unwrap().root(),
        image_large_rebuilt.resource_directory().unwrap().root(),
        "replaced and rebuilt resource directories are equal"
    );
    assert_eq!(
        data_large.len(),
        data_large_rebuilt.len(),
        "original and rebuilt data size equal"
    );
}

#[test]
fn transfer_resource_section_large() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();

    let data_small = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let mut image_small = Image::parse(&data_small[..]).unwrap();

    let source_resource_directory = image_large.resource_directory().cloned().unwrap();
    let mut target_resource_directory = image_small.resource_directory().cloned().unwrap();

    assert!(
        target_resource_directory.size() < source_resource_directory.size(),
        "target resource directory is smaller than source resource directory"
    );

    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(24),
        source_resource_directory
            .root()
            .get(&ResourceEntryName::ID(24))
            .unwrap()
            .clone(),
    );
    image_small.set_resource_directory(target_resource_directory.clone()).unwrap();

    let data_small_rebuilt = image_small.data();

    assert!(
        data_small_rebuilt.len() > data_small.len(),
        "data size after setting resource directory larger than original data size"
    );

    let mut image_small_rebuilt = Image::parse(data_small_rebuilt).unwrap();
    assert_eq!(
        image_small.resource_directory().unwrap().root(),
        image_small_rebuilt.resource_directory().unwrap().root(),
        "replaced and rebuilt resource directories are equal"
    );

    image_small_rebuilt.set_resource_directory(target_resource_directory).unwrap();
    let data_small_rebuilt_rebuilt = image_small_rebuilt.data();
    assert_eq!(
        data_small_rebuilt.len(),
        data_small_rebuilt_rebuilt.len(),
        "data size after setting same resource directory again equal"
    );
}

#[test]
fn transfer_resource_section_from_upx() {
    init_logger();

    let data_upx = std::fs::read(BINARY_PATH_UPX).unwrap();
    let image_upx = Image::parse(&data_upx[..]).unwrap();

    let data_small = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let mut image_small = Image::parse(&data_small[..]).unwrap();

    let source_resource_directory = image_upx.resource_directory().cloned().unwrap();
    let mut target_resource_directory = image_small.resource_directory().cloned().unwrap();

    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(3),
        source_resource_directory.root().get(&ResourceEntryName::ID(3)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(14),
        source_resource_directory
            .root()
            .get(&ResourceEntryName::ID(14))
            .unwrap()
            .clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(24),
        source_resource_directory
            .root()
            .get(&ResourceEntryName::ID(24))
            .unwrap()
            .clone(),
    );
    image_small.set_resource_directory(target_resource_directory.clone()).unwrap();

    let data_small_rebuilt = image_small.data();

    assert!(
        data_small_rebuilt.len() > data_small.len(),
        "rebuilt image is larger than original image"
    );
}

#[test]
fn transfer_resource_section_to_wrappe() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();

    let data_wrappe = std::fs::read(BINARY_PATH_WRAPPE).unwrap();
    let mut image_wrappe = Image::parse(&data_wrappe[..]).unwrap();

    let source_resource_directory = image_large.resource_directory().cloned().unwrap();
    let mut target_resource_directory = ResourceDirectory::default();

    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(3),
        source_resource_directory.root().get(&ResourceEntryName::ID(3)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(14),
        source_resource_directory
            .root()
            .get(&ResourceEntryName::ID(14))
            .unwrap()
            .clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(24),
        source_resource_directory
            .root()
            .get(&ResourceEntryName::ID(24))
            .unwrap()
            .clone(),
    );
    assert!(
        target_resource_directory.size() > 0,
        "resource directory is not empty after modification"
    );
    image_wrappe.set_resource_directory(target_resource_directory.clone()).unwrap();

    let data_wrappe_rebuilt = image_wrappe.data();

    assert!(
        data_wrappe_rebuilt.len() > data_wrappe.len(),
        "rebuilt image is larger than original image"
    );

    let image_wrappe_rebuilt = Image::parse(data_wrappe_rebuilt).unwrap();
    assert_eq!(
        image_wrappe.resource_directory().unwrap().root(),
        image_wrappe_rebuilt.resource_directory().unwrap().root(),
        "replaced and rebuilt resource directories are equal"
    );
}

#[test]
fn convert_resource_name_string() {
    assert_eq!(
        ResourceEntryName::from_string("MAINICON").to_string(),
        Some("MAINICON".to_string()),
        "resource name conversion to string is correct",
    );
}

#[test]
fn remove_icon() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let mut image_large = Image::parse(&data_large[..]).unwrap();

    let mut target_resource_directory =
        image_large.resource_directory().cloned().unwrap_or_default();

    let size_before = target_resource_directory.size();
    target_resource_directory.remove_icon().unwrap();
    let size_after = target_resource_directory.size();

    assert!(size_before > size_after, "resource directory is smaller after removing icon");

    image_large.set_resource_directory(target_resource_directory.clone()).unwrap();

    let data_large_rebuilt = image_large.data();

    assert!(
        data_large_rebuilt.len() == data_large.len(),
        "rebuilt image is equal to original image"
    );
}

#[test]
fn get_icon() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();

    let target_resource_directory = image_large.resource_directory().cloned().unwrap_or_default();

    let icon = target_resource_directory.get_icon();
    assert!(icon.is_ok(), "icon successfully parsed");
    let icon = icon.unwrap();
    assert!(icon.is_some(), "icon is present");
}

#[test]
fn set_icon() {
    init_logger();

    let data_wrappe = std::fs::read(BINARY_PATH_WRAPPE).unwrap();
    let mut image_wrappe = Image::parse(&data_wrappe[..]).unwrap();

    let mut target_resource_directory =
        image_wrappe.resource_directory().cloned().unwrap_or_default();

    let data_icon = std::fs::read(BINARY_PATH_ICON).unwrap();

    target_resource_directory.set_icon(&data_icon[..]).unwrap();

    assert!(
        target_resource_directory.size() > 0,
        "resource directory is not empty after modification"
    );
    image_wrappe.set_resource_directory(target_resource_directory.clone()).unwrap();

    let data_large_rebuilt = image_wrappe.data();
    assert!(
        data_large_rebuilt.len() > data_wrappe.len(),
        "rebuilt image is larger than original image"
    );

    let image_large_rebuilt = Image::parse(data_large_rebuilt).unwrap();
    assert_eq!(
        image_wrappe.resource_directory().unwrap().root(),
        image_large_rebuilt.resource_directory().unwrap().root(),
        "replaced and rebuilt resource directories are equal"
    );

    let icon_directory = image_large_rebuilt
        .resource_directory()
        .unwrap()
        .root()
        .get(ResourceEntryName::ID(constants::RT_GROUP_ICON as u32))
        .unwrap();
    if let ResourceEntry::Table(table) = icon_directory {
        let group_icon = table.get(ResourceEntryName::from_string("MAINICON")).unwrap();
        assert!(group_icon.data_size() > 0, "resource directory contains main icon group");
    } else {
        panic!("resource icon group directory is not a table");
    }
}

#[test]
fn parse_version_info() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();

    let target_resource_directory = image_large.resource_directory().cloned().unwrap_or_default();

    let version_info = target_resource_directory.get_version_info();
    assert!(version_info.is_ok(), "version info successfully parsed");
    let version_info = version_info.unwrap();
    assert!(version_info.is_some(), "version info is present");
}


#[test]
fn build_version_info() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();

    let target_resource_directory = image_large.resource_directory().cloned().unwrap_or_default();

    let data = target_resource_directory
        .root()
        .get(&ResourceEntryName::ID(16))
        .unwrap()
        .as_table()
        .unwrap()
        .get(&ResourceEntryName::ID(1))
        .unwrap();

    let version_info = target_resource_directory.get_version_info().unwrap().unwrap();
    let data_rebuilt = version_info.build();

    assert_eq!(
        data.data_size() as usize,
        data_rebuilt.len(),
        "built version info size equals computed size"
    );
}

#[test]
fn set_version_info() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();

    let data_wrappe = std::fs::read(BINARY_PATH_WRAPPE).unwrap();
    let mut image_wrappe = Image::parse(&data_wrappe[..]).unwrap();

    let source_resource_directory = image_large.resource_directory().cloned().unwrap();
    let mut target_resource_directory =
        image_wrappe.resource_directory().cloned().unwrap_or_default();

    let version_info = source_resource_directory.get_version_info().unwrap().unwrap();
    target_resource_directory.set_version_info(&version_info).unwrap();

    assert!(
        target_resource_directory.size()
            > image_wrappe.resource_directory().cloned().unwrap_or_default().size(),
        "resource directory is larger after modification"
    );

    image_wrappe.set_resource_directory(target_resource_directory.clone()).unwrap();
    let version_info_rebuilt =
        image_wrappe.resource_directory().unwrap().get_version_info().unwrap().unwrap();

    assert_eq!(
        version_info, version_info_rebuilt,
        "rebuilt version info is equal to original version info"
    );
}

#[test]
fn get_manifest() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();

    let target_resource_directory = image_large.resource_directory().cloned().unwrap_or_default();

    let manifest = target_resource_directory.get_manifest();
    assert!(manifest.is_ok(), "manifest successfully parsed");
    let manifest = manifest.unwrap();
    assert!(manifest.is_some(), "manifest is present");
}

#[test]
fn set_manifest() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let mut image_large = Image::parse(&data_large[..]).unwrap();

    let mut target_resource_directory =
        image_large.resource_directory().cloned().unwrap_or_default();

    let manifest = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
    target_resource_directory.set_manifest(manifest).unwrap();
    image_large.set_resource_directory(target_resource_directory.clone()).unwrap();

    let manifest_rebuilt =
        image_large.resource_directory().unwrap().get_manifest().unwrap().unwrap();

    assert_eq!(manifest, manifest_rebuilt, "rebuilt manifest is equal to original manifest");
}
