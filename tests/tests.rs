use editpe::{constants::*, types::*, *};
use std::{mem::size_of, sync::Once};

static BINARY_PATH_SMALL: &str = "./tests/assets/smallbin.exe";
static BINARY_PATH_SMALL_32: &str = "./tests/assets/smallbin-32.exe";
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

fn pe32_base_of_data(data: &[u8]) -> u32 {
    let pe_signature_offset = u32::from_le_bytes(
        data[PE_PTR_OFFSET as usize..PE_PTR_OFFSET as usize + size_of::<u32>()]
            .try_into()
            .unwrap(),
    ) as usize;
    // PE signature + COFF header + StandardHeader (through BaseOfCode) = BaseOfData
    let offset = pe_signature_offset
        + size_of::<u32>()
        + size_of::<CoffHeader>()
        + size_of::<StandardHeader>();
    u32::from_le_bytes(data[offset..offset + size_of::<u32>()].try_into().unwrap())
}

fn expected_size_of_image(image: &Image<'_>) -> u32 {
    let alignment = u64::from(image.windows_header().section_alignment());
    assert!(alignment > 0, "section alignment must be non-zero");
    let max_end = image
        .section_table()
        .iter()
        .map(|section| u64::from(section.virtual_address) + u64::from(section.virtual_size))
        .max()
        .unwrap_or(0);
    let aligned = if max_end % alignment == 0 {
        max_end
    } else {
        max_end + alignment - (max_end % alignment)
    };
    u32::try_from(aligned).expect("expected SizeOfImage fits in u32")
}

#[test]
fn set_pe32_resource_section() {
    init_logger();

    let data = std::fs::read(BINARY_PATH_SMALL_32).unwrap();
    let mut image = Image::parse(&data[..]).unwrap();
    assert_eq!(image.standard_header().magic, PE_32_MAGIC, "fixture is PE32");

    let original_base_of_data = pe32_base_of_data(&data);
    let resource_directory = image.resource_directory().cloned().unwrap();
    image.set_resource_directory(resource_directory).unwrap();

    let new_data = image.data();
    assert_eq!(data.len(), new_data.len(), "original and rebuilt PE32 data size equal");
    assert_eq!(
        pe32_base_of_data(new_data),
        original_base_of_data,
        "PE32 BaseOfData DWORD is preserved across rewrite"
    );

    let new_image = Image::parse(new_data).unwrap();
    assert_eq!(image, new_image, "original and rebuilt PE32 images equal");
}

#[test]
fn set_resource_section_rejects_invalid_section_layout() {
    init_logger();

    for binary_path in [BINARY_PATH_SMALL, BINARY_PATH_SMALL_32] {
        let data = std::fs::read(binary_path).unwrap();
        let image = Image::parse(&data[..]).unwrap();
        let section_alignment = image.windows_header().section_alignment();
        assert_eq!(
            section_alignment, 0x1000,
            "overflow fixture depends on 0x1000 section alignment ({binary_path})"
        );

        let pe_signature_offset = u32::from_le_bytes(
            data[PE_PTR_OFFSET as usize..PE_PTR_OFFSET as usize + size_of::<u32>()]
                .try_into()
                .unwrap(),
        ) as usize;
        let last_section_offset = pe_signature_offset
            + size_of::<u32>()
            + size_of::<CoffHeader>()
            + image.coff_header().size_of_optional_header as usize
            + (image.coff_header().number_of_sections as usize - 1) * size_of::<SectionHeader>();
        // SectionHeader: Name(8) VirtualSize(4) VirtualAddress(4) ...
        let virtual_size_offset = last_section_offset + size_of::<u64>();
        let virtual_address_offset = virtual_size_offset + size_of::<u32>();
        let last_section_va = u32::from_le_bytes(
            data[virtual_address_offset..virtual_address_offset + size_of::<u32>()]
                .try_into()
                .unwrap(),
        );

        let mut cases = vec![(last_section_va, 0xffff_f800_u64, false, "aligned image size")];
        if binary_path == BINARY_PATH_SMALL {
            cases.push((0xffff_f000, 0x1_0000_1000_u64, true, "virtual section extent"));
        }

        for (virtual_address, virtual_end, virtual_extent_overflows, description) in cases {
            let virtual_size = u32::try_from(virtual_end - u64::from(virtual_address))
                .expect("virtual size fits in u32");
            let computed_virtual_end = u64::from(virtual_address) + u64::from(virtual_size);
            let alignment = u64::from(section_alignment);
            let aligned_image_size =
                computed_virtual_end + (alignment - computed_virtual_end % alignment) % alignment;

            assert!(
                aligned_image_size > u64::from(u32::MAX),
                "fixture makes aligned SizeOfImage exceed the PE address space ({binary_path})"
            );
            assert_eq!(
                virtual_end > u64::from(u32::MAX),
                virtual_extent_overflows,
                "fixture marks whether the virtual section extent itself exceeds the PE address space ({binary_path})"
            );

            let mut data = data.clone();
            data[virtual_size_offset..virtual_size_offset + size_of::<u32>()]
                .copy_from_slice(&virtual_size.to_le_bytes());
            data[virtual_address_offset..virtual_address_offset + size_of::<u32>()]
                .copy_from_slice(&virtual_address.to_le_bytes());

            let mut image = Image::parse(&data[..]).unwrap();
            assert!(
                image.resource_directory().is_some(),
                "resource directory can be parsed with an invalid virtual size ({binary_path})"
            );
            let resource_directory = image.resource_directory().cloned().unwrap();
            let result = image.set_resource_directory(resource_directory);
            assert!(
                matches!(result, Err(ImageWriteError::InvalidSectionRange(_, _))),
                "set_resource_directory errors when {description} overflows ({binary_path}): {result:?}"
            );
        }
    }
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
        source_resource_directory.root().get(ResourceEntryName::ID(3)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(14),
        source_resource_directory.root().get(ResourceEntryName::ID(14)).unwrap().clone(),
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
        source_resource_directory.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
    );
    let previous_size_of_image = image_small.windows_header().size_of_image();
    image_small.set_resource_directory(target_resource_directory.clone()).unwrap();

    let section_alignment = image_small.windows_header().section_alignment();
    let size_of_image = image_small.windows_header().size_of_image();
    assert_eq!(
        size_of_image % section_alignment,
        0,
        "image size is aligned to section boundaries"
    );
    assert_eq!(
        size_of_image,
        expected_size_of_image(&image_small),
        "SizeOfImage equals align(max(VA + VS), SectionAlignment)"
    );
    assert!(
        size_of_image >= previous_size_of_image,
        "SizeOfImage does not shrink when growing resource section"
    );

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
fn set_resource_directory_repeated_without_reparse() {
    init_logger();

    // smallbin has .rsrc followed by .reloc, so growing resources adds a new section
    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();
    let data_small = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let mut image_small = Image::parse(&data_small[..]).unwrap();
    let original_section_count = image_small.coff_header().number_of_sections;

    let source = image_large.resource_directory().cloned().unwrap();
    let mut target = image_small.resource_directory().cloned().unwrap();
    target.root_mut().insert(
        ResourceEntryName::ID(24),
        source.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
    );

    image_small.set_resource_directory(target.clone()).unwrap();
    let after_first = image_small.data().to_vec();
    assert_eq!(
        image_small.coff_header().number_of_sections,
        original_section_count + 1,
        "first write appends a resource section"
    );
    assert!(
        after_first.len() > data_small.len(),
        "first write grows the image (new section path)"
    );

    // second setting of resource should keep the same size
    image_small.set_resource_directory(target.clone()).unwrap();
    let after_second = image_small.data().to_vec();
    assert_eq!(
        after_first.len(),
        after_second.len(),
        "second same-size write does not change file length"
    );
    assert_eq!(after_first, after_second, "second same-resource-directory write equals in data");

    let reparsed = Image::parse(&after_second[..]).unwrap();
    assert_eq!(
        image_small.resource_directory().unwrap().root(),
        reparsed.resource_directory().unwrap().root(),
        "resources survive double write without intermediate parse"
    );
    assert_eq!(
        image_small.section_table(),
        reparsed.section_table(),
        "section table survives double write without intermediate parse"
    );
    assert_eq!(
        reparsed.windows_header().size_of_image(),
        expected_size_of_image(&reparsed),
        "SizeOfImage remains consistent after double write"
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
        source_resource_directory.root().get(ResourceEntryName::ID(3)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(14),
        source_resource_directory.root().get(ResourceEntryName::ID(14)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(24),
        source_resource_directory.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
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
        source_resource_directory.root().get(ResourceEntryName::ID(3)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(14),
        source_resource_directory.root().get(ResourceEntryName::ID(14)).unwrap().clone(),
    );
    target_resource_directory.root_mut().insert(
        ResourceEntryName::ID(24),
        source_resource_directory.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
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
    target_resource_directory.remove_main_icon().unwrap();
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

    let icon = target_resource_directory.get_main_icon();
    assert!(icon.is_ok(), "icon successfully parsed");
    let icon = icon.unwrap();
    assert!(icon.is_some(), "icon is present");

    let icon = image::load_from_memory(icon.unwrap());
    assert!(icon.is_ok(), "icon is valid");
}

#[test]
fn set_icon() {
    init_logger();

    let data_wrappe = std::fs::read(BINARY_PATH_WRAPPE).unwrap();
    let mut image_wrappe = Image::parse(&data_wrappe[..]).unwrap();

    let mut target_resource_directory =
        image_wrappe.resource_directory().cloned().unwrap_or_default();

    let data_icon = std::fs::read(BINARY_PATH_ICON).unwrap();

    let icon = image::load_from_memory(&data_icon[..]).unwrap();
    target_resource_directory.set_main_icon(icon).unwrap();
    assert!(
        target_resource_directory.size() > 0,
        "resource directory is not empty after modification"
    );
    image_wrappe.set_resource_directory(target_resource_directory.clone()).unwrap();

    target_resource_directory.set_main_icon_file(BINARY_PATH_ICON).unwrap();
    assert!(
        target_resource_directory.size() > 0,
        "resource directory is not empty after modification"
    );

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

    let icon = image::load_from_memory(
        image_large_rebuilt
            .resource_directory()
            .unwrap()
            .get_main_icon()
            .unwrap()
            .unwrap(),
    );
    assert!(icon.is_ok(), "icon is valid after setting icon");
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
        .get(ResourceEntryName::ID(16))
        .unwrap()
        .as_table()
        .unwrap()
        .get(ResourceEntryName::ID(1))
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

#[test]
fn set_subsystem() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let mut image_large = Image::parse(&data_large[..]).unwrap();

    image_large.set_subsystem(IMAGE_SUBSYSTEM_NATIVE_WINDOWS);

    let data_large_rebuilt = image_large.data();
    let image_large_rebuilt = Image::parse(data_large_rebuilt).unwrap();

    assert_eq!(
        IMAGE_SUBSYSTEM_NATIVE_WINDOWS,
        image_large_rebuilt.windows_header().subsystem(),
        "original and rebuilt subsystem equal"
    );
    assert_eq!(
        image_large.data(),
        image_large_rebuilt.data(),
        "original and rebuilt data equal"
    );
}
