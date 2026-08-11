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
fn parse_truncated_image_returns_error() {
    let result = std::panic::catch_unwind(|| Image::parse(&b"MZ"[..]));
    assert!(result.is_ok(), "truncated images must not panic");
    assert!(result.unwrap().is_err(), "truncated images must return an error");

    let mut data = vec![0; PE_PTR_OFFSET as usize + size_of::<u32>()];
    data[..2].copy_from_slice(&PE_DOS_MAGIC.to_le_bytes());
    data[PE_PTR_OFFSET as usize..].copy_from_slice(&u32::MAX.to_le_bytes());
    let result = std::panic::catch_unwind(|| Image::parse(&data));
    assert!(result.is_ok(), "out-of-range PE offsets must not panic");
    assert!(result.unwrap().is_err(), "out-of-range PE offsets must return an error");
}

#[test]
fn zero_alignment_allows_parsing_and_resource_writes() {
    let data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let standard_header_offset =
        pe_signature_offset(&data) + size_of::<u32>() + size_of::<CoffHeader>();
    let windows_header_offset = standard_header_offset + 24;
    let section_alignment_offset = windows_header_offset + size_of::<u64>();
    let file_alignment_offset = section_alignment_offset + size_of::<u32>();

    for (name, offset) in [
        ("section alignment", section_alignment_offset),
        ("file alignment", file_alignment_offset),
    ] {
        let mut data = data.clone();
        data[offset..offset + size_of::<u32>()].fill(0);

        let mut image = Image::parse(data)
            .unwrap_or_else(|error| panic!("{name} does not restrict data ingestion: {error}"));
        let resources = image.resource_directory().cloned().expect("resources are still parsed");
        image.set_resource_directory(resources).unwrap_or_else(|error| {
            panic!("zero {name} does not prevent resource writes: {error}")
        });
    }
}

#[test]
fn parse_invalid_optional_header_ranges_return_specific_errors() {
    let data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let standard_header_offset =
        pe_signature_offset(&data) + size_of::<u32>() + size_of::<CoffHeader>();

    let mut truncated = data.clone();
    truncated.truncate(standard_header_offset + 112);
    assert!(matches!(
        Image::parse(truncated),
        Err(ImageReadError::InvalidHeader(error)) if error == "optional header exceeds image"
    ));

    let mut undersized = data;
    let optional_header_size_offset = pe_signature_offset(&undersized) + size_of::<u32>() + 16;
    undersized[optional_header_size_offset..optional_header_size_offset + size_of::<u16>()]
        .copy_from_slice(&112u16.to_le_bytes());
    assert!(matches!(
        Image::parse(undersized),
        Err(ImageReadError::InvalidHeader(error))
            if error == "data directories exceed the optional header"
    ));
}

#[test]
fn parse_invalid_resource_entry_is_skipped() {
    let mut data = vec![0; size_of::<ResourceDirectoryTable>()];
    data[14..16].copy_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0x100u32.to_le_bytes());

    let result = std::panic::catch_unwind(|| ResourceDirectory::parse(&data, 0, 0));
    assert!(result.is_ok(), "invalid resource offsets must not panic");
    let directory = result.unwrap().expect("invalid child entries do not reject the directory");
    assert!(directory.root().entries().is_empty(), "invalid child entry is skipped");
    let rebuilt = directory.build(0);
    assert!(
        ResourceDirectory::parse(&rebuilt, 0, 0).is_ok(),
        "tolerantly parsed directories rebuild consistently"
    );
}

#[test]
fn parse_cyclic_resource_directory_is_skipped() {
    let mut data = vec![0; size_of::<ResourceDirectoryTable>()];
    data[14..16].copy_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0x80000000u32.to_le_bytes());

    let directory = ResourceDirectory::parse(&data, 0, 0).unwrap();
    assert!(directory.root().entries().is_empty(), "cyclic child directories are skipped");
}

#[test]
fn set_resource_directory_aligns_appended_section_data() {
    let source_data = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let source_resources =
        Image::parse(source_data).unwrap().resource_directory().cloned().unwrap();
    let mut data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let image = Image::parse(&data[..]).unwrap();
    let last_section_index = image
        .section_table()
        .iter()
        .enumerate()
        .max_by_key(|(_, section)| {
            u64::from(section.pointer_to_raw_data) + u64::from(section.size_of_raw_data)
        })
        .map(|(index, _)| index)
        .unwrap();
    let raw_size_offset = section_header_offset(&image, last_section_index) + 16;
    let raw_size = u32::from_le_bytes(
        data[raw_size_offset..raw_size_offset + size_of::<u32>()].try_into().unwrap(),
    );
    data[raw_size_offset..raw_size_offset + size_of::<u32>()]
        .copy_from_slice(&(raw_size - 1).to_le_bytes());

    let mut image = Image::parse(data).unwrap();
    image.set_resource_directory(source_resources).unwrap();

    let resource_section = image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .unwrap();
    assert_eq!(
        resource_section.pointer_to_raw_data % image.windows_header().file_alignment(),
        0,
        "appended section data is file-aligned"
    );
    assert!(Image::parse(image.data()).is_ok(), "aligned output reparses");
}

#[test]
fn parse_truncated_version_info_returns_error() {
    let data = [6, 0, size_of::<FixedFileInfo>() as u8, 0, 0, 0];
    let result = std::panic::catch_unwind(|| VersionInfo::parse(&data));
    assert!(result.is_ok(), "truncated version information must not panic");
    assert!(result.unwrap().is_err(), "truncated version information must return an error");
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

fn pe_signature_offset(data: &[u8]) -> usize {
    u32::from_le_bytes(
        data[PE_PTR_OFFSET as usize..PE_PTR_OFFSET as usize + size_of::<u32>()]
            .try_into()
            .unwrap(),
    ) as usize
}

fn pe32_base_of_data(data: &[u8]) -> u32 {
    let pe_signature_offset = pe_signature_offset(data);
    // PE signature + COFF header + StandardHeader (through BaseOfCode) = BaseOfData
    let offset = pe_signature_offset
        + size_of::<u32>()
        + size_of::<CoffHeader>()
        + size_of::<StandardHeader>();
    u32::from_le_bytes(data[offset..offset + size_of::<u32>()].try_into().unwrap())
}

fn section_header_offset(image: &Image<'_>, index: usize) -> usize {
    pe_signature_offset(image.data())
        + size_of::<u32>()
        + size_of::<CoffHeader>()
        + image.coff_header().size_of_optional_header as usize
        + index * size_of::<SectionHeader>()
}

fn data_directory_offset(image: &Image<'_>, index: usize) -> usize {
    let standard_header_offset =
        pe_signature_offset(image.data()) + size_of::<u32>() + size_of::<CoffHeader>();
    let optional_header_size = if image.standard_header().magic == PE_32_MAGIC {
        96
    } else {
        112
    };
    standard_header_offset + optional_header_size + index * size_of::<ImageDataDirectory>()
}

fn last_section_end(image: &Image<'_>) -> usize {
    image
        .section_table()
        .iter()
        .map(|section| section.pointer_to_raw_data as usize + section.size_of_raw_data as usize)
        .max()
        .unwrap_or(image.data().len())
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
fn set_resource_directory_reuses_optional_header_capacity() {
    let data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let source_resources = Image::parse(&data[..]).unwrap().resource_directory().cloned().unwrap();
    let mut data = data;
    let number_of_rva_and_sizes_offset =
        data_directory_offset(&Image::parse(&data[..]).unwrap(), 0) - size_of::<u32>();
    data[number_of_rva_and_sizes_offset..number_of_rva_and_sizes_offset + size_of::<u32>()]
        .copy_from_slice(&2u32.to_le_bytes());

    let mut image = Image::parse(data).unwrap();
    let optional_header_size = image.coff_header().size_of_optional_header;
    assert!(image.resource_directory().is_none(), "resource directory is not declared");

    image.set_resource_directory(source_resources).unwrap();

    assert_eq!(
        image.coff_header().size_of_optional_header,
        optional_header_size,
        "existing optional-header directory capacity is reused"
    );
    let reparsed = Image::parse(image.data()).unwrap();
    assert_eq!(image.section_table(), reparsed.section_table(), "section table remains aligned");
    assert_eq!(
        image.resource_directory(),
        reparsed.resource_directory(),
        "resource directory survives reparsing"
    );
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
            let image_before = image.cloned();
            let data_before = image.data().to_vec();
            let result = image.set_resource_directory(resource_directory);
            assert!(
                matches!(result, Err(ImageWriteError::InvalidSectionRange(_, _))),
                "set_resource_directory errors when {description} overflows ({binary_path}): {result:?}"
            );
            assert_eq!(image, image_before, "failed write preserves image state ({binary_path})");
            assert_eq!(
                image.data(),
                data_before,
                "failed write preserves image data ({binary_path})"
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
    let target_size = target_resource_directory.size();

    image_large.set_resource_directory(target_resource_directory).unwrap();

    assert_eq!(
        image_large.data_directory(DataDirectoryType::ResourceTable).unwrap().size,
        target_size,
        "resource data directory size matches the replacement"
    );
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
    let original = image_small.resource_directory().cloned().unwrap();
    let mut larger = original.clone();
    larger.root_mut().insert(
        ResourceEntryName::ID(24),
        source.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
    );
    assert!(larger.size() > original.size(), "modified resource directory is larger");

    let previous = image_small.set_resource_directory(larger.clone()).unwrap();
    assert_eq!(previous, Some(original.clone()), "first write returns original resources");
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
    let appended_resource_rva = image_small
        .data_directory(DataDirectoryType::ResourceTable)
        .unwrap()
        .virtual_address;

    let previous = image_small.set_resource_directory(original.clone()).unwrap().unwrap();
    assert_eq!(previous.root(), larger.root(), "shrinking returns larger resources");
    assert_eq!(
        previous.virtual_address(),
        appended_resource_rva,
        "returned resources carry their target-image RVA"
    );
    let after_second = image_small.data().to_vec();
    assert_eq!(
        image_small.coff_header().number_of_sections,
        original_section_count + 1,
        "shrinking reuses the appended resource section"
    );
    assert!(after_second.len() < after_first.len(), "second write shrinks the last section");

    let previous = image_small.set_resource_directory(larger.clone()).unwrap().unwrap();
    assert_eq!(previous.root(), original.root(), "growing returns smaller resources");
    assert_eq!(
        previous.virtual_address(),
        appended_resource_rva,
        "reused resources retain their target-image RVA"
    );
    let after_third = image_small.data().to_vec();
    assert_eq!(
        image_small.coff_header().number_of_sections,
        original_section_count + 1,
        "growing again reuses the appended resource section"
    );
    assert_eq!(after_first, after_third, "grow-shrink-grow writes deterministic data");

    let reparsed = Image::parse(&after_third[..]).unwrap();
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
fn set_pe32_resource_directory_repeated_without_reparse() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();
    let data = std::fs::read(BINARY_PATH_SMALL_32).unwrap();
    let mut image = Image::parse(&data[..]).unwrap();
    assert_eq!(image.standard_header().magic, PE_32_MAGIC, "fixture is PE32");

    let original_base_of_data = pe32_base_of_data(&data);
    let original_section_count = image.coff_header().number_of_sections;
    let source = image_large.resource_directory().cloned().unwrap();
    let mut resources = image.resource_directory().cloned().unwrap();
    resources.root_mut().insert(
        ResourceEntryName::ID(24),
        source.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
    );

    image.set_resource_directory(resources.clone()).unwrap();
    let after_first = image.data().to_vec();
    assert_eq!(
        image.coff_header().number_of_sections,
        original_section_count,
        "first PE32 write expands the last resource section in place"
    );
    assert!(after_first.len() > data.len(), "first PE32 write grows the resource section");
    image.set_resource_directory(resources).unwrap();
    assert_eq!(image.data(), after_first, "second PE32 write produces identical data");
    assert_eq!(
        pe32_base_of_data(image.data()),
        original_base_of_data,
        "PE32 BaseOfData is preserved across repeated writes"
    );

    let reparsed = Image::parse(image.data()).unwrap();
    assert_eq!(image, reparsed, "repeatedly rebuilt PE32 image reparses equally");
}

#[test]
fn set_resource_directory_preserves_overlay() {
    init_logger();

    const OVERLAY_SENTINEL: &[u8] = b"editpe overlay sentinel";

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();
    let mut data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    data.extend_from_slice(OVERLAY_SENTINEL);
    let mut image = Image::parse(data).unwrap();
    let original_last_section_end = last_section_end(&image);
    let original_overlay = image.data()[original_last_section_end..].to_vec();

    let source = image_large.resource_directory().cloned().unwrap();
    let mut resources = image.resource_directory().cloned().unwrap();
    resources.root_mut().insert(
        ResourceEntryName::ID(24),
        source.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
    );
    image.set_resource_directory(resources).unwrap();

    let resource_section = image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .unwrap();
    assert_eq!(
        resource_section.name().as_deref(),
        Some(".pedata"),
        "new resource section added"
    );
    assert_eq!(
        &image.data()[last_section_end(&image)..],
        original_overlay,
        "all data after the original sections is preserved after the new section"
    );
    assert!(
        image.data().ends_with(OVERLAY_SENTINEL),
        "overlay sentinel remains at end of image"
    );
}

#[test]
fn set_resource_directory_rejects_overflowing_new_section_address() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();
    let mut data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let image = Image::parse(&data[..]).unwrap();
    let last_section_index = image.coff_header().number_of_sections as usize - 1;
    let last_section_offset = section_header_offset(&image, last_section_index);
    let virtual_size_offset = last_section_offset + size_of::<u64>();
    let virtual_address_offset = virtual_size_offset + size_of::<u32>();
    data[virtual_size_offset..virtual_size_offset + size_of::<u32>()]
        .copy_from_slice(&0x800_u32.to_le_bytes());
    data[virtual_address_offset..virtual_address_offset + size_of::<u32>()]
        .copy_from_slice(&0xffff_f000_u32.to_le_bytes());

    let mut image = Image::parse(data).unwrap();
    let source = image_large.resource_directory().cloned().unwrap();
    let mut resources = image.resource_directory().cloned().unwrap();
    resources.root_mut().insert(
        ResourceEntryName::ID(24),
        source.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
    );
    let image_before = image.cloned();
    let data_before = image.data().to_vec();
    let result = image.set_resource_directory(resources);

    assert!(
        matches!(result, Err(ImageWriteError::InvalidSectionRange(0x1_0000_0000, _))),
        "new section address overflow is rejected: {result:?}"
    );
    assert_eq!(image, image_before, "failed append preserves image state");
    assert_eq!(image.data(), data_before, "failed append preserves image data");
}

#[test]
fn set_resource_directory_succeeds_after_failed_append() {
    init_logger();

    let data_large = std::fs::read(BINARY_PATH_LARGE).unwrap();
    let image_large = Image::parse(&data_large[..]).unwrap();
    let mut data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let image = Image::parse(&data[..]).unwrap();
    let first_section_offset = section_header_offset(&image, 0);
    let pointer_to_raw_data_offset = first_section_offset
        + size_of::<u64>()
        + size_of::<u32>()
        + size_of::<u32>()
        + size_of::<u32>();
    let section_table_end =
        section_header_offset(&image, image.coff_header().number_of_sections as usize);
    let constrained_section_start = section_table_end + 20;
    data[pointer_to_raw_data_offset..pointer_to_raw_data_offset + size_of::<u32>()]
        .copy_from_slice(&(constrained_section_start as u32).to_le_bytes());

    let mut image = Image::parse(data).unwrap();
    let original_section_count = image.coff_header().number_of_sections;
    let original_resources = image.resource_directory().cloned().unwrap();
    let source = image_large.resource_directory().cloned().unwrap();
    let mut larger_resources = original_resources.clone();
    larger_resources.root_mut().insert(
        ResourceEntryName::ID(24),
        source.root().get(ResourceEntryName::ID(24)).unwrap().clone(),
    );

    let result = image.set_resource_directory(larger_resources);
    assert!(
        matches!(result, Err(ImageWriteError::NotEnoughSpaceInHeader)),
        "append fails when the header has only 20 free bytes: {result:?}"
    );

    let previous = image.set_resource_directory(original_resources.clone()).unwrap();
    assert_eq!(
        previous,
        Some(original_resources),
        "successful retry returns original resources"
    );
    assert_eq!(
        image.coff_header().number_of_sections,
        original_section_count,
        "successful retry updates the resource section in place"
    );
    let reparsed = Image::parse(image.data()).unwrap();
    assert_eq!(image, reparsed, "image reparses after retrying a failed write");
}

#[test]
fn set_resource_directory_preserves_shared_section() {
    init_logger();

    let data = std::fs::read(BINARY_PATH_SMALL).unwrap();
    let image = Image::parse(&data[..]).unwrap();
    let resource_data_directory = *image.data_directory(DataDirectoryType::ResourceTable).unwrap();
    let resource_section = *image
        .section_header_for_data_directory(DataDirectoryType::ResourceTable)
        .unwrap();
    let resource_section_data = data[resource_section.pointer_to_raw_data as usize
        ..(resource_section.pointer_to_raw_data + resource_section.size_of_raw_data) as usize]
        .to_vec();
    let import_directory_offset = data_directory_offset(&image, 1);
    let mut data = data;
    // point import directory header to resource directory
    data[import_directory_offset..import_directory_offset + size_of::<u32>()]
        .copy_from_slice(&resource_data_directory.virtual_address.to_le_bytes());
    data[import_directory_offset + size_of::<u32>()
        ..import_directory_offset + size_of::<ImageDataDirectory>()]
        .copy_from_slice(&resource_data_directory.size.to_le_bytes());

    let mut image = Image::parse(data).unwrap();
    let original_section_count = image.coff_header().number_of_sections;
    let resources = image.resource_directory().cloned().unwrap();
    image.set_resource_directory(resources).unwrap();

    assert_eq!(
        image.coff_header().number_of_sections,
        original_section_count + 1,
        "shared resource section causes a new section to be added"
    );
    assert_eq!(
        &image.data()[resource_section.pointer_to_raw_data as usize
            ..(resource_section.pointer_to_raw_data + resource_section.size_of_raw_data) as usize],
        resource_section_data,
        "original shared section data is preserved"
    );
    assert_eq!(
        image.data_directory(DataDirectoryType::ImportTable).unwrap().virtual_address,
        resource_data_directory.virtual_address,
        "other data directory continues to reference the original section"
    );
    assert_ne!(
        image.data_directory(DataDirectoryType::ResourceTable).unwrap().virtual_address,
        resource_data_directory.virtual_address,
        "resource directory moves to the new section"
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
