use clap::{ArgAction, Parser};
use editpe::{
    Image, ResourceData, ResourceDirectory, ResourceEntry, ResourceEntryName, ResourceTable,
    VersionInfo, VersionStringTable, constants::*, types::VersionU32,
};

/// Command line tool to edit resources of exe files.
///
/// API-compatible with https://github.com/electron/rcedit.
#[derive(Debug, Parser)]
#[command(
    name = "editpe",
    about = "Command line tool to edit resources of exe file",
    arg_required_else_help = true,
    disable_help_flag = true
)]
struct Cli {
    /// Path to the exe or dll to edit
    filename: String,

    /// Set a version string (e.g. --set-version-string ProductName "My App")
    #[arg(long, num_args = 2, value_names = ["KEY", "VALUE"], action = ArgAction::Append)]
    set_version_string: Vec<String>,

    /// Set the file version (e.g. 1.2.3.4)
    #[arg(long, value_name = "VERSION", action = ArgAction::Append)]
    set_file_version: Vec<String>,

    /// Set the product version (e.g. 1.2.3.4)
    #[arg(long, value_name = "VERSION", action = ArgAction::Append)]
    set_product_version: Vec<String>,

    /// Set the icon from a file
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    set_icon: Vec<String>,

    /// Set a string table resource by numeric id
    #[arg(long, num_args = 2, value_names = ["ID", "VALUE"], action = ArgAction::Append)]
    set_resource_string: Vec<String>,

    /// Set the requested execution level in the manifest
    /// (asInvoker | highestAvailable | requireAdministrator)
    #[arg(long, value_name = "LEVEL", action = ArgAction::Append)]
    set_requested_execution_level: Vec<String>,

    /// Set the application manifest from a file
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    application_manifest: Vec<String>,

    /// Set an RCDATA resource by id (numeric or named) from a file
    #[arg(long, num_args = 2, value_names = ["ID", "PATH"], action = ArgAction::Append)]
    set_rcdata: Vec<String>,

    /// Get a version string and print it to stdout
    #[arg(long, value_name = "KEY", action = ArgAction::Append)]
    get_version_string: Vec<String>,

    /// Get a string table resource by numeric id and print it to stdout
    #[arg(long, value_name = "ID", action = ArgAction::Append)]
    get_resource_string: Vec<String>,

    /// Print help information
    #[arg(short, long, action = ArgAction::Help)]
    help: Option<bool>,
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn parse_version(s: &str) -> Result<VersionU32, String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 4 {
        return Err(format!(
            "invalid version '{s}': expected at most 4 dot-separated components"
        ));
    }

    let mut parsed = [0u16; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(format!(
                "invalid version '{s}': empty version component at position {}",
                i + 1
            ));
        }
        parsed[i] = part
            .parse::<u16>()
            .map_err(|_| format!("invalid version component '{part}' in '{s}'"))?;
    }

    let [major, minor, patch, build] = parsed;
    Ok(VersionU32 {
        major: ((major as u32) << 16) | minor as u32,
        minor: ((patch as u32) << 16) | build as u32,
    })
}

fn load_version_info(resources: &ResourceDirectory) -> VersionInfo {
    match resources.get_version_info() {
        Ok(Some(vi)) => vi,
        Ok(None) => VersionInfo::default(),
        Err(e) => die(format!("failed to read version info: {e}")),
    }
}

fn ensure_table<'a>(
    table: &'a mut ResourceTable, name: &ResourceEntryName,
) -> &'a mut ResourceTable {
    if table.get(name).is_none() {
        table.insert(name.clone(), ResourceEntry::Table(ResourceTable::default()));
    }
    match table.get_mut(name) {
        Some(ResourceEntry::Table(inner)) => inner,
        Some(ResourceEntry::Data(_)) => {
            die(format!(
                "invalid resource table: entry '{name:?}' is data, not a table"
            ))
        }
        None => die(format!(
            "failed to create or retrieve resource table entry '{name:?}'"
        )),
    }
}

fn get_resource_string(resources: &ResourceDirectory, id: u32) -> Option<String> {
    let block_id = id / 16 + 1;
    let position = (id % 16) as usize;

    let type_table = resources.root().get(ResourceEntryName::ID(RT_STRING as u32))?.as_table()?;
    let block_table = type_table.get(ResourceEntryName::ID(block_id))?.as_table()?;
    let data = block_table
        .get(ResourceEntryName::ID(LANGUAGE_ID_EN_US as u32))
        .or_else(|| {
            let lang_key = block_table.entries().first()?.clone();
            block_table.get(lang_key)
        })?
        .as_data()?
        .data();

    let mut offset = 0usize;
    for i in 0..16 {
        if offset + 2 > data.len() {
            return None;
        }
        let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if i == position {
            if len == 0 || offset + len * 2 > data.len() {
                return None;
            }
            let chars: Vec<u16> = (0..len)
                .map(|j| u16::from_le_bytes([data[offset + j * 2], data[offset + j * 2 + 1]]))
                .collect();
            return String::from_utf16(&chars).ok();
        }
        offset += len * 2;
    }
    None
}

fn set_resource_string(resources: &mut ResourceDirectory, id: u32, value: &str) {
    let block_id = id / 16 + 1;
    let position = (id % 16) as usize;
    let type_name = ResourceEntryName::ID(RT_STRING as u32);
    let block_name = ResourceEntryName::ID(block_id);

    let block_table = ensure_table(ensure_table(resources.root_mut(), &type_name), &block_name);

    if block_table.entries().is_empty() {
        block_table
            .insert(ResourceEntryName::default(), ResourceEntry::Data(ResourceData::default()));
    }
    let key = block_table.entries().first().copied().unwrap().clone();
    let existing_data = block_table
        .get(&key)
        .and_then(|e| e.as_data())
        .map(|d| d.data().to_vec())
        .unwrap_or_default();

    let mut strings: Vec<Vec<u16>> = Vec::with_capacity(16);
    let mut offset = 0usize;
    for _ in 0..16 {
        if offset + 2 > existing_data.len() {
            strings.push(Vec::new());
            continue;
        }
        let len = u16::from_le_bytes([existing_data[offset], existing_data[offset + 1]]) as usize;
        offset += 2;
        let chars = if len > 0 && offset + len * 2 <= existing_data.len() {
            (0..len)
                .map(|j| {
                    u16::from_le_bytes([
                        existing_data[offset + j * 2],
                        existing_data[offset + j * 2 + 1],
                    ])
                })
                .collect()
        } else {
            Vec::new()
        };
        offset += len * 2;
        strings.push(chars);
    }

    strings[position] = value.encode_utf16().collect();

    let mut new_data: Vec<u8> = Vec::new();
    for chars in &strings {
        new_data.extend_from_slice(&(chars.len() as u16).to_le_bytes());
        for &c in chars {
            new_data.extend_from_slice(&c.to_le_bytes());
        }
    }

    if let Some(entry) = block_table.get_mut(&key) {
        match entry {
            ResourceEntry::Data(d) => d.set_data(new_data),
            _ => {
                let mut data = ResourceData::default();
                data.set_data(new_data);
                *entry = ResourceEntry::Data(data);
            }
        }
    }
}

/// Modify the `level` attribute of `<requestedExecutionLevel>` in an XML manifest string.
/// If the attribute exists it is updated in-place. If the element is absent but a manifest
/// exists, a `<trustInfo>` block is injected before `</assembly>`. If there is no manifest
/// at all, a minimal one is created.
fn set_requested_execution_level(manifest: &str, level: &str) -> String {
    let try_update = || -> Option<String> {
        let elem_pos = manifest.find("requestedExecutionLevel")?;
        let attr_rel = manifest[elem_pos..].find("level=")?;
        let attr_start = elem_pos + attr_rel + 6;
        let quote = manifest[attr_start..].chars().next().filter(|&c| c == '"' || c == '\'')?;
        let end_pos = attr_start + 1 + manifest[attr_start + 1..].find(quote)?;
        Some(format!(
            "{}{}{}{}",
            &manifest[..attr_start + 1],
            level,
            quote,
            &manifest[end_pos + 1..]
        ))
    };

    if let Some(updated) = try_update() {
        return updated;
    }

    if !manifest.is_empty() {
        if let Some(end_pos) = manifest.rfind("</assembly>") {
            let trustinfo = format!(
                "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">\n    \
                 <security>\n      \
                 <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n        \
                 <requestedExecutionLevel level=\"{level}\" uiAccess=\"false\"/>\n      \
                 </requestedPrivileges>\n    \
                 </security>\n  \
                 </trustInfo>\n"
            );
            return format!("{}{}{}", &manifest[..end_pos], trustinfo, &manifest[end_pos..]);
        }
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n  \
           <assemblyIdentity version=\"1.0.0.0\" name=\"Application\" type=\"win32\"/>\n  \
           <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">\n    \
             <security>\n      \
               <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n        \
                 <requestedExecutionLevel level=\"{level}\" uiAccess=\"false\"/>\n      \
               </requestedPrivileges>\n    \
             </security>\n  \
           </trustInfo>\n\
         </assembly>"
    )
}

fn main() {
    let cli = Cli::parse();
    let filename = &cli.filename;

    if [
        cli.get_version_string.as_slice(),
        cli.get_resource_string.as_slice(),
        cli.set_version_string.as_slice(),
        cli.set_file_version.as_slice(),
        cli.set_product_version.as_slice(),
        cli.set_icon.as_slice(),
        cli.set_resource_string.as_slice(),
        cli.set_requested_execution_level.as_slice(),
        cli.application_manifest.as_slice(),
        cli.set_rcdata.as_slice(),
    ]
    .iter()
    .all(|s| s.is_empty())
    {
        die("no operations specified");
    }

    let image_data = std::fs::read(filename)
        .unwrap_or_else(|e| die(format!("failed to read '{filename}': {e}")));
    let mut image = Image::parse(&image_data)
        .unwrap_or_else(|e| die(format!("failed to parse '{filename}': {e}")));
    let mut resources = image.resource_directory().cloned().unwrap_or_default();
    let mut modified = false;

    for key in &cli.get_version_string {
        let vi = resources
            .get_version_info()
            .unwrap_or_else(|e| die(format!("failed to read version info: {e}")))
            .unwrap_or_else(|| die(format!("no version info present in '{filename}'")));
        println!(
            "{}",
            vi.strings
                .iter()
                .find_map(|t| t.strings.get(key.as_str()))
                .cloned()
                .unwrap_or_else(|| die(format!("version string '{key}' not found")))
        );
    }

    for raw_id in &cli.get_resource_string {
        let id: u32 = raw_id
            .parse()
            .unwrap_or_else(|_| die(format!("invalid resource string id '{raw_id}'")));
        println!(
            "{}",
            get_resource_string(&resources, id)
                .unwrap_or_else(|| die(format!("resource string {id} not found")))
        );
    }

    for chunk in cli.set_version_string.chunks(2) {
        let mut vi = load_version_info(&resources);
        if vi.strings.is_empty() {
            vi.strings.push(VersionStringTable {
                key:     format!("{:04X}{:04X}", LANGUAGE_ID_EN_US, CODE_PAGE_ID_EN_US),
                strings: Default::default(),
            });
        }
        vi.strings[0].strings.insert(chunk[0].clone(), chunk[1].clone());
        resources
            .set_version_info(&vi)
            .unwrap_or_else(|e| die(format!("failed to set version string: {e}")));
        modified = true;
    }

    for v in &cli.set_file_version {
        let mut vi = load_version_info(&resources);
        vi.info.file_version = parse_version(v).unwrap_or_else(|e| die(e));
        if vi.strings.is_empty() {
            vi.strings.push(VersionStringTable {
                key:     format!("{:04X}{:04X}", LANGUAGE_ID_EN_US, CODE_PAGE_ID_EN_US),
                strings: Default::default(),
            });
        }
        vi.strings[0].strings.insert("FileVersion".to_string(), v.clone());
        resources
            .set_version_info(&vi)
            .unwrap_or_else(|e| die(format!("failed to set file version: {e}")));
        modified = true;
    }

    for v in &cli.set_product_version {
        let mut vi = load_version_info(&resources);
        vi.info.product_version = parse_version(v).unwrap_or_else(|e| die(e));
        if vi.strings.is_empty() {
            vi.strings.push(VersionStringTable {
                key:     format!("{:04X}{:04X}", LANGUAGE_ID_EN_US, CODE_PAGE_ID_EN_US),
                strings: Default::default(),
            });
        }
        vi.strings[0].strings.insert("ProductVersion".to_string(), v.clone());
        resources
            .set_version_info(&vi)
            .unwrap_or_else(|e| die(format!("failed to set product version: {e}")));
        modified = true;
    }

    for path in &cli.set_icon {
        resources
            .set_main_icon_file(path)
            .unwrap_or_else(|e| die(format!("failed to set icon from '{path}': {e}")));
        modified = true;
    }

    for chunk in cli.set_resource_string.chunks(2) {
        let id: u32 = chunk[0]
            .parse()
            .unwrap_or_else(|_| die(format!("invalid resource string id '{}'", chunk[0])));
        set_resource_string(&mut resources, id, &chunk[1]);
        modified = true;
    }

    for level in &cli.set_requested_execution_level {
        let existing = resources
            .get_manifest()
            .unwrap_or_else(|e| die(format!("failed to read manifest: {e}")))
            .unwrap_or_default();
        resources
            .set_manifest(&set_requested_execution_level(&existing, level))
            .unwrap_or_else(|e| die(format!("failed to set manifest: {e}")));
        modified = true;
    }

    for path in &cli.application_manifest {
        let manifest = std::fs::read_to_string(path)
            .unwrap_or_else(|e| die(format!("failed to read manifest file '{path}': {e}")));
        resources
            .set_manifest(&manifest)
            .unwrap_or_else(|e| die(format!("failed to set manifest: {e}")));
        modified = true;
    }

    for chunk in cli.set_rcdata.chunks(2) {
        let id_name = match chunk[0].parse::<u32>() {
            Ok(n) => ResourceEntryName::ID(n),
            Err(_) => ResourceEntryName::from_string(&chunk[0]),
        };
        let data = std::fs::read(&chunk[1])
            .unwrap_or_else(|e| die(format!("failed to read rcdata file '{}': {e}", chunk[1])));
        let inner = ensure_table(
            ensure_table(resources.root_mut(), &ResourceEntryName::ID(RT_RCDATA as u32)),
            &id_name,
        );
        let mut entry = ResourceData::default();
        entry.set_data(data);
        inner.insert(ResourceEntryName::default(), ResourceEntry::Data(entry));
        modified = true;
    }

    if modified {
        image
            .set_resource_directory(resources)
            .unwrap_or_else(|e| die(format!("failed to update resource directory: {e}")));
        image
            .write_file(filename)
            .unwrap_or_else(|e| die(format!("failed to write '{filename}': {e}")));
    }
}
