//! Data types for parsing and building the resource section.
//! The resource section contains the resource directory and the resource data.
//! See <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section> for more information.

use std::{borrow::Borrow, mem::size_of};

use debug_ignore::DebugIgnore;
use indexmap::IndexMap;
use log::{error, trace, warn};
use zerocopy::AsBytes;

use crate::{constants::*, errors::*, types::*, util::*};


/// Portable executable resource directory.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ResourceDirectory {
    pub(crate) virtual_address: u32,
    pub(crate) root:            ResourceTable,
}
impl ResourceDirectory {
    /// Parse the resource directory from the given image at the given base address.
    /// The virtual address is used to resolve the resource data offsets and has to correspond to the virtual address in the section table header of the source image.
    ///
    /// # Returns
    /// Returns an error if the resource directory at the given address is invalid.
    pub fn parse(
        image: &[u8], base_address: u32, virtual_address: u32,
    ) -> Result<Self, ImageReadError> {
        let root = ResourceTable::parse(image, base_address, virtual_address, 0, 0)?;
        Ok(Self {
            virtual_address,
            root,
        })
    }

    /// Returns the virtual address of the resource directory in the source image.
    pub fn virtual_address(&self) -> u32 { self.virtual_address }

    /// Returns the root resource table.
    /// The root resource table contains the top-level resource entries.
    pub fn root(&self) -> &ResourceTable { &self.root }

    /// Returns the mutable root resource table.
    /// The root resource table contains the top-level resource entries.
    pub fn root_mut(&mut self) -> &mut ResourceTable { &mut self.root }

    /// Returns the size of the resulting resource directory in bytes.
    pub fn size(&self) -> u32 { self.root.size() }

    /// Build the resource directory into raw bytes to be included in an image.
    /// The virtual address is used to compute the resource data offsets and has to correspond to the virtual address in the section table header of the target image.
    pub fn build(&self, virtual_address: u32) -> Vec<u8> { self.root.build(virtual_address) }
}

/// Portable executable resource table data.
enum TableData {
    Table(ResourceDirectoryTable),
    Entry(ResourceDirectoryEntry),
}

/// Portable executable resource table.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ResourceTable {
    pub(crate) data:    ResourceDirectoryTable,
    pub(crate) entries: IndexMap<ResourceEntryName, ResourceEntry>,
}
impl ResourceTable {
    fn parse(
        image: &[u8], base_address: u32, virtual_address: u32, directory_offset: u32, level: usize,
    ) -> Result<Self, ImageReadError> {
        let table_offset = base_address + directory_offset;
        let resource_table = read::<ResourceDirectoryTable>(&image[table_offset as usize..])?;
        trace!("{} {:#x?}", "--".repeat(level + 1), resource_table);

        let mut entries = IndexMap::new();

        let mut entry_offset = table_offset + 16;
        for _ in 0..(resource_table.number_of_name_entries + resource_table.number_of_id_entries) {
            let entry = read::<ResourceDirectoryEntry>(&image[entry_offset as usize..])?;
            trace!("{} {:#x?}", "--".repeat(level + 1), entry);

            if entry.data_entry_or_subdirectory_offset & 0x80000000 != 0 {
                entries.insert(
                    ResourceEntryName::parse(image, base_address, entry.name_offset_or_integer_id)?,
                    ResourceEntry::Table(ResourceTable::parse(
                        image,
                        base_address,
                        virtual_address,
                        entry.data_entry_or_subdirectory_offset ^ 0x80000000,
                        level + 1,
                    )?),
                );
            } else {
                trace!(
                    "reading {} bytes at {} (image size {})",
                    size_of::<ResourceDataEntry>(),
                    base_address + entry.data_entry_or_subdirectory_offset,
                    image.len()
                );
                let data = read::<ResourceDataEntry>(
                    &image[(base_address + entry.data_entry_or_subdirectory_offset) as usize..],
                )?;
                // calculate as i64 and convert to u64 first to check for padding
                let address = base_address as i64 + data.data_rva as i64 - virtual_address as i64;
                let mut address = address as u64;
                if address & 0xffffffffff000000 == 0xffffffffff000000 {
                    warn!(
                        "{} resource data entry address {:#x?} seems to be packed, ignoring padding",
                        "--".repeat(level + 1),
                        address
                    );
                    address ^= 0xffffffffff000000;
                }
                trace!("{} {:#x?} {:#x?}", "--".repeat(level + 1), address, data);
                if address + data.size as u64 > image.len() as u64 {
                    error!(
                        "{} resource data entry address {:#x?} with size {:#x?} ({:#x?}) outside valid range ({:#x?})",
                        "--".repeat(level + 1),
                        address,
                        data.size,
                        address + data.size as u64,
                        image.len()
                    );
                    continue;
                }
                let address = address as u32;
                entries.insert(
                    ResourceEntryName::parse(image, base_address, entry.name_offset_or_integer_id)?,
                    ResourceEntry::Data(ResourceData {
                        codepage: data.codepage,
                        reserved: data.reserved,
                        data:     Vec::from(
                            &image[address as usize..(address + data.size) as usize],
                        )
                        .into(),
                    }),
                );
            }

            entry_offset += 8;
        }
        Ok(Self {
            data: resource_table,
            entries,
        })
    }

    fn build(&self, virtual_address: u32) -> Vec<u8> {
        let mut tables_offset = 0;
        let mut strings_offset = 0;
        let mut descriptions_offset = 0;
        let mut data_offset = 0;
        let (mut tables_data, strings_data, mut descriptions_data, data_data) = self.build_table(
            virtual_address,
            &mut tables_offset,
            &mut strings_offset,
            &mut descriptions_offset,
            &mut data_offset,
        );

        let mut data = Vec::new();
        data.extend(tables_data.iter_mut().flat_map(|data| match data {
            TableData::Table(table) => table.as_bytes(),
            TableData::Entry(entry) => {
                if entry.data_entry_or_subdirectory_offset & 0x80000000 == 0 {
                    entry.data_entry_or_subdirectory_offset += tables_offset + strings_offset;
                }
                if entry.name_offset_or_integer_id & 0x80000000 != 0 {
                    entry.name_offset_or_integer_id += tables_offset;
                }
                entry.as_bytes()
            }
        }));
        data.extend(strings_data.iter());
        data.extend(descriptions_data.iter_mut().flat_map(|data| {
            data.data_rva += tables_offset + strings_offset + descriptions_offset;
            data.as_bytes()
        }));
        data.extend(data_data);

        data
    }

    fn build_table(
        &self, virtual_address: u32, tables_offset: &mut u32, strings_offset: &mut u32,
        descriptions_offset: &mut u32, data_offset: &mut u32,
    ) -> (Vec<TableData>, Vec<u8>, Vec<ResourceDataEntry>, Vec<u8>) {
        let mut tables_data = Vec::<TableData>::new();
        let mut strings_data = Vec::<u8>::new();
        let mut descriptions_data = Vec::<ResourceDataEntry>::new();
        let mut data_data = Vec::<u8>::new();

        tables_data.push(TableData::Table(self.data));
        *tables_offset += 16;

        let mut next_table_offset = 0u32;
        let mut next_table_sizes = 0u32;
        for (name, entry) in &self.entries {
            strings_data.extend(name.string_data());
            let name_offset_or_integer_id = if name.string_size() > 0 {
                *strings_offset | 0x80000000
            } else {
                name.id()
            };
            *strings_offset += name.string_size();

            match entry {
                ResourceEntry::Table(table) => {
                    let entry_data = ResourceDirectoryEntry {
                        name_offset_or_integer_id,
                        data_entry_or_subdirectory_offset: (*tables_offset
                            + self.entries.len() as u32 * 8
                            + next_table_sizes)
                            | 0x80000000,
                    };
                    tables_data.push(TableData::Entry(entry_data));
                    next_table_offset += 8;
                    next_table_sizes += table.tables_size();
                }
                ResourceEntry::Data(data) => {
                    let entry_data = ResourceDirectoryEntry {
                        name_offset_or_integer_id,
                        data_entry_or_subdirectory_offset: *descriptions_offset,
                    };
                    tables_data.push(TableData::Entry(entry_data));
                    next_table_offset += 8;

                    data_data.extend(&*data.data);
                    let description_data = ResourceDataEntry {
                        data_rva: *data_offset + virtual_address,
                        size:     data.data.len() as u32,
                        codepage: data.codepage,
                        reserved: data.reserved,
                    };
                    descriptions_data.push(description_data);
                    *descriptions_offset += 16;
                    *data_offset += data.data.len() as u32;
                }
            }
        }
        *tables_offset += next_table_offset;

        for (_, entry) in &self.entries {
            match entry {
                ResourceEntry::Table(table) => {
                    let (t_tables_data, t_strings_data, t_descriptions_data, t_data_data) = table
                        .build_table(
                            virtual_address,
                            tables_offset,
                            strings_offset,
                            descriptions_offset,
                            data_offset,
                        );
                    tables_data.extend(t_tables_data);
                    strings_data.extend(t_strings_data);
                    descriptions_data.extend(t_descriptions_data);
                    data_data.extend(t_data_data);
                }
                ResourceEntry::Data(_) => {}
            }
        }

        (tables_data, strings_data, descriptions_data, data_data)
    }

    /// Get a resource entry from the table.
    /// # Returns
    /// The resource entry.
    pub fn get<N: Borrow<ResourceEntryName>>(&self, name: N) -> Option<&ResourceEntry> {
        self.entries.get(name.borrow())
    }

    /// Get a mutable resource entry from the table.
    /// # Returns
    /// The resource entry.
    pub fn get_mut<N: Borrow<ResourceEntryName>>(&mut self, name: N) -> Option<&mut ResourceEntry> {
        self.entries.get_mut(name.borrow())
    }

    /// Insert a resource entry into the table.
    /// If an entry with the given name already exists, it will be replaced.
    /// # Returns
    /// The replaced entry.
    pub fn insert<N: Borrow<ResourceEntryName>>(
        &mut self, name: N, entry: ResourceEntry,
    ) -> Option<ResourceEntry> {
        let name = name.borrow();
        let entry = self.entries.insert(name.clone(), entry);
        if entry.is_none() {
            if name.string_size() > 0 {
                self.data.number_of_name_entries += 1;
            } else {
                self.data.number_of_id_entries += 1;
            }
        }
        entry
    }

    /// Remove a resource entry from the table.
    /// # Returns
    /// The removed entry.
    pub fn remove<N: Borrow<ResourceEntryName>>(&mut self, name: N) -> Option<ResourceEntry> {
        let name = name.borrow();
        if let Some(entry) = self.entries.remove(name) {
            if name.string_size() > 0 {
                self.data.number_of_name_entries -= 1;
            } else {
                self.data.number_of_id_entries -= 1;
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Returns the entries in the table.
    pub fn entries(&self) -> Vec<&ResourceEntryName> { self.entries.keys().collect() }

    /// Returns the complete size of the table, its resources and its children in the resource table.
    pub fn size(&self) -> u32 {
        self.tables_size() + self.strings_size() + self.descriptions_size() + self.data_size()
    }

    /// Returns the size of the table and its children in the resource table.
    pub fn tables_size(&self) -> u32 {
        self.entries.iter().map(|(_, entry)| entry.table_size()).sum::<u32>() + 16
    }

    /// Returns the size of the strings in the entry and its children in the resource table.
    pub fn strings_size(&self) -> u32 {
        self.entries
            .iter()
            .map(|(name, entry)| name.string_size() + entry.strings_size())
            .sum::<u32>()
    }

    /// Returns the size of the descriptions in the tables children in the resource table.
    pub fn descriptions_size(&self) -> u32 {
        self.entries.iter().map(|(_, entry)| entry.description_size()).sum::<u32>()
    }

    /// Returns the size of the data in in the tables children in the resource table.
    pub fn data_size(&self) -> u32 {
        self.entries.iter().map(|(_, entry)| entry.data_size()).sum::<u32>()
    }
}

/// Raw resource data.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ResourceData {
    data:     DebugIgnore<Vec<u8>>,
    codepage: u32,
    reserved: u32,
}
impl ResourceData {
    /// Returns the raw data.
    pub fn data(&self) -> &[u8] { &self.data }

    /// Returns the codepage of the data.
    pub fn codepage(&self) -> u32 { self.codepage }

    /// Set the raw data.
    pub fn set_data(&mut self, data: Vec<u8>) { self.data = data.into(); }

    /// Set the codepage of the data.
    pub fn set_codepage(&mut self, codepage: u32) { self.codepage = codepage; }
}

/// Resource entry in a resource table.
/// This can be either a child table or raw data.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResourceEntry {
    Table(ResourceTable),
    Data(ResourceData),
}
impl ResourceEntry {
    /// Returns the size of the table entry and its children in the resource table.
    pub fn table_size(&self) -> u32 {
        match self {
            // entry + sub-table
            ResourceEntry::Table(table) => table.tables_size() + 8,
            // entry
            ResourceEntry::Data(_) => 8,
        }
    }

    /// Returns the size of the strings in the entry and its children in the resource table.
    /// This is the size of the resouorce names of child tables.
    pub fn strings_size(&self) -> u32 {
        match self {
            ResourceEntry::Table(table) => table.strings_size(),
            ResourceEntry::Data(_) => 0,
        }
    }

    /// Returns the size of the descriptions in the entry and its children in the resource table.
    /// This is the size of the resource data description of the entry or child entries.
    pub fn description_size(&self) -> u32 {
        match self {
            ResourceEntry::Table(table) => table.descriptions_size(),
            ResourceEntry::Data(_) => 16,
        }
    }

    /// Returns the size of the data in the entry and its children in the resource table.
    /// This is the size of the resource data of the entry or child entries.
    pub fn data_size(&self) -> u32 {
        match self {
            ResourceEntry::Table(table) => table.data_size(),
            ResourceEntry::Data(data) => data.data.len() as u32,
        }
    }
}

/// Resource directory entry name.
/// This can either be a raw id or a name.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ResourceEntryName {
    // raw id
    ID(u32),
    // 2 byte size + data
    Name(Vec<u8>),
}
impl ResourceEntryName {
    fn parse(image: &[u8], offset: u32, id: u32) -> Result<Self, ReadError> {
        if id & 0x80000000 != 0 {
            trace!("reading resource name {:#x?}", id);
            let address = offset + (id ^ 0x80000000);
            let length = read::<u16>(&image[address as usize..])? as u32;
            trace!("resource name length: {}", length);
            // size is in 16 bit characters so it needs to be doubled
            let data = &image[address as usize..(address + 2 + (length * 2)) as usize];
            trace!("resource name: {:x?}", data);
            Ok(Self::Name(data.to_vec()))
        } else {
            trace!("reading resource id {:#x?}", id);
            Ok(Self::ID(id))
        }
    }

    pub fn from_string<S: AsRef<str>>(string: S) -> Self {
        let string = string.as_ref();
        let mut data = Vec::with_capacity(string.len() * 2 + 2);
        data.extend_from_slice(&(string.len() as u16).to_le_bytes());
        data.extend(string.encode_utf16().flat_map(|c| c.to_le_bytes().to_vec()));
        Self::Name(data)
    }

    pub fn to_string(&self) -> Option<String> {
        match self {
            Self::ID(_) => None,
            Self::Name(data) => {
                let length = read::<u16>(&data[0..]).unwrap() as usize;
                let data = &data[2..];
                let mut string = String::with_capacity(length);
                for i in 0..length {
                    let c = read::<u16>(&data[i * 2..]).unwrap() as u32;
                    string.push(std::char::from_u32(c).unwrap());
                }
                Some(string)
            }
        }
    }

    fn string_size(&self) -> u32 {
        match self {
            Self::ID(_) => 0,
            Self::Name(name) => name.len() as u32,
        }
    }

    fn id(&self) -> u32 {
        match self {
            Self::ID(id) => *id,
            Self::Name(_) => unreachable!(),
        }
    }

    fn string_data(&self) -> &[u8] {
        match self {
            Self::ID(_) => &[],
            Self::Name(data) => data.as_bytes(),
        }
    }
}
