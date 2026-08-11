use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    any::type_name,
    ops::{Add, Rem, Sub},
};

use zerocopy::FromBytes;

use crate::ReadError;

pub fn read<T: FromBytes + Copy>(resource: &[u8]) -> Result<T, ReadError> {
    T::read_from_prefix(resource)
        .map_err(|_| ReadError(type_name::<T>().to_string()))
        .map(|(value, _)| value)
}

pub fn read_at<T: FromBytes + Copy>(resource: &[u8], offset: usize) -> Result<T, ReadError> {
    read(resource.get(offset..).ok_or_else(|| {
        ReadError(format!("offset {offset:#x} is outside data of length {:#x}", resource.len()))
    })?)
}

pub fn checked_slice(resource: &[u8], offset: usize, length: usize) -> Result<&[u8], ReadError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| ReadError(format!("range {offset:#x} + {length:#x} overflows")))?;
    resource.get(offset..end).ok_or_else(|| {
        ReadError(format!(
            "range {offset:#x}..{end:#x} is outside data of length {:#x}",
            resource.len()
        ))
    })
}

pub fn aligned_to<T: Add<Output = T> + Sub<Output = T> + Rem<Output = T> + Eq + Copy + Default>(
    value: T, alignment: T,
) -> T {
    if alignment == T::default() || value % alignment == T::default() {
        return value;
    }
    value + alignment - (value % alignment)
}

pub fn read_u16_string(data: &[u8]) -> Result<String, ReadError> {
    let mut string = Vec::new();
    for i in 0..(data.len() / 2) {
        let c = read::<u16>(&data[i * 2..])?;
        if c == 0 {
            break;
        }
        string.push(c);
    }
    Ok(String::from_utf16_lossy(&string))
}

pub fn string_to_u16<S: AsRef<str>>(string: S) -> Vec<u8> {
    let string = string.as_ref();
    let mut data = Vec::with_capacity(string.len() * 2 + 2);
    data.extend(string.encode_utf16().flat_map(|c| c.to_le_bytes()));
    data.extend([0, 0]);
    data
}

pub fn u16_string_len(string: &str) -> usize { string.encode_utf16().count() }
