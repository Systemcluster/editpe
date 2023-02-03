use std::{
    any::type_name,
    ops::{Add, Rem, Sub},
};

use zerocopy::FromBytes;

use crate::ReadError;

pub fn read<T: FromBytes + Copy>(resource: &[u8]) -> Result<T, ReadError> {
    T::read_from_prefix(resource).ok_or_else(|| ReadError(type_name::<T>().to_string()))
}

pub fn aligned_to<T: Add<Output = T> + Sub<Output = T> + Rem<Output = T> + Eq + Copy + Default>(
    value: T, alignment: T,
) -> T {
    if value % alignment == T::default() {
        return value;
    }
    value + alignment - (value % alignment)
}
