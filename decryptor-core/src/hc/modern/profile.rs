//! Strict HPC1 packed-profile reader.

use super::HcError;
use serde_json::{Map, Value};

pub(super) fn decode(mut bytes: &[u8]) -> Result<Value, HcError> {
    fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], HcError> {
        let result = bytes.get(..count).ok_or(HcError::InvalidModernLayout)?;
        *bytes = &bytes[count..];
        Ok(result)
    }
    if take(&mut bytes, 8)? != b"HPC1\0\0\0\x0b" {
        return Err(HcError::InvalidModernLayout);
    }
    let mut fields = Map::new();
    for name in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"] {
        let value = match name {
            "j" => Value::from(i64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap())),
            "d" | "i" => Value::from(i32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap())),
            _ => {
                let length = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
                let text = std::str::from_utf8(take(&mut bytes, length)?)
                    .map_err(|_| HcError::InvalidModernLayout)?;
                Value::String(text.to_owned())
            }
        };
        fields.insert(name.to_owned(), value);
    }
    if !bytes.is_empty() {
        return Err(HcError::InvalidModernLayout);
    }
    Ok(Value::Object(fields))
}
