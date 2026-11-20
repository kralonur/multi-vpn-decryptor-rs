//! HTTP Custom format detection and shared native/WASM entry points.
//! Legacy build-810 and authenticated modern (n11/n15) decoding stay separate.

mod legacy;
mod modern;

use serde_json::Value;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
pub enum HcError {
    #[error("HC input is empty")]
    EmptyInput,
    #[error("HC input is not valid UTF-8")]
    InvalidText,
    #[error("HC input contains a character outside the byte mapping")]
    InvalidByteMapping,
    #[error("HC outer XOR layer did not produce hexadecimal data")]
    InvalidOuterHex,
    #[error("HC outer ChaCha20 layer could not be decrypted")]
    OuterDecryption,
    #[error("HC outer payload is not a JSON object")]
    InvalidOuterJson,
    #[error("HC outer JSON does not contain the verified slot fields")]
    InvalidOuterLayout,
    #[error("HC modern container authentication failed")]
    ModernAuthentication,
    #[error("HC modern container has an invalid layout")]
    InvalidModernLayout,
    #[error("HC modern key scheme, password, or access protection is not supported")]
    UnsupportedModernProtection,
    #[error("HC decoded slot stream is empty")]
    EmptySlotStream,
    #[error("HC profile contains {found} slots; expected {expected}")]
    UnexpectedSlotCount { found: usize, expected: usize },
}

/// Decode a legacy or modern HTTP Custom file without network/device access.
/// Raw fields are retained alongside readable or best-effort decoded views.
pub fn decrypt_hc_file(file_bytes: &[u8]) -> Result<Value, HcError> {
    if file_bytes.is_empty() {
        return Err(HcError::EmptyInput);
    }
    let outer = decode_outer_json(file_bytes)?;
    if outer.get("a").and_then(Value::as_str) == Some("HCCFG") {
        modern::decode(&outer)
    } else {
        legacy::decode(&outer)
    }
}

/// WASM-facing HTTP Custom decryptor returning the decoded configuration.
#[wasm_bindgen]
pub fn decrypt_hc(file_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let value =
        decrypt_hc_file(file_bytes).map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&value).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn decode_outer_json(file_bytes: &[u8]) -> Result<Value, HcError> {
    let text = std::str::from_utf8(file_bytes).map_err(|_| HcError::InvalidText)?;
    // Do not normalize line endings: mapped CR and LF characters are ciphertext.
    let mapped = text
        .chars()
        .map(|character| u8::try_from(character as u32).map_err(|_| HcError::InvalidByteMapping))
        .collect::<Result<Vec<_>, _>>()?;
    match legacy::open_envelope(&mapped)? {
        Some(outer) => Ok(outer),
        None => modern::open_envelope(&mapped),
    }
}
