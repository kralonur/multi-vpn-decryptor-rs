//! Best-effort HTTP Custom (`.hc`) configuration decoding.
//!
//! The outer container below is verified against HTTP Custom versionCode 810
//! (7.10.12 - Patch 2): UTF-8 character-to-byte mapping, the repeating XOR
//! layer, hex, and the legacy ChaCha20 stream. The per-slot ChaCha20 layer and
//! the 32-slot order are also observed in that APK/sample pair. Credential,
//! protocol, and some nested-field meanings are intentionally reported as
//! provisional because the native implementation remains stripped.

use base64::Engine as _;
use chacha20::ChaCha20Legacy;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hex_literal::hex;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::sync::LazyLock;
use thiserror::Error;
use wasm_bindgen::prelude::*;

const STREAM_COUNTER: u64 = 1;
const CHACHA_BLOCK_BYTES: u64 = 64;
const AUTH_TAG_BYTES: usize = 16;
const SLOT_COUNT: usize = 32;

struct HcConstants;

impl HcConstants {
    // The file's Unicode obfuscation key, recovered from the version 810
    // outer path. It is applied to the byte value of every UTF-8 character,
    // not to the original UTF-8 byte sequence.
    const OUTER_XOR_KEY: [u8; 11] = hex!("e382e4b8adc386f09f9293");
    const STATIC_NONCE: [u8; 8] = [0xdb; 8];

    // Keys recovered from the HTTP Custom ChaCha20 key table. Key #5 opens
    // the file container; key #1 opens the slot stream; key #7 opens the
    // metadata and per-slot legacy values.
    const CHACHA_KEYS: [[u8; 32]; 8] = [
        hex!("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
        hex!("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
        hex!("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
        hex!("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
        hex!("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
        hex!("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
        hex!("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
        hex!("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"),
    ];

    // This is the observed pre/post Base64 byte transform for the legacy
    // slot representation. The newer table found in historical references
    // is not selected here because it was not independently verified.
    const JKL_KEY_OLD: [u8; 20] = [
        0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce, 0xcd, 0xcc, 0xbd, 0xbc, 0xbb, 0xba, 0xb9,
        0xb8, 0xb7, 0xb6, 0xb5, 0xb4,
    ];

    // The first 26 entries are the a-z Braille symbols. The number symbols
    // are retained because they are part of the historical alphabet and may
    // occur in another credential-bearing slot.
    const BRAILLE_ALPHABET: &str = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚";

    const TOKEN_NAMES: [&str; SLOT_COUNT] = [
        "payload",
        "proxy",
        "lockAllConfig",
        "blockedByRoot",
        "expiryTime",
        "noteEnabled",
        "notes",
        "sshField",
        "mobileDataAndLockProvider",
        "unlockUserAndPass",
        "ovpnConfig",
        "ovpnUserAndPass",
        "sni",
        "unlockUserAndPass2",
        "unknown14",
        "blockedByHwid",
        "cloudconfig",
        "psiphon",
        "name",
        "blockArea",
        "connectionMode",
        "blockedByPassword",
        "unknown22",
        "extraSniffer",
        "unknown24",
        "v2rayEnabled",
        "v2rayConfig",
        "version",
        "slowdnsEnabled",
        "slowdnsServer",
        "slowdnsPublickey",
        "dnsResolver",
    ];
}

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
    #[error("HC decoded slot stream is empty")]
    EmptySlotStream,
    #[error("HC profile contains {found} slots; expected {expected}")]
    UnexpectedSlotCount { found: usize, expected: usize },
}

/// Decode an HTTP Custom `.hc` file into a JSON value.
///
/// The returned object contains `config` for decoded slot values,
/// `raw_slots` for lossless access to all 32 slot strings, and `unresolved`
/// for nested transformations whose semantics are not yet independently
/// confirmed. No network or Android runtime is used.
pub fn decrypt_hc_file(file_bytes: &[u8]) -> Result<Value, HcError> {
    if file_bytes.is_empty() {
        return Err(HcError::EmptyInput);
    }

    let outer = decode_outer_json(file_bytes)?;
    let outer_object = outer.as_object().ok_or(HcError::InvalidOuterJson)?;
    let config_object = outer_object
        .get("a")
        .and_then(Value::as_object)
        .ok_or(HcError::InvalidOuterLayout)?;
    let slot_ciphertext = config_object
        .get("xy")
        .and_then(Value::as_str)
        .ok_or(HcError::InvalidOuterLayout)?;
    let delimiter = config_object
        .get("uv")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(HcError::InvalidOuterLayout)?;

    let password = outer_object
        .get("e")
        .and_then(Value::as_str)
        .and_then(|value| {
            decode_abc_text(
                value,
                &HcConstants::CHACHA_KEYS[7],
                &HcConstants::STATIC_NONCE,
            )
        })
        .filter(|value| !value.is_empty());
    let hardware_id = decode_outer_metadata(config_object, "bb").filter(|value| !value.is_empty());
    let provider = decode_outer_metadata(config_object, "ed").filter(|value| !value.is_empty());
    let area = decode_outer_metadata(config_object, "fe").filter(|value| !value.is_empty());
    let dynamic_nonce = derive_dynamic_nonce(
        password.as_deref(),
        hardware_id.as_deref(),
        provider.as_deref(),
        area.as_deref(),
    );

    let slot_plaintext = decode_abc_text(
        slot_ciphertext,
        &HcConstants::CHACHA_KEYS[1],
        &HcConstants::STATIC_NONCE,
    )
    .filter(|value| !value.is_empty())
    .ok_or(HcError::EmptySlotStream)?;
    let raw_slots = slot_plaintext
        .split(delimiter)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if raw_slots.len() != SLOT_COUNT {
        return Err(HcError::UnexpectedSlotCount {
            found: raw_slots.len(),
            expected: SLOT_COUNT,
        });
    }

    let mut config = Map::new();
    for (index, raw_slot) in raw_slots.iter().enumerate() {
        // The meanings of these two positions were not recovered. Their raw
        // values remain available below instead of being silently discarded.
        if matches!(index, 22 | 24) {
            continue;
        }
        let decoded = decode_slot(raw_slot, index, &dynamic_nonce);
        config.insert(HcConstants::TOKEN_NAMES[index].to_owned(), decoded);
    }

    let mut protections = Map::new();
    if let Some(value) = password.as_deref().filter(|value| !value.is_empty()) {
        protections.insert("password".to_owned(), Value::String(value.to_owned()));
    }
    for (name, value) in [
        ("hwid", hardware_id.as_deref()),
        ("provider", provider.as_deref()),
        ("area", area.as_deref()),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            protections.insert(name.to_owned(), Value::String(value.to_owned()));
        }
    }

    let mut metadata = Map::new();
    if let Some(value) = password.as_deref() {
        metadata.insert("password".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = decode_outer_metadata(outer_object, "b") {
        metadata.insert("outer_b".to_owned(), Value::String(value));
    }
    let mut outer_fields = Map::new();
    for (key, value) in config_object {
        if matches!(key.as_str(), "xy" | "uv") {
            continue;
        }
        if let Some(raw_value) = value.as_str()
            && let Some(decoded) = decode_abc_text(
                raw_value,
                &HcConstants::CHACHA_KEYS[7],
                &HcConstants::STATIC_NONCE,
            )
        {
            outer_fields.insert(key.clone(), Value::String(decoded));
        }
    }
    if !outer_fields.is_empty() {
        metadata.insert("outer_fields".to_owned(), Value::Object(outer_fields));
    }
    metadata.insert(
        "dynamic_nonce".to_owned(),
        Value::String(hex::encode(dynamic_nonce)),
    );
    metadata.insert(
        "nested_decoding".to_owned(),
        Value::String("best-effort; credential and protocol semantics are provisional".to_owned()),
    );

    let mut unknown_slots = Map::new();
    for index in [14usize, 22, 24] {
        let name = HcConstants::TOKEN_NAMES[index];
        let mut entry = Map::new();
        entry.insert("name".to_owned(), Value::String(name.to_owned()));
        entry.insert("raw".to_owned(), Value::String(raw_slots[index].clone()));
        if let Some(value) = config.get(name) {
            entry.insert("decoded_candidate".to_owned(), value.clone());
        }
        entry.insert(
            "status".to_owned(),
            Value::String("unresolved semantics".to_owned()),
        );
        unknown_slots.insert(index.to_string(), Value::Object(entry));
    }

    let mut unresolved = Map::new();
    unresolved.insert("unknown_slots".to_owned(), Value::Object(unknown_slots));
    unresolved.insert(
        "nested".to_owned(),
        json!({
            "credential_transform": {
                "status": "provisional",
                "slots": [7, 11],
                "note": "Braille/numeric tuple decoding is a best-effort transform; the stripped native credential semantics are not proven.",
                "slot_7_candidate": config.get("sshField").cloned().unwrap_or(Value::Null),
                "slot_11_candidate": config.get("ovpnUserAndPass").cloned().unwrap_or(Value::Null),
            },
            "protocol_mappings": {
                "status": "unresolved",
                "note": "The slot names are historical/APK-derived labels; complete protocol-state mapping is not recovered."
            }
        }),
    );

    let mut result = Map::new();
    result.insert("format".to_owned(), Value::String("http-custom".to_owned()));
    result.insert("protections".to_owned(), Value::Object(protections));
    result.insert("metadata".to_owned(), Value::Object(metadata));
    result.insert("config".to_owned(), Value::Object(config));
    result.insert(
        "raw_slots".to_owned(),
        Value::Array(raw_slots.into_iter().map(Value::String).collect()),
    );
    result.insert("unresolved".to_owned(), Value::Object(unresolved));
    Ok(Value::Object(result))
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
    if text.is_empty() {
        return Err(HcError::EmptyInput);
    }

    let mut obfuscated_hex = Vec::with_capacity(text.chars().count());
    for (index, character) in text.chars().enumerate() {
        let byte = u8::try_from(character as u32).map_err(|_| HcError::InvalidByteMapping)?;
        obfuscated_hex
            .push(byte ^ HcConstants::OUTER_XOR_KEY[index % HcConstants::OUTER_XOR_KEY.len()]);
    }
    if !obfuscated_hex.iter().all(u8::is_ascii_hexdigit) {
        return Err(HcError::InvalidOuterHex);
    }

    let ciphertext = hex::decode(obfuscated_hex).map_err(|_| HcError::InvalidOuterHex)?;
    let plaintext = decrypt_abc_bytes(
        &ciphertext,
        &HcConstants::CHACHA_KEYS[5],
        &HcConstants::STATIC_NONCE,
    )
    .ok_or(HcError::OuterDecryption)?;
    let value =
        serde_json::from_slice::<Value>(&plaintext).map_err(|_| HcError::InvalidOuterJson)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(HcError::InvalidOuterJson)
    }
}

fn decode_outer_metadata(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).and_then(|value| {
        decode_abc_text(
            value,
            &HcConstants::CHACHA_KEYS[7],
            &HcConstants::STATIC_NONCE,
        )
    })
}

fn decrypt_abc_bytes(
    ciphertext_and_tail: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 8],
) -> Option<Vec<u8>> {
    let ciphertext_length = ciphertext_and_tail.len().checked_sub(AUTH_TAG_BYTES)?;
    let mut plaintext = ciphertext_and_tail[..ciphertext_length].to_vec();
    let mut cipher = ChaCha20Legacy::new_from_slices(key, nonce).ok()?;
    cipher.try_seek(STREAM_COUNTER * CHACHA_BLOCK_BYTES).ok()?;
    cipher.try_apply_keystream(&mut plaintext).ok()?;
    Some(plaintext)
}

fn decode_abc_text(raw_value: &str, key: &[u8; 32], nonce: &[u8; 8]) -> Option<String> {
    let ciphertext = hex::decode(raw_value).ok()?;
    let plaintext = decrypt_abc_bytes(&ciphertext, key, nonce)?;
    Some(String::from_utf8_lossy(&plaintext).into_owned())
}

fn derive_dynamic_nonce(
    password: Option<&str>,
    hardware_id: Option<&str>,
    provider: Option<&str>,
    area: Option<&str>,
) -> [u8; 8] {
    // This prefix construction is retained as a named, auditable best-effort
    // rule. For the captured profile, the password begins with `https://`,
    // which exactly yields the observed nonce 68 74 74 70 73 3a 2f 2f.
    let only_hardware_id = hardware_id
        .filter(|value| !value.is_empty())
        .filter(|_| password.is_none() && provider.is_none() && area.is_none());
    let material = if let Some(hardware_id) = only_hardware_id {
        let mut material = hardware_id.as_bytes().to_vec();
        material.extend_from_slice(hardware_id.as_bytes());
        material
    } else {
        let mut material = Vec::new();
        for value in [password, hardware_id, provider, area]
            .into_iter()
            .flatten()
        {
            material.extend_from_slice(value.as_bytes());
        }
        material
    };

    let mut nonce = HcConstants::STATIC_NONCE;
    for (index, byte) in material.into_iter().take(nonce.len()).enumerate() {
        nonce[index] = byte;
    }
    nonce
}

fn decode_slot(raw_slot: &str, index: usize, dynamic_nonce: &[u8; 8]) -> Value {
    let mut value = raw_slot.to_owned();
    if is_hex_token(raw_slot)
        && let Some(decoded) =
            decode_abc_text(raw_slot, &HcConstants::CHACHA_KEYS[7], dynamic_nonce)
                .filter(|value| !value.is_empty())
    {
        value = decoded;
    }
    value = jkl_decrypt(&value);

    if index == 7 {
        value = process_credentials(&value, true);
    } else if index == 11 {
        value = process_credentials(&value, false);
    }

    if (value.starts_with('{') || value.starts_with('['))
        && let Ok(json_value) = serde_json::from_str::<Value>(&value)
    {
        return json_value;
    }
    Value::String(value)
}

fn is_hex_token(value: &str) -> bool {
    value.len() >= 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn jkl_decrypt(input: &str) -> String {
    if input.is_empty() {
        return input.to_owned();
    }
    let mut padded = input.to_owned();
    let remainder = padded.len() % 4;
    if remainder != 0 {
        padded.extend(std::iter::repeat_n('=', 4 - remainder));
    }
    let Ok(mut data) = base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()) else {
        return input.to_owned();
    };

    for (index, byte) in data.iter_mut().enumerate() {
        let key = HcConstants::JKL_KEY_OLD[index % HcConstants::JKL_KEY_OLD.len()];
        *byte = (((*byte ^ 0xff) & 0xca) | (*byte & 0x35)) ^ (((key ^ 0xff) & 0xca) | (key & 0x35));
    }
    let Ok(transformed_text) = std::str::from_utf8(&data) else {
        return input.to_owned();
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(transformed_text) else {
        return input.to_owned();
    };
    String::from_utf8(decoded).unwrap_or_else(|_| input.to_owned())
}

fn process_credentials(raw_value: &str, is_ssh: bool) -> String {
    if raw_value.is_empty() {
        return raw_value.to_owned();
    }

    let value = if is_ssh
        && raw_value
            .chars()
            .next()
            .is_some_and(|character| HcConstants::BRAILLE_ALPHABET.contains(character))
    {
        decode_braille(raw_value)
    } else {
        raw_value.to_owned()
    };

    if is_ssh {
        static SSH_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^([A-Za-z0-9_.-]+):([0-9-]+)@(.+):(.+)$")
                .expect("hardcoded HC SSH credential pattern must compile")
        });
        let Some(captures) = SSH_CREDENTIALS.captures(&value) else {
            return value;
        };
        let host = captures.get(1).map_or("", |match_| match_.as_str());
        let port = captures.get(2).map_or("", |match_| match_.as_str());
        let user = captures.get(3).map_or("", |match_| match_.as_str());
        let password = captures.get(4).map_or("", |match_| match_.as_str());
        let user_iv = Z3A_REGEX.find_iter(user).count();
        let password_iv = Z3A_REGEX.find_iter(password).count();
        let decoded_user = decode_z3a(user, user_iv);
        let decoded_password = decode_z3a(password, password_iv);
        let user = if decoded_user.is_empty() {
            user.to_owned()
        } else {
            decoded_user
        };
        let password = if decoded_password.is_empty() {
            password.to_owned()
        } else {
            decoded_password
        };
        return format!("{host}:{port}@{user}:{password}");
    }

    static CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([^:]+):(.+)$").expect("hardcoded HC credential pattern must compile")
    });
    let Some(captures) = CREDENTIALS.captures(&value) else {
        return value;
    };
    let user = captures.get(1).map_or("", |match_| match_.as_str());
    let password = captures.get(2).map_or("", |match_| match_.as_str());
    let decoded_user = decode_z3a(user, Z3A_REGEX.find_iter(user).count());
    let decoded_password = decode_z3a(password, Z3A_REGEX.find_iter(password).count());
    let user = if decoded_user.is_empty() {
        user.to_owned()
    } else {
        decoded_user
    };
    let password = if decoded_password.is_empty() {
        password.to_owned()
    } else {
        decoded_password
    };
    format!("{user}:{password}")
}

static Z3A_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(-?[0-9]+)\.(-?[0-9]+)")
        .expect("hardcoded HC numeric credential pattern must compile")
});

fn decode_z3a(value: &str, iv: usize) -> String {
    let iv = i128::try_from(iv).unwrap_or(i128::MAX);
    let mut output = Vec::new();
    for captures in Z3A_REGEX.captures_iter(value) {
        let Some(first) = captures
            .get(1)
            .and_then(|match_| match_.as_str().parse::<i128>().ok())
        else {
            continue;
        };
        let Some(second) = captures
            .get(2)
            .and_then(|match_| match_.as_str().parse::<i128>().ok())
        else {
            continue;
        };
        let exponent = second - iv;
        if !(0..=127).contains(&exponent) {
            continue;
        }
        let Ok(exponent) = u32::try_from(exponent) else {
            continue;
        };
        let Some(divisor) = 1_i128.checked_shl(exponent) else {
            continue;
        };
        let byte = first
            .checked_sub(iv)
            .map(|value| value.div_euclid(divisor).rem_euclid(256) as u8);
        if let Some(byte) = byte {
            output.push(byte);
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn decode_braille(value: &str) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.is_empty() {
        return value.to_owned();
    }
    let alphabet = HcConstants::BRAILLE_ALPHABET.chars().collect::<Vec<_>>();
    let mut decoded = Vec::with_capacity(chars.len() / 2);
    for pair in chars.chunks(2) {
        if pair.len() < 2 {
            break;
        }
        let Some(first) = alphabet.iter().position(|character| *character == pair[0]) else {
            return value.to_owned();
        };
        let Some(second) = alphabet.iter().position(|character| *character == pair[1]) else {
            return value.to_owned();
        };
        decoded.push(((first * 16 + second) & 0xff) as u8);
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}
