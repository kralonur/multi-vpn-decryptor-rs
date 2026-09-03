//! SSH Custom (`.ssc`) configuration decoding.
//!
//! The implementation is based on static analysis of the SSH Custom APK,
//! including its Dalvik/Dex2C paths and native libraries. The compact JSON
//! schema, hardcoded keys/nonces, nested lock, nonce construction, and field
//! cleanup rules below are recovered APK behavior rather than generic JSON or
//! cryptographic conventions.

use chacha20::ChaCha20Legacy;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hex_literal::hex;
use poly1305::{Poly1305, universal_hash::KeyInit};
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;
use subtle::ConstantTimeEq;
use thiserror::Error;
use wasm_bindgen::prelude::*;

mod fields {
    // These one- and two-letter names are the compact keys emitted by the APK.
    // The same compact schema is used for the outer object, nested lock, and
    // each profile entry.
    pub const CONFIGS: &str = "a";
    pub const USER_KEY: &str = "b";
    pub const EXPIRY_DATE: &str = "c";
    // In the nested-lock shape, the same compact `c` slot contains ciphertext.
    pub const NESTED_CIPHERTEXT: &str = EXPIRY_DATE;
    pub const CONFIG_NAME: &str = "e";
    pub const PAYLOAD_ENABLED: &str = "f";
    pub const PAYLOAD: &str = "g";
    pub const PROXY: &str = "h";
    pub const PROXY_PORT: &str = "i";
    pub const TUNNEL_TYPE: &str = "j";
    pub const PROXY_ENABLED: &str = "k";
    pub const SNI_OR_HOST: &str = "l";
    pub const PORT: &str = "m";
    pub const IS_PREMIUM: &str = "n";
    pub const USERNAME: &str = "o";
    pub const PASSWORD: &str = "p";
    pub const UDPGW_PORT: &str = "q";
    pub const PROTOCOL: &str = "r";
    pub const VERSION: &str = "s";
    pub const ENCRYPTION: &str = "t";
    pub const COMPRESSION: &str = "u";
    pub const DNS: &str = "v";
    pub const NS_SERVER: &str = "w";
    pub const PUBKEY: &str = "x";
    pub const IS_DEFAULT: &str = "y";
    pub const SSH_PORT: &str = "z";
    pub const HWID_LOCK: &str = "ab";
    pub const ROOT_LOCK: &str = "ac";
    pub const PLAYSTORE_LOCK: &str = "ad";
    pub const EXPIRY_LOCK: &str = "ae";
    pub const PASSWORD_LOCK: &str = "ag";

    // The APK applies the Layer 3 stream cipher only to these profile fields.
    pub const ENCRYPTED: &[&str] = &[
        PAYLOAD,
        SNI_OR_HOST,
        PROXY,
        PROXY_PORT,
        DNS,
        NS_SERVER,
        PUBKEY,
    ];
    pub const HOST_LIKE: &[&str] = &[SNI_OR_HOST, PROXY, PROXY_PORT, DNS, NS_SERVER, PUBKEY];
}

// The APK's output path maps compact keys to these descriptive labels. `b`
// is labeled NOTE because that is the APK schema name even though its value is
// also the 32-character material used to derive the Layer 3 nonce.
const KEY_MAP: &[(&str, &str)] = &[
    (fields::CONFIGS, "CONFIGS"),
    (fields::USER_KEY, "NOTE"),
    (fields::EXPIRY_DATE, "EXPIRY_DATE"),
    (fields::CONFIG_NAME, "CONFIG_NAME"),
    (fields::PAYLOAD_ENABLED, "PAYLOAD_ENABLED"),
    (fields::PAYLOAD, "PAYLOAD"),
    (fields::PROXY, "PROXY"),
    (fields::PROXY_PORT, "PROXY_PORT"),
    (fields::TUNNEL_TYPE, "TUNNEL_TYPE"),
    (fields::PROXY_ENABLED, "PROXY_ENABLED"),
    (fields::SNI_OR_HOST, "SNI_OR_HOST"),
    (fields::PORT, "PORT"),
    (fields::IS_PREMIUM, "IS_PREMIUM"),
    (fields::USERNAME, "USERNAME"),
    (fields::PASSWORD, "PASSWORD"),
    (fields::UDPGW_PORT, "UDPGW_PORT"),
    (fields::PROTOCOL, "PROTOCOL"),
    (fields::VERSION, "VERSION"),
    (fields::ENCRYPTION, "ENCRYPTION"),
    (fields::COMPRESSION, "COMPRESSION"),
    (fields::DNS, "DNS"),
    (fields::NS_SERVER, "NS_SERVER"),
    (fields::PUBKEY, "PUBKEY"),
    (fields::IS_DEFAULT, "IS_DEFAULT"),
    (fields::SSH_PORT, "SSH_PORT"),
    (fields::HWID_LOCK, "HWID_LOCK"),
    (fields::ROOT_LOCK, "ROOT_LOCK"),
    (fields::PLAYSTORE_LOCK, "PLAYSTORE_LOCK"),
    (fields::EXPIRY_LOCK, "EXPIRY_LOCK"),
    (fields::PASSWORD_LOCK, "PASSWORD_LOCK"),
];

struct SscConstants;

impl SscConstants {
    // APK finding: these values are hardcoded in the SSH Custom crypto paths.
    // `hex!` preserves the recovered hexadecimal bytes at compile time.
    const SCHEME: &str = "ssc://";
    // Fixed nonce and key used by the outer container AEAD.
    const FIXED_NONCE: [u8; 8] = hex!("74d0f3879f9d47f7");
    const L1_KEY: [u8; 32] =
        hex!("c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b");
    // Key used only when the outer JSON contains the optional nested lock.
    const L2_KEY: [u8; 32] =
        hex!("7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e");
    // Key used for per-profile fields after the container has been opened.
    const L3_KEY: [u8; 32] =
        hex!("d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e");

    // The APK derives the Layer 3 nonce from a 32-character hexadecimal user
    // key and starts its legacy ChaCha20 stream at block counter one.
    const USER_KEY_HEX_CHARS: usize = 32;
    // Nested locks take the first 16 hexadecimal characters from field `a`;
    // each pair is a byte, producing the 8-byte legacy nonce.
    const NESTED_NONCE_HEX_CHARS: usize = 16;
    // The APK attempts Layer 3 decryption only when an encoded field is longer
    // than this threshold.
    const INNER_FIELD_MIN_HEX_CHARS: usize = 16;
    // Original ChaCha20-Poly1305 appends a 16-byte Poly1305 tag.
    const AUTH_TAG_BYTES: usize = 16;
    // The original MAC appends two little-endian 64-bit lengths.
    const LENGTH_FIELD_BYTES: usize = 8;
    // The APK starts field encryption at legacy ChaCha20 block counter one.
    const STREAM_COUNTER: u64 = 1;
    // ChaCha20 emits 64 bytes per block.
    const CHACHA_BLOCK_BYTES: u64 = 64;
    // This literal is the cleanup marker emitted in decoded payload strings.
    const CRLF_MARKER: &str = "[crlf]";
    // Host-like fields are cleaned with the APK's domain/IPv4 matching rule.
    const HOST_PATTERN: &str = r"([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})";
}

#[derive(Debug, Error)]
pub enum SscError {
    #[error("SSC input is not valid UTF-8")]
    InvalidText,
    #[error("SSC input is empty")]
    EmptyInput,
    #[error("SSC input is not valid hexadecimal")]
    InvalidHex,
    #[error("SSC Layer 1 authenticated decryption failed")]
    Layer1Decryption,
    #[error("SSC Layer 1 payload is not a JSON object")]
    InvalidOuterJson,
}

/// Decrypt an SSH Custom `.ssc` file or an `ssc://` payload.
///
/// The APK format is decoded in three stages: an 8-byte-nonce legacy
/// ChaCha20-Poly1305 container, an optional nested lock using the same AEAD,
/// and per-profile legacy ChaCha20 field encryption. Set `remap_keys` to
/// convert compact APK keys such as `g` and `l` to descriptive labels.
pub fn decrypt_ssc_file(file_bytes: &[u8], remap_keys: bool) -> Result<Value, SscError> {
    let ciphertext = parse_ssc_input(file_bytes)?;
    let outer_plaintext = decrypt_original_aead(
        &ciphertext,
        &SscConstants::FIXED_NONCE,
        &SscConstants::L1_KEY,
    )
    .ok_or(SscError::Layer1Decryption)?;
    let outer_value = serde_json::from_slice::<Value>(&outer_plaintext)
        .map_err(|_| SscError::InvalidOuterJson)?;
    outer_value.as_object().ok_or(SscError::InvalidOuterJson)?;

    let mut target = decrypt_nested_layer(&outer_value).unwrap_or(outer_value);
    decrypt_inner_profiles(&mut target);

    Ok(if remap_keys {
        remap_json_keys(target)
    } else {
        target
    })
}

/// WASM-facing SSC decryptor returning the decoded configuration as a JS value.
#[wasm_bindgen]
pub fn decrypt_ssc(file_bytes: &[u8], remap_keys: bool) -> Result<JsValue, JsValue> {
    let value = decrypt_ssc_file(file_bytes, remap_keys)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&value).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn parse_ssc_input(file_bytes: &[u8]) -> Result<Vec<u8>, SscError> {
    let text = std::str::from_utf8(file_bytes)
        .map_err(|_| SscError::InvalidText)?
        .trim();
    if text.is_empty() {
        return Err(SscError::EmptyInput);
    }

    let normalized = text
        .strip_prefix(SscConstants::SCHEME)
        .map(|encoded| encoded.chars().rev().collect::<String>())
        .unwrap_or_else(|| text.to_owned());
    let compact = normalized
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.is_empty() {
        return Err(SscError::EmptyInput);
    }
    hex::decode(compact).map_err(|_| SscError::InvalidHex)
}

// A nested lock is signaled by an outer object whose `a` slot changes from
// the profile list to a nonce-bearing string and whose `c` slot carries the
// second AEAD ciphertext. Failed nested decryption intentionally falls back
// to the already-opened outer object.
fn decrypt_nested_layer(outer: &Value) -> Option<Value> {
    let object = outer.as_object()?;
    let nonce_text = object
        .get(fields::CONFIGS)
        .and_then(Value::as_str)
        .filter(|value| value.len() >= SscConstants::NESTED_NONCE_HEX_CHARS)?;
    let ciphertext_text = object
        .get(fields::NESTED_CIPHERTEXT)
        .and_then(Value::as_str)?;
    let nonce = decode_hex_array::<8>(nonce_text.get(..SscConstants::NESTED_NONCE_HEX_CHARS)?)?;
    let ciphertext = hex::decode(ciphertext_text).ok()?;
    let plaintext = decrypt_original_aead(&ciphertext, &nonce, &SscConstants::L2_KEY)?;
    let value = serde_json::from_slice::<Value>(&plaintext).ok()?;
    value.is_object().then_some(value)
}

// The APK calls the original 8-byte-nonce ChaCha20-Poly1305 construction.
// Its MAC input is `AD || LE64(AD length) || ciphertext || LE64(ciphertext
// length)`, with no RFC-style pad16 separators. The RustCrypto AEAD wrapper
// targets the newer 12-byte-nonce construction, so the matching construction
// is composed from the audited ChaCha20 and Poly1305 crates here.
fn decrypt_original_aead(
    ciphertext_and_tag: &[u8],
    nonce: &[u8; 8],
    key: &[u8; 32],
) -> Option<Vec<u8>> {
    let tag_start = ciphertext_and_tag
        .len()
        .checked_sub(SscConstants::AUTH_TAG_BYTES)?;
    let (ciphertext, expected_tag) = ciphertext_and_tag.split_at(tag_start);
    let mut poly1305_key = [0u8; 32];
    let mut key_stream = ChaCha20Legacy::new_from_slices(key, nonce).ok()?;
    key_stream.try_apply_keystream(&mut poly1305_key).ok()?;

    let ciphertext_length = u64::try_from(ciphertext.len()).ok()?;
    let mac_capacity = ciphertext
        .len()
        .checked_add(2 * SscConstants::LENGTH_FIELD_BYTES)?;
    let mut mac_input = Vec::with_capacity(mac_capacity);
    mac_input.extend_from_slice(&0u64.to_le_bytes());
    mac_input.extend_from_slice(ciphertext);
    mac_input.extend_from_slice(&ciphertext_length.to_le_bytes());
    let poly1305_key = poly1305::Key::from(poly1305_key);
    // `compute_unpadded` preserves the original construction's single
    // Poly1305 stream; zero-padding the concatenated input would change the
    // position of Poly1305's implicit final `1` bit.
    let authenticator = Poly1305::new(&poly1305_key);
    let calculated_tag = authenticator.compute_unpadded(&mac_input);
    bool::from(calculated_tag.as_slice().ct_eq(expected_tag)).then_some(())?;

    let mut plaintext = ciphertext.to_vec();
    let mut cipher = ChaCha20Legacy::new_from_slices(key, nonce).ok()?;
    cipher
        .try_seek(SscConstants::STREAM_COUNTER * SscConstants::CHACHA_BLOCK_BYTES)
        .ok()?;
    cipher.try_apply_keystream(&mut plaintext).ok()?;
    Some(plaintext)
}

fn decrypt_inner_profiles(target: &mut Value) {
    let Some(configs) = target
        .get_mut(fields::CONFIGS)
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for config in configs {
        decrypt_inner_profile(config);
    }
}

fn decrypt_inner_profile(config: &mut Value) {
    let Some(object) = config.as_object_mut() else {
        return;
    };
    let Some(user_key) = object.get(fields::USER_KEY).and_then(Value::as_str) else {
        return;
    };
    let Some(nonce) = derive_inner_nonce(user_key) else {
        return;
    };

    let replacements = fields::ENCRYPTED
        .iter()
        .filter_map(|field| {
            object
                .get(*field)
                .and_then(Value::as_str)
                .filter(|value| value.len() > SscConstants::INNER_FIELD_MIN_HEX_CHARS)
                .and_then(|value| decrypt_inner_field(value, field, &nonce))
                .map(|value| ((*field).to_owned(), Value::String(value)))
        })
        .collect::<Vec<_>>();

    for (field, value) in replacements {
        object.insert(field, value);
    }
}

// The APK expression is:
// hex_decode(reverse(user_key[16..32]) + "68" + user_key[0..16])[..8].
// The full expression is retained here even though truncation means the
// returned nonce consists of the reversed second half's eight decoded bytes.
fn derive_inner_nonce(user_key: &str) -> Option<[u8; 8]> {
    if user_key.len() != SscConstants::USER_KEY_HEX_CHARS {
        return None;
    }
    let prefix = user_key.get(..16)?;
    let suffix = user_key.get(16..SscConstants::USER_KEY_HEX_CHARS)?;
    let derived_hex = suffix
        .chars()
        .rev()
        .chain("68".chars())
        .chain(prefix.chars())
        .collect::<String>();
    let decoded = hex::decode(derived_hex).ok()?;
    decoded.get(..8)?.try_into().ok()
}

// Layer 3 uses the APK's hardcoded key, the derived 8-byte nonce, and the
// legacy ChaCha20 stream beginning at block counter one.
fn decrypt_inner_field(raw_value: &str, field: &str, nonce: &[u8; 8]) -> Option<String> {
    let mut ciphertext = hex::decode(raw_value).ok()?;
    let mut cipher = ChaCha20Legacy::new_from_slices(&SscConstants::L3_KEY, nonce).ok()?;
    cipher
        .try_seek(SscConstants::STREAM_COUNTER * SscConstants::CHACHA_BLOCK_BYTES)
        .ok()?;
    cipher.try_apply_keystream(&mut ciphertext).ok()?;

    let raw_text = ciphertext
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    let text = String::from_utf8_lossy(raw_text).into_owned();
    Some(clean_inner_field(text, field))
}

fn clean_inner_field(mut value: String, field: &str) -> String {
    if let Some(last_marker) = value.rfind(SscConstants::CRLF_MARKER) {
        value.truncate(last_marker + SscConstants::CRLF_MARKER.len());
    } else if fields::HOST_LIKE.contains(&field) {
        value = extract_host_like(&value);
    }
    value
}

fn extract_host_like(value: &str) -> String {
    static HOST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(SscConstants::HOST_PATTERN)
            .expect("the hardcoded SSC host pattern must be valid")
    });

    HOST_REGEX
        .find(value)
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_else(|| {
            value
                .chars()
                .filter(|character| character.is_alphanumeric() || ".-_".contains(*character))
                .collect()
        })
}

fn remap_json_keys(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let existing_keys = object
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>();
            let remapped = object
                .into_iter()
                .map(|(key, value)| {
                    let descriptive_key = remap_key(&key).to_owned();
                    let output_key =
                        if descriptive_key != key && !existing_keys.contains(&descriptive_key) {
                            descriptive_key
                        } else {
                            key
                        };
                    (output_key, remap_json_keys(value))
                })
                .collect::<Map<_, _>>();
            Value::Object(remapped)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(remap_json_keys).collect()),
        value => value,
    }
}

fn remap_key(key: &str) -> &str {
    KEY_MAP
        .iter()
        .find(|(compact, _)| *compact == key)
        .map_or(key, |(_, descriptive)| descriptive)
}

fn decode_hex_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    hex::decode(input).ok()?.try_into().ok()
}
