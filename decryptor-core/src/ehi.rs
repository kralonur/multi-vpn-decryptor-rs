//! HTTP Injector (`.ehi`) decoding for the library and WASM API.
//!
//! Protocol provenance comes from static analysis of HTTP Injector v6.5.0:
//! Dalvik bytecode and native libraries expose the layer order, hardcoded
//! constants, field names, byte ranges, and fallback behavior. Comments below
//! distinguish values recovered from the APK from standard primitive
//! parameters.

use aes::{Aes128, Aes256};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{
    Engine as _,
    alphabet::Alphabet,
    engine::general_purpose::{GeneralPurpose, PAD_INDIFFERENT, STANDARD},
};
use cbc::Decryptor;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use cipher::{
    BlockModeDecrypt, KeyIvInit,
    block_padding::{NoPadding, Padding, Pkcs7},
};
use hex_literal::hex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wasm_bindgen::prelude::*;

mod config_fields {
    // These names and their grouping were recovered from the APK's lock-key
    // construction and post-decryption field-processing paths.
    pub const AES_KEY: &str = "configAesKey";
    pub const IDENTIFIER: &str = "configIdentifier";
    pub const SALT: &str = "configSalt";
    pub const TIMESTAMP: &str = "configTimestamp";
    pub const EXPIRY_TIMESTAMP: &str = "configExpiryTimestamp";
    pub const LOCK_MODES: &str = "lockModes";
    pub const LOCK_MODES_HASH: &str = "lockModesHash";
    pub const HWID: &str = "configHwid";
    pub const MOBILE_OPERATOR_ID: &str = "configLockMobileOperatorId";
    pub const DATA: &str = "configData";
    pub const MESSAGE: &str = "configMessage";
    pub const RAW_JSON: &str = "v2rRawJson";
    pub const OVERWRITE_SERVER_DATA: &str = "overwriteServerData";

    // The APK concatenates these fields in this order and includes optional
    // entries only when its value-presence check considers them non-empty.
    pub const MASTER_KEY_OPTIONAL: &[&str] = &[AES_KEY, IDENTIFIER, SALT];
    pub const MASTER_KEY_TIMESTAMPS: &[&str] = &[TIMESTAMP, EXPIRY_TIMESTAMP];
    pub const MASTER_KEY_LOCK_FIELDS: &[&str] =
        &[LOCK_MODES, LOCK_MODES_HASH, HWID, MOBILE_OPERATOR_ID];

    // These names come from the APK's post-decryption field-processing paths,
    // not from a generic JSON convention.
    pub const EMBEDDED_JSON: &[&str] = &[RAW_JSON, OVERWRITE_SERVER_DATA];
    pub const REDACTED: &[&str] = &["password", "v2rUserId", "shadowsocksPassword", "sshKey"];
    pub const REDACTED_VALUE: &str = "[REDACTED]";
}

mod file_layout {
    // APK finding: the container reader consumes two big-endian length bytes,
    // skips 8 bytes, repeats that pair, then consumes a big-endian u32 length
    // and skips another 8 bytes before the encrypted payload.
    pub const UTF_LENGTH_BYTES: usize = 2;
    pub const U32_BYTES: usize = 4;
    pub const HEADER_GAP_BYTES: usize = 8;
}

// APK finding: both the lock decoder and inner-field decoder use `EVZJNI`
// when `configSalt` is absent.
const DEFAULT_SALT: &str = "EVZJNI";

// APK finding: a missing timestamp contributes integer zero, converted to
// text before master-secret concatenation.
const DEFAULT_TIMESTAMP: &str = "0";

// These spellings preserve the APK's string conversion for JSON values used
// in master-secret material; falsey optional values are filtered separately.
const NULL_KEY_MATERIAL: &str = "None";
const TRUE_KEY_MATERIAL: &str = "True";
const FALSE_KEY_MATERIAL: &str = "False";

// APK finding: the decrypted Layer 1 text is colon-separated; the first
// segment is the Layer 2 IV and the third segment is the Layer 2 ciphertext.
const OUTER_SEPARATOR: char = ':';

// APK finding: `configMessage` uses Java-char XOR with the literal key
// `EHIMSG`. The source is kept as bytes; each ASCII byte is widened to a
// UTF-16 code unit at the XOR site.
const MESSAGE_XOR_KEY: &[u8] = b"EHIMSG";

// APK finding: this is a recovered EHI alphabet, not a generated or standard
// Base64 value. The APK maps each symbol by position to the standard alphabet;
// the Rust Base64 engine uses the recovered alphabet directly.
const EHI_BASE64_ALPHABET_TEXT: &str =
    "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs";
const CUSTOM_ALPHABET: Alphabet = match Alphabet::new(EHI_BASE64_ALPHABET_TEXT) {
    Ok(alphabet) => alphabet,
    Err(_) => panic!("invalid EHI base64 alphabet"),
};
const CUSTOM_BASE64: GeneralPurpose = GeneralPurpose::new(&CUSTOM_ALPHABET, PAD_INDIFFERENT);

// These sizes are either standard primitive properties or APK payload
// values: AES blocks are 16 bytes, XXTEA words are 4 bytes, the Argon2
// output is 32 bytes, and XChaCha20 nonces are 24 bytes.
const AES_BLOCK_BYTES: usize = 16;
const XXTEA_WORD_BYTES: usize = 4;
const HASH_BYTES: usize = 32;
const XCHACHA_NONCE_BYTES: usize = 24;

// Resource limits prevent crafted profiles from exhausting a native process
// or browser tab before the locked payload can be authenticated. These bounds
// accommodate the 64 MiB/low-single-digit parameters used by observed mobile
// profiles while rejecting unreasonable work factors.
const MAX_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const MAX_ARGON2_TIME_COST: u32 = 8;
const MAX_ARGON2_PARALLELISM: u32 = 8;

#[derive(Clone, Copy)]
enum ContainerMode {
    Bypass,
    Locked,
}

#[derive(Clone, Copy)]
struct OuterIv {
    mode: ContainerMode,
    value: [u8; AES_BLOCK_BYTES],
}

struct EhiConstants;

impl EhiConstants {
    // APK finding: this hardcoded Layer 1 AES-256 key was recovered as hex
    // from the APK's crypto path. `hex!` turns that representation into the
    // same bytes at compile time.
    const L1_KEY: [u8; 32] =
        hex!("7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c");

    // APK finding: this hardcoded Layer 2 AES-128 key was recovered from the
    // APK's crypto path and represented as a compile-time hex literal.
    const L2_KEY: [u8; 16] = hex!("b2bc617c32d8b9eb1943a5ffa8051eea");

    // APK finding: this exact XXTEA key includes a trailing NUL. The string
    // literal therefore supplies the same UTF-8 byte sequence to the crate.
    const XXTEA_KEY: &str = "null=V5kU5+FFrY\0";

    // APK finding: the crypto path tries six hardcoded IVs. The first three
    // are the bypass set and the last three are the locked-profile set; this
    // order follows the APK's candidate table. Each `hex!` literal is the
    // byte sequence represented by the recovered hex constant.
    const OUTER_IVS: [OuterIv; 6] = [
        OuterIv {
            mode: ContainerMode::Bypass,
            value: hex!("221d572349555f1d112133236b1f4a3f"),
        },
        OuterIv {
            mode: ContainerMode::Bypass,
            value: hex!("5543494c53443e3f4a6a4539384e776a"),
        },
        OuterIv {
            mode: ContainerMode::Bypass,
            value: hex!("374c2541575e4d531a3c327b75431e5f"),
        },
        OuterIv {
            mode: ContainerMode::Locked,
            value: hex!("2c5d1147bbad422b3b334d4d235f1a53"),
        },
        OuterIv {
            mode: ContainerMode::Locked,
            value: hex!("522b01433a5e8b2fc7549e1ad368e541"),
        },
        OuterIv {
            mode: ContainerMode::Locked,
            value: hex!("337a1035aaedf3458ca167e92d74b839"),
        },
    ];
}

#[derive(Debug, Error)]
pub enum EhiError {
    #[error("invalid EHI file header or structure")]
    InvalidFile,
    #[error("could not decrypt the EHI outer AES/XXTEA container")]
    OuterContainer,
    #[error("locked EHI profile does not contain configData")]
    MissingConfigData,
    #[error("could not decrypt the locked EHI outer XOR layer")]
    OuterXor,
    #[error("invalid locked EHI payload")]
    InvalidLockedPayload,
    #[error("Argon2id parameters exceed safe resource limits")]
    KeyDerivationLimit,
    #[error("invalid Argon2id parameters or key derivation failure")]
    KeyDerivation,
    #[error("XChaCha20-Poly1305 authentication failed")]
    AuthenticatedDecryption,
    #[error("decrypted EHI configuration is not an object")]
    InvalidConfiguration,
}

/// Decrypt an HTTP Injector `.ehi` profile into its configuration object.
///
/// The APK's layer order is: file framing, six-candidate AES-256-CBC,
/// colon-split AES-128-CBC, XXTEA, optional locked-profile
/// Argon2id/XChaCha20-Poly1305, then inner-field decoding.
pub fn decrypt_ehi_file(file_bytes: &[u8], redact_secrets: bool) -> Result<Value, EhiError> {
    let payload = parse_file_payload(file_bytes).ok_or(EhiError::InvalidFile)?;
    if payload.is_empty() {
        return Err(EhiError::InvalidFile);
    }

    let (outer_config, mode) = decrypt_outer_container(payload)?;
    let salt = outer_config
        .get(config_fields::SALT)
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_SALT)
        .to_owned();
    let decoded_config = match mode {
        ContainerMode::Bypass => outer_config,
        ContainerMode::Locked => decrypt_locked_config(&outer_config)?,
    };

    let cleaned = clean_configuration(decoded_config, &salt, redact_secrets);
    Ok(Value::Object(cleaned))
}

/// WASM-facing EHI decryptor returning the decoded configuration as a JS value.
#[wasm_bindgen]
pub fn decrypt_ehi(file_bytes: &[u8], redact_secrets: bool) -> Result<JsValue, JsValue> {
    let value = decrypt_ehi_file(file_bytes, redact_secrets)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&value).map_err(|error| JsValue::from_str(&error.to_string()))
}

// APK finding: Layer 1 has six hardcoded IV candidates rather than a per-file
// IV. A candidate is accepted only when all later decrypt/parse steps produce
// a non-empty JSON object; the candidate group supplies the profile mode.
fn decrypt_outer_container(
    payload: &[u8],
) -> Result<(Map<String, Value>, ContainerMode), EhiError> {
    EhiConstants::OUTER_IVS
        .into_iter()
        .find_map(|candidate| decrypt_outer_candidate(payload, candidate))
        .ok_or(EhiError::OuterContainer)
}

// APK finding: this candidate path is AES-256-CBC, colon split, Base64
// IV/AES-128-CBC, and XXTEA. Every `?` below is a format validation failure,
// not an alternate decryption path.
fn decrypt_outer_candidate(
    payload: &[u8],
    candidate: OuterIv,
) -> Option<(Map<String, Value>, ContainerMode)> {
    let first_layer = decrypt_aes_cbc(payload, &EhiConstants::L1_KEY, &candidate.value)?;
    let first_text = String::from_utf8(first_layer).ok()?;
    let (inner_iv_text, inner_ciphertext_text) = split_outer_layer(&first_text)?;
    let inner_iv = decode_base64_array::<AES_BLOCK_BYTES>(inner_iv_text)?;
    let inner_ciphertext = decode_base64(inner_ciphertext_text).ok()?;
    let second_layer = decrypt_aes_cbc(&inner_ciphertext, &EhiConstants::L2_KEY, &inner_iv)?;
    let final_layer = decrypt_xxtea_payload(&second_layer, EhiConstants::XXTEA_KEY)?;
    let json_start = final_layer.iter().position(|byte| *byte == b'{')?;
    let value = serde_json::from_slice::<Value>(&final_layer[json_start..]).ok()?;
    let config = value.as_object().filter(|config| !config.is_empty())?;

    Some((config.clone(), candidate.mode))
}

// APK finding: locked profiles continue with salt-based XOR/Base64 decoding,
// dynamic Argon2id, and authenticated XChaCha20-Poly1305 using the payload
// header's associated data and nonce.
fn decrypt_locked_config(config: &Map<String, Value>) -> Result<Map<String, Value>, EhiError> {
    let salt = config
        .get(config_fields::SALT)
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_SALT);
    let encoded_data = config
        .get(config_fields::DATA)
        .and_then(Value::as_str)
        .filter(|data| !data.is_empty())
        .ok_or(EhiError::MissingConfigData)?;
    let xor_data = decrypt_xor_layer(encoded_data, salt).ok_or(EhiError::OuterXor)?;
    let raw_payload = decode_base64(&xor_data).map_err(|_| EhiError::InvalidLockedPayload)?;
    let locked_payload = LockedPayload::parse(&raw_payload)?;
    locked_payload.validate_work_factors()?;

    // APK payload mapping: `time_cost` is the iteration count,
    // `memory_cost` is measured in KiB, `parallelism` is the lane count, and
    // the derived key length is 32 bytes.
    let params = Params::new(
        locked_payload.memory_cost,
        locked_payload.time_cost,
        locked_payload.parallelism,
        Some(HASH_BYTES),
    )
    .map_err(|_| EhiError::KeyDerivation)?;
    // APK finding: the lock path selects Argon2id version 0x13.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let master_key = derive_master_key(config);
    let mut encryption_key = [0u8; HASH_BYTES];
    argon2
        .hash_password_into(&master_key, locked_payload.salt, &mut encryption_key)
        .map_err(|_| EhiError::KeyDerivation)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&encryption_key)
        .map_err(|_| EhiError::AuthenticatedDecryption)?;
    let nonce = XNonce::from(locked_payload.nonce);
    // The payload's pre-nonce header bytes are authenticated as associated
    // data, matching libsodium's `ad_bytes = raw_payload[:0x1a]` call.
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: locked_payload.ciphertext,
                aad: locked_payload.associated_data,
            },
        )
        .map_err(|_| EhiError::AuthenticatedDecryption)?;
    let value =
        serde_json::from_slice::<Value>(&plaintext).map_err(|_| EhiError::InvalidConfiguration)?;
    value
        .as_object()
        .cloned()
        .ok_or(EhiError::InvalidConfiguration)
}

fn clean_configuration(
    config: Map<String, Value>,
    salt: &str,
    redact_secrets: bool,
) -> Map<String, Value> {
    let mut cleaned = config
        .into_iter()
        .map(|(field, value)| {
            let decoded = decode_field(&field, value, salt);
            (field, decoded)
        })
        .collect::<Map<_, _>>();

    decode_embedded_json(&mut cleaned);
    if redact_secrets {
        redact_secret_fields(&mut cleaned);
    }
    cleaned
}

// APK finding: `configMessage` uses the Java-char transform. Every other
// non-empty string uses the recovered custom Base64/salt-XOR layer; values
// that do not decode are retained as stored.
fn decode_field(field: &str, value: Value, salt: &str) -> Value {
    match value {
        Value::String(text) if !text.trim().is_empty() && field == config_fields::MESSAGE => {
            Value::String(decode_message(&text))
        }
        Value::String(text) if !text.trim().is_empty() => decrypt_xor_layer(&text, salt)
            .map(Value::String)
            .unwrap_or(Value::String(text)),
        value => value,
    }
}

// APK finding: `v2rRawJson` and `overwriteServerData` are the two named
// fields scanned for an outer `{...}` JSON object after field decoding.
fn decode_embedded_json(config: &mut Map<String, Value>) {
    let replacements = config_fields::EMBEDDED_JSON
        .iter()
        .filter_map(|field| {
            config
                .get(*field)
                .and_then(Value::as_str)
                .and_then(extract_embedded_json)
                .map(|value| ((*field).to_owned(), value))
        })
        .collect::<Vec<_>>();

    for (field, value) in replacements {
        config.insert(field, value);
    }
}

fn extract_embedded_json(raw: &str) -> Option<Value> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    let json_text = raw.get(start..=end)?;
    serde_json::from_str(json_text).ok()
}

// These four names and the `[REDACTED]` replacement come from the APK's
// output-cleanup path; redaction is intentionally not recursive.
fn redact_secret_fields(config: &mut Map<String, Value>) {
    for field in config_fields::REDACTED {
        if let Some(value) = config
            .get_mut(*field)
            .filter(|value| value_has_content(value))
        {
            *value = Value::String(config_fields::REDACTED_VALUE.to_owned());
        }
    }
}

/// Decode `configMessage` using the APK's Java-char transform:
/// standard Base64, UTF-8 text, UTF-16 code units, and a repeating `EHIMSG`
/// XOR key. The key bytes are widened to `u16` because Java `char` is 16-bit.
fn decode_message(encoded: &str) -> String {
    let Ok(raw_bytes) = decode_base64(encoded) else {
        return encoded.to_owned();
    };
    let decoded = String::from_utf8_lossy(&raw_bytes)
        .encode_utf16()
        .enumerate()
        .map(|(index, code_unit)| {
            code_unit ^ u16::from(MESSAGE_XOR_KEY[index % MESSAGE_XOR_KEY.len()])
        })
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&decoded)
}

/// Decode the EHI field transform recovered from the APK's string-decoder
/// path:
/// reverse text -> remove `?` placeholders -> custom-Base64 decode -> ASCII
/// hex -> optional leading nibble -> repeating salt-byte XOR -> UTF-8.
fn decrypt_xor_layer(encoded: &str, key: &str) -> Option<String> {
    if encoded.trim().is_empty() {
        return Some(encoded.to_owned());
    }
    if key.is_empty() {
        return None;
    }

    let reversed = encoded.chars().rev().collect::<String>();
    let decoded = decode_custom_base64(&reversed)?;
    let mut hex_text = String::from_utf8(decoded).ok()?;
    if hex_text.len() % 2 != 0 {
        hex_text.insert(0, '0');
    }
    let ciphertext = hex::decode(hex_text).ok()?;
    let key_bytes = key.as_bytes();
    let plaintext = ciphertext
        .into_iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key_bytes[index % key_bytes.len()])
        .filter(|byte| *byte != 0)
        .collect::<Vec<_>>();
    String::from_utf8(plaintext).ok()
}

// APK finding: standard Base64 carries the Layer 2 IV/ciphertext and locked
// payload. The decoder accepts unpadded strings, so missing padding is restored
// before invoking the standard Base64 engine.
fn decode_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let mut clean = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(char::from)
        .collect::<String>();
    let padding = (4 - clean.len() % 4) % 4;
    clean.extend(std::iter::repeat_n('=', padding));
    STANDARD.decode(clean)
}

// APK finding: `?` is a placeholder removed before custom-Base64 decoding;
// the recovered alphabet performs the position mapping and PAD_INDIFFERENT
// accepts either padded or unpadded input.
fn decode_custom_base64(input: &str) -> Option<Vec<u8>> {
    let clean = input
        .bytes()
        .filter(|byte| *byte != b'?' && !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    CUSTOM_BASE64.decode(clean).ok()
}

fn decode_base64_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    decode_base64(input).ok()?.try_into().ok()
}

// The APK requires at least three colon-separated parts and uses the first
// as the Layer 2 IV and the third as its ciphertext. `split_once` expresses
// that selection without allocating a vector.
fn split_outer_layer(text: &str) -> Option<(&str, &str)> {
    let mut segments = text.split(OUTER_SEPARATOR);
    let inner_iv = segments.next()?;
    segments.next()?;
    let inner_ciphertext = segments.next()?;
    Some((inner_iv, inner_ciphertext))
}

/// Decrypt the raw XXTEA layer recovered from the APK. The crate supplies the
/// standard rounds and word padding; EHI then stores its logical byte length in
/// the final word, falling back to zero trimming when that length is invalid.
fn decrypt_xxtea_payload(data: &[u8], key: &str) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(Vec::new());
    }

    // XXTEA is provided by the crate; only EHI's trailing length convention is format-specific.
    let encrypted = data.to_vec();
    let mut plaintext = xxtea::decrypt_raw(&encrypted, key);
    let length_offset = plaintext.len().checked_sub(XXTEA_WORD_BYTES)?;
    let length_bytes: [u8; XXTEA_WORD_BYTES] = plaintext.get(length_offset..)?.try_into().ok()?;
    let decoded_length = u32::from_le_bytes(length_bytes) as usize;

    match (1..=plaintext.len()).contains(&decoded_length) {
        true => plaintext.truncate(decoded_length),
        false => plaintext.truncate(
            plaintext
                .iter()
                .rposition(|byte| *byte != 0)
                .map_or(0, |index| index + 1),
        ),
    }
    Some(plaintext)
}

/// Read the length-prefixed EHI container recovered from the APK. The three
/// eight-byte gaps are container metadata that the crypto path skips rather
/// than decrypts.
fn parse_file_payload(file_bytes: &[u8]) -> Option<&[u8]> {
    let mut remaining = file_bytes;
    skip_utf(&mut remaining)?;
    take_bytes(&mut remaining, file_layout::HEADER_GAP_BYTES)?;
    skip_utf(&mut remaining)?;
    take_bytes(&mut remaining, file_layout::HEADER_GAP_BYTES)?;
    let payload_length = usize::try_from(read_be_u32(&mut remaining)?).ok()?;
    take_bytes(&mut remaining, file_layout::HEADER_GAP_BYTES)?;
    take_bytes(&mut remaining, payload_length)
}

// The APK labels these as UTF fields, but only their length-prefixed byte
// spans matter to decryption; their contents are skipped.
fn skip_utf(input: &mut &[u8]) -> Option<()> {
    let length = usize::from(read_be_u16(input)?);
    take_bytes(input, length)?;
    Some(())
}

fn take_bytes<'a>(input: &mut &'a [u8], amount: usize) -> Option<&'a [u8]> {
    let taken = input.get(..amount)?;
    *input = input.get(amount..)?;
    Some(taken)
}

fn read_be_u16(input: &mut &[u8]) -> Option<u16> {
    let bytes = take_bytes(input, file_layout::UTF_LENGTH_BYTES)?
        .try_into()
        .ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_be_u32(input: &mut &[u8]) -> Option<u32> {
    let bytes = take_bytes(input, file_layout::U32_BYTES)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// Borrowed view of the advanced-lock payload header. Every offset below is
/// a direct translation of the APK's byte reads:
/// `[1..5]`, `[5..9]`, `[9]`, `[0x0a..0x1a]`, `[0x1a..0x32]`, and
/// `[0x32..]`.
#[derive(Clone, Copy)]
struct LockedPayload<'a> {
    salt: &'a [u8],
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    nonce: [u8; XCHACHA_NONCE_BYTES],
    associated_data: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> LockedPayload<'a> {
    // 0x32 = 26 bytes of associated data + 24-byte XChaCha nonce, as laid
    // out in the APK's locked-payload layout.
    const HEADER_BYTES: usize = 0x32;
    // Argon2id parameters are little-endian/dynamic in the payload header.
    const TIME_COST_OFFSET: usize = 1;
    const MEMORY_COST_OFFSET: usize = 5;
    const PARALLELISM_OFFSET: usize = 9;
    // The header carries a 16-byte Argon2 salt from 0x0a through 0x1a.
    const SALT_START: usize = 0x0a;
    const SALT_END: usize = 0x1a;
    // The following 24 bytes are the XChaCha20-Poly1305 nonce.
    const NONCE_START: usize = 0x1a;
    const NONCE_END: usize = 0x32;
    // Libsodium authenticates the bytes before the nonce as associated data.
    const ASSOCIATED_DATA_END: usize = 0x1a;

    fn parse(raw: &'a [u8]) -> Result<Self, EhiError> {
        let header = raw
            .get(..Self::HEADER_BYTES)
            .ok_or(EhiError::InvalidLockedPayload)?;
        let time_cost =
            read_le_u32(&header[Self::TIME_COST_OFFSET..]).ok_or(EhiError::InvalidLockedPayload)?;
        let memory_cost = read_le_u32(&header[Self::MEMORY_COST_OFFSET..])
            .ok_or(EhiError::InvalidLockedPayload)?;
        let parallelism = u32::from(header[Self::PARALLELISM_OFFSET]);
        let nonce = header[Self::NONCE_START..Self::NONCE_END]
            .try_into()
            .map_err(|_| EhiError::InvalidLockedPayload)?;

        Ok(Self {
            salt: &header[Self::SALT_START..Self::SALT_END],
            time_cost,
            memory_cost,
            parallelism,
            nonce,
            associated_data: &header[..Self::ASSOCIATED_DATA_END],
            ciphertext: &raw[Self::HEADER_BYTES..],
        })
    }

    fn validate_work_factors(&self) -> Result<(), EhiError> {
        if self.memory_cost > MAX_ARGON2_MEMORY_KIB
            || self.time_cost > MAX_ARGON2_TIME_COST
            || self.parallelism > MAX_ARGON2_PARALLELISM
        {
            return Err(EhiError::KeyDerivationLimit);
        }
        Ok(())
    }
}

// APK finding: advanced-lock parameter fields are little-endian, unlike the
// big-endian outer file-header lengths.
fn read_le_u32(bytes: &[u8]) -> Option<u32> {
    let bytes: [u8; file_layout::U32_BYTES] =
        bytes.get(..file_layout::U32_BYTES)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Build the locked-profile master secret from the field order recovered in
/// the APK's lock-key path. Optional values are omitted using the APK's
/// presence rules; SHA-256 then reduces the concatenated text to 32 bytes.
fn derive_master_key(config: &Map<String, Value>) -> [u8; 32] {
    let mut material = String::new();
    append_optional_key_material(config, config_fields::MASTER_KEY_OPTIONAL, &mut material);
    append_timestamp_key_material(config, &mut material);
    append_optional_key_material(config, config_fields::MASTER_KEY_LOCK_FIELDS, &mut material);
    Sha256::digest(material.as_bytes()).into()
}

fn append_optional_key_material(
    config: &Map<String, Value>,
    fields: &[&str],
    material: &mut String,
) {
    for field in fields {
        if let Some(value) = config.get(*field).filter(|value| value_has_content(value)) {
            material.push_str(&value_to_key_material(value));
        }
    }
}

fn append_timestamp_key_material(config: &Map<String, Value>, material: &mut String) {
    for field in config_fields::MASTER_KEY_TIMESTAMPS {
        let value = config
            .get(*field)
            .map(value_to_key_material)
            .unwrap_or_else(|| DEFAULT_TIMESTAMP.to_owned());
        if !value.is_empty() {
            material.push_str(&value);
        }
    }
}

// This is deliberately not general JSON serialization: it reproduces the
// APK's string spellings used during master-key generation.
fn value_to_key_material(value: &Value) -> String {
    match value {
        Value::Null => NULL_KEY_MATERIAL.to_owned(),
        Value::Bool(true) => TRUE_KEY_MATERIAL.to_owned(),
        Value::Bool(false) => FALSE_KEY_MATERIAL.to_owned(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

// Mirror the APK's value-presence rules for conditional master-secret fields
// and the optional secret-redaction pass.
fn value_has_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_i64()
            .map(|value| value != 0)
            .or_else(|| value.as_u64().map(|value| value != 0))
            .or_else(|| value.as_f64().map(|value| value != 0.0))
            .unwrap_or(true),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

/// Decrypt one EHI CBC layer. APK analysis assigns AES-256-CBC to Layer 1 and
/// AES-128-CBC to Layer 2. EHI's compatibility unpadding is applied after the
/// cipher because malformed padding is retained by the APK's compatibility path.
fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8; AES_BLOCK_BYTES]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(AES_BLOCK_BYTES) {
        return None;
    }

    let mut buffer = ciphertext.to_vec();
    let plaintext = match key.len() {
        16 => Decryptor::<Aes128>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded::<NoPadding>(&mut buffer)
            .ok()?,
        32 => Decryptor::<Aes256>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded::<NoPadding>(&mut buffer)
            .ok()?,
        _ => return None,
    };
    Some(remove_pkcs7_padding(plaintext))
}

// Use the crate's strict PKCS#7 validator on the final AES block, while
// preserving the EHI behavior of returning the original bytes when padding is
// malformed.
fn remove_pkcs7_padding(data: &[u8]) -> Vec<u8> {
    let Some(last_block_start) = data.len().checked_sub(AES_BLOCK_BYTES) else {
        return data.to_vec();
    };
    let Some(last_block) = data.get(last_block_start..) else {
        return data.to_vec();
    };
    let Ok(unpadded_last_block) = Pkcs7::raw_unpad(last_block) else {
        return data.to_vec();
    };

    let mut unpadded = Vec::with_capacity(last_block_start + unpadded_last_block.len());
    unpadded.extend_from_slice(&data[..last_block_start]);
    unpadded.extend_from_slice(unpadded_last_block);
    unpadded
}
