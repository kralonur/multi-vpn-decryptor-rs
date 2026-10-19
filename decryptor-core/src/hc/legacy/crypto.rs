//! Legacy outer/slot stream cipher and nonce construction.

use crate::hc::HcError;
use chacha20::ChaCha20Legacy;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hex_literal::hex;
use serde_json::Value;

pub(super) const STREAM_COUNTER: u64 = 1;
pub(super) const CHACHA_BLOCK_BYTES: u64 = 64;
const AUTH_TAG_BYTES: usize = 16;

// The file's Unicode obfuscation key, recovered from the version 810
// outer path. It is applied to the byte value of every UTF-8 character,
// not to the original UTF-8 byte sequence.
pub(super) const OUTER_XOR_KEY: [u8; 11] = hex!("e382e4b8adc386f09f9293");
pub(super) const STATIC_NONCE: [u8; 8] = [0xdb; 8];

// Keys recovered from the HTTP Custom ChaCha20 key table. Key #5 opens
// the file container; key #1 opens the slot stream; key #7 opens the
// metadata and per-slot legacy values.
pub(super) const CHACHA_KEYS: [[u8; 32]; 8] = [
    hex!("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
    hex!("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
    hex!("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
    hex!("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
    hex!("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
    hex!("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
    hex!("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
    hex!("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"),
];

/// None means the mapped bytes are not a legacy XOR/hex envelope.
pub(in crate::hc) fn open_envelope(mapped: &[u8]) -> Result<Option<Value>, HcError> {
    let encoded = mapped
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ OUTER_XOR_KEY[index % OUTER_XOR_KEY.len()])
        .collect::<Vec<_>>();
    if !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Ok(None);
    }
    let ciphertext = hex::decode(encoded).map_err(|_| HcError::InvalidOuterHex)?;
    let plaintext = decrypt_bytes(&ciphertext, &CHACHA_KEYS[5], &STATIC_NONCE)
        .ok_or(HcError::OuterDecryption)?;
    let outer: Value = serde_json::from_slice(&plaintext).map_err(|_| HcError::InvalidOuterJson)?;
    if !outer.is_object() {
        return Err(HcError::InvalidOuterJson);
    }
    Ok(Some(outer))
}

pub(super) fn decrypt_bytes(
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

pub(super) fn decode_text(raw_value: &str, key: &[u8; 32], nonce: &[u8; 8]) -> Option<String> {
    let ciphertext = hex::decode(raw_value).ok()?;
    let plaintext = decrypt_bytes(&ciphertext, key, nonce)?;
    Some(String::from_utf8_lossy(&plaintext).into_owned())
}

pub(super) fn derive_dynamic_nonce(
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

    let mut nonce = STATIC_NONCE;
    for (index, byte) in material.into_iter().take(nonce.len()).enumerate() {
        nonce[index] = byte;
    }
    nonce
}
