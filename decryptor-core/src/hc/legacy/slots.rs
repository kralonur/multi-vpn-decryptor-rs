//! Legacy slot transforms; unresolved protocol semantics stay explicit.

use super::SLOT_COUNT;
use super::crypto::{CHACHA_KEYS, decode_text};
use base64::Engine as _;
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

// This is the observed pre/post Base64 byte transform for the legacy
// slot representation. The newer table found in historical references
// is not selected here because it was not independently verified.
const JKL_KEY_OLD: [u8; 20] = [
    0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce, 0xcd, 0xcc, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8,
    0xb7, 0xb6, 0xb5, 0xb4,
];

// The first 26 entries are the a-z Braille symbols. The number symbols
// are retained because they are part of the historical alphabet and may
// occur in another credential-bearing slot.
const BRAILLE_ALPHABET: &str = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚";

pub(super) const TOKEN_NAMES: [&str; SLOT_COUNT] = [
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

pub(super) fn decode(raw_slot: &str, index: usize, dynamic_nonce: &[u8; 8]) -> Value {
    let mut value = raw_slot.to_owned();
    if is_hex_token(raw_slot)
        && let Some(decoded) =
            decode_text(raw_slot, &CHACHA_KEYS[7], dynamic_nonce).filter(|value| !value.is_empty())
    {
        value = decoded;
    }
    value = decode_nested_base64(&value);

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

fn decode_nested_base64(input: &str) -> String {
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
        let key = JKL_KEY_OLD[index % JKL_KEY_OLD.len()];
        *byte ^= key;
    }
    let Ok(transformed_text) = std::str::from_utf8(&data) else {
        return input.to_owned();
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(transformed_text) else {
        return input.to_owned();
    };
    String::from_utf8(decoded).unwrap_or_else(|_| input.to_owned())
}

fn process_credentials(raw: &str, is_ssh: bool) -> String {
    if raw.is_empty() {
        return raw.to_owned();
    }
    let value = if is_ssh
        && raw
            .chars()
            .next()
            .is_some_and(|c| BRAILLE_ALPHABET.contains(c))
    {
        decode_braille(raw)
    } else {
        raw.to_owned()
    };
    if is_ssh {
        static SSH_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^([A-Za-z0-9_.-]+):([0-9-]+)@(.+):(.+)$")
                .expect("hardcoded HC SSH credential pattern must compile")
        });
        let Some(parts) = SSH_CREDENTIALS.captures(&value) else {
            return value;
        };
        return format!(
            "{}:{}@{}:{}",
            &parts[1],
            &parts[2],
            decode_credential(&parts[3]),
            decode_credential(&parts[4])
        );
    }
    static CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([^:]+):(.+)$").expect("hardcoded HC credential pattern must compile")
    });
    let Some(parts) = CREDENTIALS.captures(&value) else {
        return value;
    };
    format!(
        "{}:{}",
        decode_credential(&parts[1]),
        decode_credential(&parts[2])
    )
}

fn decode_credential(value: &str) -> String {
    let decoded = decode_numeric_pairs(value, NUMERIC_PAIRS.find_iter(value).count());
    if decoded.is_empty() {
        value.to_owned()
    } else {
        decoded
    }
}

static NUMERIC_PAIRS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(-?[0-9]+)\.(-?[0-9]+)")
        .expect("hardcoded HC numeric credential pattern must compile")
});

fn decode_numeric_pairs(value: &str, iv: usize) -> String {
    let iv = i128::try_from(iv).unwrap_or(i128::MAX);
    let mut output = Vec::new();
    for captures in NUMERIC_PAIRS.captures_iter(value) {
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
    let alphabet = BRAILLE_ALPHABET.chars().collect::<Vec<_>>();
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
