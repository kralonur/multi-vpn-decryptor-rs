//! Authenticated HCX4 envelopes and unpassworded n11 (build 899) / n15 (build 934) sections.

mod crypto;
mod profile;
mod view;

use super::HcError;
use crypto::{derive_key, derive_v5_key, derive_v5_part_key, open};
use serde_json::{Map, Value, json};

const PACKAGE: &str = "xyz.easypro.httpcustom";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const RUNTIME_HEADER: &[u8; 4] = b"HPR1";

pub(super) fn open_envelope(bytes: &[u8]) -> Result<Value, HcError> {
    if bytes.len() < NONCE_BYTES + TAG_BYTES {
        return Err(HcError::ModernAuthentication);
    }
    let key = derive_key(
        format!("hc-envelope-seal-v4 {PACKAGE}").as_bytes(),
        b"hc-envelope-seal-salt-v4",
        b"hc-envelope-seal-info-v4",
    );
    let plaintext = open(
        &key,
        &bytes[..NONCE_BYTES],
        &bytes[NONCE_BYTES..],
        format!("HCX4|{PACKAGE}|1").as_bytes(),
    )?;
    serde_json::from_slice(&plaintext).map_err(|_| HcError::InvalidOuterJson)
}

pub(super) fn decode(envelope: &Value) -> Result<Value, HcError> {
    let session = Session::from_envelope(envelope)?;
    let manifest = envelope.get("i").ok_or(HcError::InvalidModernLayout)?;
    if string(manifest, "a")? != "m" {
        return Err(HcError::InvalidModernLayout);
    }
    let plaintext = session.open_section(manifest)?;
    let config: Value =
        serde_json::from_slice(&plaintext).map_err(|_| HcError::InvalidModernLayout)?;
    if !config.is_object() {
        return Err(HcError::InvalidModernLayout);
    }

    let sections = envelope
        .get("j")
        .and_then(Value::as_array)
        .ok_or(HcError::InvalidModernLayout)?;
    let mut profiles = Map::new();
    let mut payloads = Map::new();
    let mut decoded_profiles = Map::new();
    for section in sections {
        let id = string(section, "a")?;
        if profiles.contains_key(id) {
            return Err(HcError::InvalidModernLayout);
        }
        let profile = session.decode_profile(section)?;
        let payload = session.protected_payload(section)?;
        decoded_profiles.insert(id.to_owned(), view::profile(&profile, payload.as_deref()));
        profiles.insert(id.to_owned(), profile);
        if let Some(payload) = payload {
            payloads.insert(id.to_owned(), Value::String(payload));
        }
    }
    // Payload sidecars belong to profiles, never to the manifest.
    if manifest.get("d").is_some_and(|v| !v.is_null()) {
        return Err(HcError::InvalidModernLayout);
    }
    let decoded_config = view::named_view(&config, "config");
    let protections = decoded_config
        .get("protection")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(json!({
        "format": "http-custom",
        "config": config,
        "profiles": profiles,
        "protected_payloads": payloads,
        "decoded": {"config": decoded_config, "profiles": decoded_profiles},
        "protections": protections,
        "metadata": {
            "container_version": session.scheme.container_version(),
            "key_scheme": session.scheme.key_scheme(),
            "reader_version": session.reader,
        },
    }))
}

#[derive(Clone, Copy)]
enum Scheme {
    N11,
    N15,
}

impl Scheme {
    fn container_version(self) -> u64 {
        match self {
            Self::N11 => 10,
            Self::N15 => 12,
        }
    }

    fn key_scheme(self) -> &'static str {
        match self {
            Self::N11 => "n11",
            Self::N15 => "n15",
        }
    }
}

/// One session key and its authenticated context for n11 (shared) or n15 (per-section derived).
struct Session {
    scheme: Scheme,
    key: [u8; 32],
    aad: Vec<u8>,
    reader: Option<u64>,
}

impl Session {
    fn from_envelope(envelope: &Value) -> Result<Self, HcError> {
        let scheme = match (
            envelope.get("b").and_then(Value::as_u64),
            string(envelope, "e")?,
        ) {
            (Some(10), "n11") => Scheme::N11,
            (Some(12), "n15") => Scheme::N15,
            _ => return Err(HcError::UnsupportedModernProtection),
        };
        if !matches!(string(envelope, "c")?, "s1" | "XCHACHA20P1305")
            || !matches!(string(envelope, "d")?, "h1" | "NATIVE-HKDF-SHA256")
            || envelope.get("h").and_then(Value::as_u64) != Some(0)
            || envelope.get("o").is_some()
            || envelope.get("p").is_some()
        {
            return Err(HcError::UnsupportedModernProtection);
        }
        let parts = envelope
            .get("f")
            .and_then(Value::as_array)
            .ok_or(HcError::InvalidModernLayout)?
            .iter()
            .map(|part| part.as_str().ok_or(HcError::InvalidModernLayout))
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        let reader = envelope
            .get("n")
            .map(|value| {
                value
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or(HcError::InvalidModernLayout)
            })
            .transpose()?;
        if matches!(scheme, Scheme::N15) && reader.is_none() {
            return Err(HcError::InvalidModernLayout);
        }
        let suffix = reader.map(|n| format!("|{n}")).unwrap_or_default();
        let aad = format!(
            "HCCFG|{}|XCHACHA20P1305|NATIVE-HKDF-SHA256|{}|{PACKAGE}|1|{parts}|0{suffix}",
            scheme.container_version(),
            scheme.key_scheme()
        );
        let salt = unhex(envelope, "g")?;
        if salt.len() != 32 {
            return Err(HcError::InvalidModernLayout);
        }
        let key = match scheme {
            Scheme::N11 => {
                let mut prefix = format!("HCCFG\0{PACKAGE}\x001\0{parts}\0").into_bytes();
                if let Some(reader) = reader {
                    prefix.extend_from_slice(format!("{reader}\0").as_bytes());
                }
                prefix.extend_from_slice(&salt);
                let info = format!("app-config|n11|{PACKAGE}|1|{parts}{suffix}");
                derive_key(&prefix, &salt, info.as_bytes())
            }
            Scheme::N15 => derive_v5_key(aad.as_bytes(), &salt),
        };
        Ok(Self {
            scheme,
            key,
            aad: aad.into_bytes(),
            reader,
        })
    }

    fn open_section(&self, section: &Value) -> Result<Vec<u8>, HcError> {
        self.open(
            &unhex(section, "b")?,
            &unhex(section, "c")?,
            string(section, "a")?,
        )
    }

    fn decode_profile(&self, section: &Value) -> Result<Value, HcError> {
        let plaintext = self.open_section(section)?;
        if let Some(runtime) = plaintext.strip_prefix(RUNTIME_HEADER) {
            if runtime.len() < NONCE_BYTES + TAG_BYTES {
                return Err(HcError::InvalidModernLayout);
            }
            let id = string(section, "a")?;
            let packed = self.open(
                &runtime[..NONCE_BYTES],
                &runtime[NONCE_BYTES..],
                &format!("{id}:r"),
            )?;
            profile::decode(&packed)
        } else {
            profile::decode(&plaintext)
        }
    }

    fn protected_payload(&self, section: &Value) -> Result<Option<String>, HcError> {
        let Some(secret) = section.get("d").filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let id = string(section, "a")?;
        let plaintext = self.open(
            &unhex(secret, "a")?,
            &unhex(secret, "b")?,
            &format!("{id}:x"),
        )?;
        String::from_utf8(plaintext)
            .map(Some)
            .map_err(|_| HcError::InvalidModernLayout)
    }

    fn section_key(&self, aad: &[u8]) -> [u8; 32] {
        match self.scheme {
            Scheme::N11 => self.key,
            Scheme::N15 => derive_v5_part_key(&self.key, aad),
        }
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], context: &str) -> Result<Vec<u8>, HcError> {
        let aad = section_aad(&self.aad, context);
        let key = self.section_key(&aad);
        open(&key, nonce, ciphertext, &aad)
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, HcError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(HcError::InvalidModernLayout)
}

fn unhex(value: &Value, key: &str) -> Result<Vec<u8>, HcError> {
    hex::decode(string(value, key)?).map_err(|_| HcError::InvalidModernLayout)
}

fn section_aad(aad: &[u8], context: &str) -> Vec<u8> {
    let mut result = aad.to_vec();
    result.push(0);
    result.extend_from_slice(context.as_bytes());
    result
}
