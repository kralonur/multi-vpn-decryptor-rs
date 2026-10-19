//! Authenticated build-899 envelopes and unpassworded n11 configuration sections.

mod crypto;
mod profile;
mod view;

use super::HcError;
use crypto::{derive_key, open};
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
        "metadata": {"container_version": 10, "key_scheme": "n11", "reader_version": session.reader},
    }))
}

/// One n11 key and its authenticated context, shared by every section/layer.
struct Session {
    key: [u8; 32],
    aad: Vec<u8>,
    reader: Option<u64>,
}

impl Session {
    fn from_envelope(envelope: &Value) -> Result<Self, HcError> {
        if envelope.get("b").and_then(Value::as_u64) != Some(10)
            || string(envelope, "c")? != "s1"
            || string(envelope, "d")? != "h1"
            || string(envelope, "e")? != "n11"
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
        let suffix = reader.map(|n| format!("|{n}")).unwrap_or_default();
        let aad =
            format!("HCCFG|10|XCHACHA20P1305|NATIVE-HKDF-SHA256|n11|{PACKAGE}|1|{parts}|0{suffix}");
        let salt = unhex(envelope, "g")?;
        if salt.len() != 32 {
            return Err(HcError::InvalidModernLayout);
        }
        let mut prefix = format!("HCCFG\0{PACKAGE}\x001\0{parts}\0").into_bytes();
        if let Some(reader) = reader {
            prefix.extend_from_slice(format!("{reader}\0").as_bytes());
        }
        prefix.extend_from_slice(&salt);
        let info = format!("app-config|n11|{PACKAGE}|1|{parts}{suffix}");
        Ok(Self {
            key: derive_key(&prefix, &salt, info.as_bytes()),
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

    fn open(&self, nonce: &[u8], ciphertext: &[u8], context: &str) -> Result<Vec<u8>, HcError> {
        open(
            &self.key,
            nonce,
            ciphertext,
            &section_aad(&self.aad, context),
        )
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
