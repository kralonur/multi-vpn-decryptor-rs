//! Build-810 container and result assembly; nested semantics remain best-effort.

mod crypto;
mod slots;

use super::HcError;
use crypto::{CHACHA_KEYS, STATIC_NONCE, decode_text, derive_dynamic_nonce};
use serde_json::{Map, Value, json};

pub(super) use crypto::open_envelope;

const SLOT_COUNT: usize = 32;
const UNKNOWN_SLOTS: [usize; 3] = [14, 22, 24];

pub(super) fn decode(outer: &Value) -> Result<Value, HcError> {
    let outer = outer.as_object().ok_or(HcError::InvalidOuterJson)?;
    let container = outer
        .get("a")
        .and_then(Value::as_object)
        .ok_or(HcError::InvalidOuterLayout)?;
    let ciphertext = container
        .get("xy")
        .and_then(Value::as_str)
        .ok_or(HcError::InvalidOuterLayout)?;
    let delimiter = container
        .get("uv")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(HcError::InvalidOuterLayout)?;
    let protections = Protections::from_outer(outer, container);
    let nonce = protections.nonce();
    let raw_slots = decode_slots(ciphertext, delimiter)?;
    let config = raw_slots
        .iter()
        .enumerate()
        // Unrecovered slots remain available in raw_slots and unresolved.
        .filter(|(index, _)| !matches!(index, 22 | 24))
        .map(|(index, raw)| {
            (
                slots::TOKEN_NAMES[index].to_owned(),
                slots::decode(raw, index, &nonce),
            )
        })
        .collect::<Map<_, _>>();

    Ok(json!({
        "format": "http-custom",
        "protections": protections.to_value(),
        "metadata": metadata(outer, container, &protections, &nonce),
        "unresolved": unresolved(&raw_slots, &config),
        "config": config,
        "raw_slots": raw_slots,
    }))
}

fn decode_slots(ciphertext: &str, delimiter: &str) -> Result<Vec<String>, HcError> {
    let plaintext = decode_text(ciphertext, &CHACHA_KEYS[1], &STATIC_NONCE)
        .filter(|value| !value.is_empty())
        .ok_or(HcError::EmptySlotStream)?;
    let slots = plaintext
        .split(delimiter)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if slots.len() != SLOT_COUNT {
        return Err(HcError::UnexpectedSlotCount {
            found: slots.len(),
            expected: SLOT_COUNT,
        });
    }
    Ok(slots)
}

struct Protections {
    password: Option<String>,
    hwid: Option<String>,
    provider: Option<String>,
    area: Option<String>,
}

impl Protections {
    fn from_outer(outer: &Map<String, Value>, container: &Map<String, Value>) -> Self {
        Self {
            password: decode_metadata(outer, "e").filter(|value| !value.is_empty()),
            hwid: decode_metadata(container, "bb").filter(|value| !value.is_empty()),
            provider: decode_metadata(container, "ed").filter(|value| !value.is_empty()),
            area: decode_metadata(container, "fe").filter(|value| !value.is_empty()),
        }
    }

    fn nonce(&self) -> [u8; 8] {
        derive_dynamic_nonce(
            self.password.as_deref(),
            self.hwid.as_deref(),
            self.provider.as_deref(),
            self.area.as_deref(),
        )
    }

    fn to_value(&self) -> Value {
        [
            ("password", &self.password),
            ("hwid", &self.hwid),
            ("provider", &self.provider),
            ("area", &self.area),
        ]
        .into_iter()
        .filter_map(|(name, value)| {
            value
                .as_ref()
                .map(|value| (name.to_owned(), Value::String(value.clone())))
        })
        .collect::<Map<_, _>>()
        .into()
    }
}

fn metadata(
    outer: &Map<String, Value>,
    container: &Map<String, Value>,
    protections: &Protections,
    nonce: &[u8; 8],
) -> Value {
    let mut metadata = Map::new();
    if let Some(password) = &protections.password {
        metadata.insert("password".to_owned(), json!(password));
    }
    if let Some(value) = decode_metadata(outer, "b") {
        metadata.insert("outer_b".to_owned(), json!(value));
    }
    let outer_fields = container
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "xy" | "uv"))
        .filter_map(|(key, _)| {
            decode_metadata(container, key).map(|value| (key.clone(), json!(value)))
        })
        .collect::<Map<_, _>>();
    if !outer_fields.is_empty() {
        metadata.insert("outer_fields".to_owned(), Value::Object(outer_fields));
    }
    metadata.insert("dynamic_nonce".to_owned(), json!(hex::encode(nonce)));
    metadata.insert(
        "nested_decoding".to_owned(),
        json!("best-effort; credential and protocol semantics are provisional"),
    );
    Value::Object(metadata)
}

fn unresolved(raw_slots: &[String], config: &Map<String, Value>) -> Value {
    let unknown_slots = UNKNOWN_SLOTS
        .into_iter()
        .map(|index| {
            let name = slots::TOKEN_NAMES[index];
            let mut entry = json!({
                "name": name, "raw": raw_slots[index], "status": "unresolved semantics",
            });
            if let Some(value) = config.get(name) {
                entry["decoded_candidate"] = value.clone();
            }
            (index.to_string(), entry)
        })
        .collect::<Map<_, _>>();
    json!({
        "unknown_slots": unknown_slots,
        "nested": {
            "credential_transform": {
                "status": "provisional",
                "slots": [7, 11],
                "note": "Braille/numeric tuple decoding is a best-effort transform; the stripped native credential semantics are not proven.",
                "slot_7_candidate": config.get("sshField").cloned().unwrap_or(Value::Null),
                "slot_11_candidate": config.get("ovpnUserAndPass").cloned().unwrap_or(Value::Null),
            },
            "protocol_mappings": {
                "status": "unresolved",
                "note": "The slot names are historical/APK-derived labels; complete protocol-state mapping is not recovered.",
            },
        },
    })
}

fn decode_metadata(object: &Map<String, Value>, key: &str) -> Option<String> {
    decode_text(object.get(key)?.as_str()?, &CHACHA_KEYS[7], &STATIC_NONCE)
}
