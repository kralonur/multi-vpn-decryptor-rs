//! Lossless readable projection of the reviewed build-899 wire schema.

use serde_json::{Map, Value};
use std::sync::LazyLock;

static SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../modern_schema.json"))
        .expect("reviewed HC schema must be valid JSON")
});

pub(super) fn profile(raw: &Value, payload: Option<&str>) -> Value {
    let mut view = named_view(raw, "profile");
    if let Some(payload) = payload
        && let Some(config_json) = view["configJson"].as_object_mut()
    {
        config_json.insert(
            "customPayload".to_owned(),
            Value::String(payload.to_owned()),
        );
    }
    view
}

// Keep config/profiles byte-for-byte equivalent at the JSON-value level; the
// additional view labels known wire keys and expands only the APK's configJson.
pub(super) fn named_view(value: &Value, schema_name: &str) -> Value {
    if let Some(item_schema) = schema_name.strip_suffix("[]") {
        return value.as_array().map_or_else(
            || value.clone(),
            |items| Value::Array(items.iter().map(|v| named_view(v, item_schema)).collect()),
        );
    }
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let schema = &SCHEMA[schema_name];
    if let Some(item_schema) = schema["values"].as_str() {
        return Value::Object(
            object
                .iter()
                .map(|(k, v)| (k.clone(), named_view(v, item_schema)))
                .collect(),
        );
    }
    let mut result = Map::new();
    let mut unmapped = Map::new();
    for (key, raw) in object {
        let Some(name) = schema["fields"][key].as_str() else {
            unmapped.insert(key.clone(), raw.clone());
            continue;
        };
        let mut decoded = schema["children"][key]
            .as_str()
            .map_or_else(|| raw.clone(), |child| named_view(raw, child));
        if schema["json_fields"]
            .as_array()
            .is_some_and(|fields| fields.iter().any(|f| f == key))
            && let Some(text) = raw.as_str()
            && let Ok(json) = serde_json::from_str::<Value>(text)
            && json.is_object()
        {
            decoded = json;
        }
        result.insert(name.to_owned(), decoded);
    }
    if !unmapped.is_empty() {
        result.insert("_unmapped".to_owned(), Value::Object(unmapped));
    }
    Value::Object(result)
}
