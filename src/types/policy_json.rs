//! Compact, immutable storage for JSON returned as policy metadata.

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Number, Value};
use std::hash::{Hash, Hasher};
use utoipa::{PartialSchema, ToSchema};

/// Immutable JSON with densely stored objects and arrays.
///
/// Conversion happens when policy metadata is constructed. Serializing this
/// value walks the retained data directly: it does not parse JSON or reconstruct
/// a [`serde_json::Value`]. An engine and its returned decisions share it through
/// `Arc`, so first and repeated evaluations have the same metadata cost.
/// Object serialization preserves the source value's field order. Equality and
/// hashing ignore object order, as [`serde_json::Value`] does. Explicit object
/// equality uses linear searches; hashing sorts temporary borrowed entries.
///
/// This is JSON data, not evidence that a policy is valid or an action allowed.
/// Use [`PolicyJson::to_value`] when a caller needs an owned, mutable JSON tree:
///
/// ```
/// use treetop_core::PolicyJson;
/// use serde_json::json;
///
/// let compact = PolicyJson::from(json!({"effect": "permit"}));
/// let mut editable = compact.to_value();
/// editable["effect"] = json!("forbid");
/// assert_eq!(serde_json::to_value(&compact)?, json!({"effect": "permit"}));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyJson(Node);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Node {
    Null,
    Bool(bool),
    Number(Number),
    String(Box<str>),
    Array(Box<[PolicyJson]>),
    Object(Object),
}

// Value establishes unique keys. Keep its iteration order for serialization,
// including when dependencies enable serde_json/preserve_order.
#[derive(Debug, Clone, Eq)]
struct Object(Box<[(Box<str>, PolicyJson)]>);

impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self.0.iter().all(|(key, value)| {
                other
                    .0
                    .iter()
                    .any(|(other_key, other_value)| key == other_key && value == other_value)
            })
    }
}

impl Hash for Object {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // JSON object equality is independent of order. Sort borrowed entries
        // only when explicitly hashing metadata; evaluation never hashes it.
        let mut entries: Vec<_> = self.0.iter().collect();
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        entries.hash(state);
    }
}

impl From<Value> for PolicyJson {
    fn from(value: Value) -> Self {
        Self(match value {
            Value::Null => Node::Null,
            Value::Bool(value) => Node::Bool(value),
            Value::Number(value) => Node::Number(value),
            Value::String(value) => Node::String(value.into_boxed_str()),
            Value::Array(values) => Node::Array(values.into_iter().map(Self::from).collect()),
            Value::Object(values) => Node::Object(Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key.into_boxed_str(), Self::from(value)))
                    .collect(),
            )),
        })
    }
}

impl PolicyJson {
    /// Materialize an owned, mutable JSON value for explicit caller inspection.
    ///
    /// This recursively allocates and copies the data. Evaluation and Serde
    /// serialization do not call this method. Every node is already valid JSON,
    /// so materialization does not parse text and cannot return a parse error.
    pub fn to_value(&self) -> Value {
        match &self.0 {
            Node::Null => Value::Null,
            Node::Bool(value) => Value::Bool(*value),
            Node::Number(value) => Value::Number(value.clone()),
            Node::String(value) => Value::String(value.to_string()),
            Node::Array(values) => Value::Array(values.iter().map(Self::to_value).collect()),
            Node::Object(Object(entries)) => Value::Object(
                entries
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_value()))
                    .collect(),
            ),
        }
    }
}

impl Serialize for PolicyJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            Node::Null => serializer.serialize_unit(),
            Node::Bool(value) => serializer.serialize_bool(*value),
            Node::Number(value) => value.serialize(serializer),
            Node::String(value) => serializer.serialize_str(value),
            Node::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Node::Object(Object(entries)) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for PolicyJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Value::deserialize(deserializer).map(Self::from)
    }
}

impl PartialSchema for PolicyJson {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Value::schema()
    }
}

impl ToSchema for PolicyJson {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::hash::{DefaultHasher, Hash, Hasher};

    fn hash(value: &PolicyJson) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn all_json_kinds_preserve_values_and_serialization() {
        for value in [
            Value::Null,
            json!(true),
            json!(false),
            json!(i64::MIN),
            json!(u64::MAX),
            json!(1.25),
            json!(-0.0),
            json!("quotes\"\\\n\u{0}🦀"),
            json!([]),
            json!({}),
            json!({"z": [null, true, {"nested": [1, 2.5, "文字"]}], "a": "first"}),
        ] {
            let compact = PolicyJson::from(value.clone());
            assert_eq!(compact.to_value(), value);
            assert_eq!(serde_json::to_value(&compact).unwrap(), value);
            assert_eq!(
                serde_json::to_string(&compact).unwrap(),
                serde_json::to_string(&value).unwrap()
            );
            let restored: PolicyJson = serde_json::from_value(value).unwrap();
            assert_eq!(restored, compact);
            assert_eq!(hash(&restored), hash(&compact));
        }
    }

    #[test]
    fn deserialization_uses_normal_json_validation_and_duplicate_key_semantics() {
        for input in ["", "{", "[1,]", "{\"a\": NaN}", "1e9999", "\"\\q\""] {
            assert!(
                serde_json::from_str::<PolicyJson>(input).is_err(),
                "accepted {input:?}"
            );
        }
        let input = r#"{"z":1,"a":false,"z":2}"#;
        let compact: PolicyJson = serde_json::from_str(input).unwrap();
        assert_eq!(
            compact.to_value(),
            serde_json::from_str::<Value>(input).unwrap()
        );
        assert_eq!(compact, PolicyJson::from(json!({"a": false, "z": 2})));
    }

    #[test]
    fn materializing_a_mutable_copy_does_not_change_shared_metadata() {
        let compact = PolicyJson::from(json!({"effect": "permit", "conditions": []}));
        let mut value = compact.to_value();
        value["effect"] = json!("forbid");
        assert_eq!(compact.to_value()["effect"], "permit");
    }

    #[test]
    fn object_order_is_preserved_but_does_not_affect_equality_or_hashing() {
        let left = r#"{"z":{"b":2,"a":1},"a":[true,null]}"#;
        let right = r#"{"a":[true,null],"z":{"a":1,"b":2}}"#;
        let left_json: PolicyJson = serde_json::from_str(left).unwrap();
        let right_json: PolicyJson = serde_json::from_str(right).unwrap();
        for (input, compact) in [(left, &left_json), (right, &right_json)] {
            let value: Value = serde_json::from_str(input).unwrap();
            assert_eq!(
                serde_json::to_string(compact).unwrap(),
                serde_json::to_string(&value).unwrap()
            );
        }
        assert_eq!(left_json, right_json);
        assert_eq!(hash(&left_json), hash(&right_json));
        assert_ne!(left_json, PolicyJson::from(json!({"a": [true]})));
        assert_ne!(
            left_json,
            PolicyJson::from(json!({"z": {"b": 3, "a": 1}, "a": [true, null]}))
        );
    }

    #[test]
    fn schema_remains_arbitrary_json() {
        assert!(PolicyJson::schema() == Value::schema());
    }
}
