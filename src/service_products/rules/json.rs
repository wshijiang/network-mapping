//! Reject repeated object keys before converting the rule document to typed fields.
use std::fmt;

use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

pub(super) struct UniqueJson(pub Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor).map(Self)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut entries = Vec::new();
        while let Some(UniqueJson(entry)) = sequence.next_element()? {
            entries.push(entry);
        }
        Ok(Value::Array(entries))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut fields = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if fields.contains_key(&key) {
                return Err(A::Error::custom(format!("重复的 JSON 键 {key:?}")));
            }
            fields.insert(key, object.next_value::<UniqueJson>()?.0);
        }
        Ok(Value::Object(fields))
    }
}
