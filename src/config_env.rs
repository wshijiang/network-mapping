//! Read NM__SECTION__FIELD values without loading a deployment config file.
use serde_json::Value;
use std::{collections::BTreeMap, io};

// Optional deployment fields are intentionally absent from the public config
// catalog. Keep their env names and string types explicit, including when unset.
const OPTIONAL_DEPLOYMENT_STRING_FIELDS: &[&str] = &[
    "elasticsearch.api_key",
    "elasticsearch.username",
    "elasticsearch.password",
    "elasticsearch.ca_certificate_file",
];

fn invalid(field: &str, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("environment field {field}: {message}"),
    )
}

pub(crate) fn apply(
    defaults: &mut Value,
    pairs: impl IntoIterator<Item = (String, String)>,
    allowed: impl Fn(&str) -> bool,
) -> io::Result<()> {
    let mut values = BTreeMap::new();
    for (key, text) in pairs {
        let Some(name) = key.strip_prefix("NM__") else {
            continue;
        };
        let direct = name.to_ascii_lowercase().replace("__", ".");
        let known = |field: &str| {
            allowed(field)
                || OPTIONAL_DEPLOYMENT_STRING_FIELDS.contains(&field)
                || field
                    .split('.')
                    .try_fold(&*defaults, |value, part| value.get(part))
                    .is_some_and(|value| !value.is_object())
        };
        let (field, from_file) = if known(&direct) {
            (direct, false)
        } else if let Some(base) = name.strip_suffix("_FILE") {
            let field = base.to_ascii_lowercase().replace("__", ".");
            if !known(&field) {
                return Err(invalid(&direct, "unknown configuration field"));
            }
            (field, true)
        } else {
            return Err(invalid(&direct, "unknown configuration field"));
        };
        if values.contains_key(&field) {
            return Err(invalid(
                &field,
                "provide either its value or _FILE, not both",
            ));
        }
        let text = if from_file {
            std::fs::read_to_string(&text)
                .map_err(|_| invalid(&field, "cannot read its _FILE input"))?
                .trim_end_matches(['\r', '\n'])
                .to_owned()
        } else {
            text
        };
        values.insert(field, text);
    }
    for (field, text) in values {
        let parts = field.split('.').collect::<Vec<_>>();
        let mut value = &mut *defaults;
        for part in &parts[..parts.len() - 1] {
            if value.is_null() {
                *value = serde_json::json!({});
            }
            let object = value
                .as_object_mut()
                .ok_or_else(|| invalid(&field, "invalid nested field"))?;
            value = object.entry(*part).or_insert(serde_json::json!({}));
        }
        let object = value
            .as_object_mut()
            .ok_or_else(|| invalid(&field, "invalid configuration section"))?;
        let leaf = parts[parts.len() - 1];
        let current = object.get(leaf).unwrap_or(&Value::Null);
        let sensitive = [
            "password",
            "token",
            "secret",
            "encrypt_key",
            "pepper",
            "api_key",
        ]
        .iter()
        .any(|part| field.contains(part));
        let parsed = if current.is_string()
            || sensitive
            || OPTIONAL_DEPLOYMENT_STRING_FIELDS.contains(&field.as_str())
        {
            Value::String(text)
        } else if current.is_boolean()
            || current.is_number()
            || current.is_array()
            || current.is_object()
        {
            let parsed: Value = serde_json::from_str(&text)
                .map_err(|_| invalid(&field, "invalid typed value (arrays/objects use JSON)"))?;
            if (current.is_boolean() && !parsed.is_boolean())
                || (current.is_number() && !parsed.is_number())
                || (current.is_array() && !parsed.is_array())
                || (current.is_object() && !parsed.is_object())
            {
                return Err(invalid(&field, "value has the wrong type"));
            }
            parsed
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        object.insert(leaf.to_owned(), parsed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    #[test]
    fn parses_nested_types_and_keeps_numeric_secrets_as_strings() {
        let mut value = serde_json::json!({"database":{"port":5432,"password":""},"scanner":{"enabled":false},"dns":{"types":[]}});
        apply(
            &mut value,
            pairs(&[
                ("NM__DATABASE__PORT", "5433"),
                ("NM__DATABASE__PASSWORD", "00123"),
                ("NM__SCANNER__ENABLED", "true"),
                ("NM__DNS__TYPES", "[\"A\",\"AAAA\"]"),
            ]),
            |_| true,
        )
        .unwrap();
        assert_eq!(value["database"]["password"], "00123");
        assert_eq!(value["database"]["port"], 5433);
        assert_eq!(value["scanner"]["enabled"], true);
        assert_eq!(value["dns"]["types"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn invalid_values_never_appear_in_errors() {
        let mut value = serde_json::json!({"database":{"port":5432}});
        let error = apply(
            &mut value,
            pairs(&[("NM__DATABASE__PORT", "private-sensitive-value")]),
            |_| true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("database.port"));
        assert!(!error.to_string().contains("private-sensitive-value"));
    }
    #[test]
    fn unknown_fields_fail_and_other_environment_is_ignored() {
        let mut value = serde_json::json!({});
        apply(&mut value, pairs(&[("PATH", "ignored")]), |_| false).unwrap();
        assert!(
            apply(
                &mut value,
                pairs(&[("NM__DATABSE__HOST", "secret")]),
                |_| false
            )
            .is_err()
        );
    }
    #[test]
    fn secret_file_and_direct_value_conflict_is_rejected() {
        let path = std::env::temp_dir().join(format!("env-secret-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, "00123\n").unwrap();
        let mut value = serde_json::json!({"database":{"password":""}});
        let input = [("NM__DATABASE__PASSWORD_FILE", path.to_str().unwrap())];
        apply(&mut value, pairs(&input), |f| f == "database.password").unwrap();
        assert_eq!(value["database"]["password"], "00123");
        let error = apply(
            &mut value,
            pairs(&[("NM__DATABASE__PASSWORD", "ignored"), input[0]]),
            |f| f == "database.password",
        )
        .unwrap_err();
        assert!(error.to_string().contains("either"));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn normal_fields_ending_in_file_are_not_secret_file_inputs() {
        let mut value = serde_json::json!({"tls":{"private_key_file":""}});
        apply(
            &mut value,
            pairs(&[("NM__TLS__PRIVATE_KEY_FILE", "/not/read/from/host.pem")]),
            |f| f == "tls.private_key_file",
        )
        .unwrap();
        assert_eq!(value["tls"]["private_key_file"], "/not/read/from/host.pem");
    }
}
