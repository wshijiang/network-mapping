use std::{env, fs, path::PathBuf};

fn collect(value: &toml::Value, prefix: &str, fields: &mut Vec<String>) {
    if let Some(table) = value.as_table() {
        for (key, child) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            collect(child, &path, fields);
        }
    } else {
        fields.push(prefix.into());
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=NM_PUBLIC_CONFIG_FIELDS_FILE");
    let fields = if let Ok(path) = env::var("NM_PUBLIC_CONFIG_FIELDS_FILE") {
        // Docker uses a names-only snapshot; environment values never enter its context.
        println!("cargo:rerun-if-changed={path}");
        fs::read_to_string(path)
            .expect("cannot read public configuration field names")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        println!("cargo:rerun-if-changed=config.toml");
        println!("cargo:rerun-if-changed=src/public_config_fields.txt");
        let content = fs::read_to_string("config.toml").expect("cannot read tracked config.toml");
        let Ok(config) = toml::from_str::<toml::Value>(&content) else {
            panic!("cannot parse tracked config.toml for public field names");
        };
        let mut fields = Vec::new();
        collect(&config, "", &mut fields);
        fields.sort();
        let snapshot = fs::read_to_string("src/public_config_fields.txt")
            .expect("cannot read public configuration field names");
        assert!(
            snapshot.lines().eq(fields.iter().map(String::as_str)),
            "public field snapshot is outdated; run python3 scripts/update-config-fields.py"
        );
        fields
    };
    assert!(fields.iter().all(|field| {
        !field.is_empty()
            && field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    }));
    let generated = format!("const PUBLIC_CONFIG_FIELDS: &[&str] = &{fields:?};\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is missing"));
    fs::write(output.join("public_config_fields.rs"), generated)
        .expect("cannot write public configuration field names");
}
