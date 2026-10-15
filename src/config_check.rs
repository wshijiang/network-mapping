//! Read-only inspection of the original TOML, before Serde fills defaults.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

include!(concat!(env!("OUT_DIR"), "/public_config_fields.rs"));

pub(crate) fn environment_field_allowed(path: &str) -> bool {
    PUBLIC_CONFIG_FIELDS.contains(&path)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssueKind {
    Default,
    Optional,
    Required,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigIssue {
    pub field: String,
    pub kind: ConfigIssueKind,
    pub source: String,
    pub default_value: Option<String>,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigCheck {
    pub component: String,
    pub version: String,
    pub checked_at: DateTime<Utc>,
    pub items: Vec<ConfigIssue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_fields: Vec<String>,
}

impl ConfigCheck {
    pub fn inspect(raw: &Value, defaults: &Value, required: &[&str], component: &str) -> Self {
        let mut report = Self {
            component: component.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            checked_at: Utc::now(),
            items: Vec::new(),
            public_fields: Vec::new(),
        };
        for field in required {
            if lookup(raw, field).is_none() {
                report.items.push(ConfigIssue {
                    field: (*field).into(),
                    kind: ConfigIssueKind::Required,
                    source: "startup".into(),
                    default_value: None,
                    description: "必需的部署参数，请通过启动配置提供。".into(),
                });
            }
        }
        report.collect(raw, defaults, "", defaults);
        report.items.sort_by(|a, b| a.field.cmp(&b.field));
        report
    }

    fn collect(&mut self, raw: &Value, value: &Value, prefix: &str, defaults: &Value) {
        if let Some(object) = value.as_object()
            && !prefix.ends_with("service_defaults")
        {
            for (key, child) in object {
                let field = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                self.collect(raw, child, &field, defaults);
            }
            return;
        }
        // None describes the unset default; it does not suppress a missing
        // public field. Public-schema and source filters decide eligibility.
        if lookup(raw, prefix).is_some() || sensitive(prefix) {
            return;
        }
        let section = prefix.split('.').next().unwrap_or_default();
        let source = source_for(section);
        // These fields are managed in Web and persisted in the database. TOML
        // supplies only bootstrap defaults, so an omitted field is not a notice.
        if source == "database_seed" {
            return;
        }
        let enabled_path = match section {
            "report_mail" => "report_mail.remote_images_enabled".into(),
            _ => format!("{section}.enabled"),
        };
        let inactive = lookup(raw, &enabled_path)
            .or_else(|| lookup(defaults, &enabled_path))
            .and_then(Value::as_bool)
            == Some(false);
        let optional = inactive && prefix != enabled_path;
        let description = if optional {
            "本地功能未启用，此参数无需补齐；启用时请检查相关配置。"
        } else if value.is_null() {
            match prefix {
                "backup.run_as_user" => {
                    "未配置运行账户，pgBackRest 当前以服务进程的操作系统用户执行，不使用 sudo 切换用户；如需指定账户，请配置此项并重启。"
                }
                "backup.config_file" => {
                    "未配置文件路径，使用 pgBackRest 自身的默认配置文件查找规则；如需指定文件，请配置此项并重启。"
                }
                _ => "此参数未显式配置，当前保持未设置；如需调整，请修改启动配置并重启。",
            }
        } else if source == "local_limit" {
            "采用本地默认值；远程配置仍受本地开关和速率限制约束。"
        } else if source == "remote_override" {
            "本地缺省值；有效参数还可能由服务端下发的运行配置决定。"
        } else if prefix.ends_with("directory") || prefix.ends_with("path") {
            "采用内置路径；请按文件或 Docker 部署检查路径及挂载，修改后重启。"
        } else {
            "采用内置默认值；如需调整，请修改启动配置并重启。"
        };
        let default_value = (!value.is_null()).then(|| {
            let rendered = value.to_string();
            if rendered.chars().count() > 480 {
                "内置规则（详情见对应运行时设置）".into()
            } else {
                rendered
            }
        });
        self.items.push(ConfigIssue {
            field: prefix.into(),
            kind: if optional {
                ConfigIssueKind::Optional
            } else {
                ConfigIssueKind::Default
            },
            source: source.into(),
            default_value,
            description: description.into(),
        });
    }

    pub fn error_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.kind == ConfigIssueKind::Required)
            .count()
    }

    pub fn default_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.kind == ConfigIssueKind::Default)
            .count()
    }

    pub fn emit_startup(&self) {
        eprintln!(
            "配置检查：{} 项未显式配置，{} 项为未启用功能的可选参数，{} 项必需参数缺失。",
            self.default_count(),
            self.items.len() - self.default_count() - self.error_count(),
            self.error_count()
        );
        tracing::info!(event = "ConfigCheckSummary", component = %self.component,
            default_count = self.default_count(), missing_required = self.error_count(),
            optional_count = self.items.len() - self.default_count() - self.error_count(), "启动配置检查完成");
        for item in &self.items {
            if item.kind == ConfigIssueKind::Required {
                eprintln!("配置错误：缺少 {}。{}", item.field, item.description);
                tracing::error!(event = "ConfigFieldMissing", field = %item.field, "必需配置缺失");
            } else if item.kind == ConfigIssueKind::Default {
                tracing::info!(event = "ConfigFieldDefaulted", field = %item.field,
                    source = %item.source, default_value = ?item.default_value,
                    description = %item.description, "配置字段未显式填写");
            }
        }
    }

    /// Bounds apply to scanner-supplied reports before persistence.
    pub fn valid_scanner_report(&self) -> bool {
        self.component == "scanner"
            && self.version.len() <= 64
            && self.items.len() <= 256
            && self.public_fields.len() <= 256
            && self.public_fields.iter().all(|field| {
                !field.is_empty()
                    && field.len() <= 128
                    && field
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
            })
            && self.items.iter().all(|item| {
                !item.field.is_empty()
                    && item.field.len() <= 128
                    && !sensitive(&item.field)
                    && item
                        .field
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
                    && matches!(
                        item.source.as_str(),
                        "startup" | "local_limit" | "remote_override"
                    )
                    && item.description.len() <= 512
                    && item
                        .default_value
                        .as_ref()
                        .is_none_or(|value| value.len() <= 1024)
            })
    }
}

fn lookup<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |value, key| value.get(key))
}

fn sensitive(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        "password",
        "token",
        "secret",
        "encrypt_key",
        "pepper",
        "api_key",
        "private_key",
        "scanner_id",
    ]
    .iter()
    .any(|part| path.contains(part))
}

fn source_for(section: &str) -> &'static str {
    match section {
        "requests" | "monitor" | "automatic_target" | "dns_follow_up" | "analytics_snapshot"
        | "report_mail" => "database_seed",
        _ => "startup",
    }
}

pub fn inspect_server(raw: &Value) -> ConfigCheck {
    use crate::config::*;
    // The schema's optional fields and values come from the application's own Defaults.
    let defaults = json!({
        "server": {"max_body_size": default_max_body_size()},
        "database": {"pool_wait_timeout_ms": default_pool_wait_timeout_ms(),
            "pool_create_timeout_ms": default_pool_create_timeout_ms(), "pool_recycle_timeout_ms": default_pool_recycle_timeout_ms()},
        "frontend": FrontendConfig::default(), "maxmind": MaxMindConfig::default(),
        "backup": BackupConfig::default(), "elasticsearch": ElasticsearchConfig::default(),
        "scanner_diagnostics": crate::scanner_diagnostics::DiagnosticsConfig::default(),
        "requests": RequestsConfig::default(), "monitor": MonitorConfig::default(),
        "automatic_target": AutomaticTargetConfig::default(),
        "dns_follow_up": crate::dns_follow_up::DnsFollowUpConfig::default(),
        "analytics_snapshot": AnalyticsSnapshotConfig::default(),
        "report_mail": crate::reports::mail_config::ReportMailConfig::default(),
    });
    let mut report = ConfigCheck::inspect(
        raw,
        &defaults,
        &[
            "server.host",
            "server.port",
            "server.encrypt_key",
            "tls.certificate_chain_file",
            "tls.private_key_file",
            "log.directory",
            "log.file_name",
            "log.file_rolling",
            "log.status_duration",
            "templates.templates_directory",
            "templates.templates_name",
            "database.host",
            "database.port",
            "database.username",
            "database.password",
            "database.db_name",
            "database.pool_max_size",
            "database.tls",
            "database.init_database_file",
            "database.sql_file_path",
            "pwd_hash.m",
            "pwd_hash.t",
            "pwd_hash.p",
            "security.scanner_token_pepper",
        ],
        "server",
    );
    report
        .items
        .retain(|item| PUBLIC_CONFIG_FIELDS.contains(&item.field.as_str()));
    report.public_fields = PUBLIC_CONFIG_FIELDS
        .iter()
        .map(|field| (*field).into())
        .collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commented_backup_user_reports_the_unset_execution_identity() {
        let raw: Value = toml::from_str(
            r#"[backup]
enabled = true
binary = "/usr/bin/pgbackrest"
stanza = "network_mapping"
config_file = "/etc/pgbackrest.conf"
#run_as_user = "postgres"
sudo_binary = "/usr/bin/sudo"
command_timeout_seconds = 21600
max_output_bytes = 1048576
"#,
        )
        .unwrap();
        let report = inspect_server(&raw);
        let issues: Vec<_> = report
            .items
            .iter()
            .filter(|item| item.field.starts_with("backup."))
            .collect();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "backup.run_as_user");
        assert_eq!(issues[0].kind, ConfigIssueKind::Default);
        assert_eq!(issues[0].source, "startup");
        assert!(issues[0].default_value.is_none());
        assert!(issues[0].description.contains("服务进程的操作系统用户"));
        assert!(issues[0].description.contains("不使用 sudo"));
        let config: crate::config::BackupConfig =
            serde_json::from_value(raw["backup"].clone()).unwrap();
        assert!(config.run_as_user.is_none());
        assert_eq!(
            config.config_file.unwrap(),
            std::path::PathBuf::from("/etc/pgbackrest.conf")
        );
    }

    #[test]
    fn unset_backup_options_are_not_required_and_are_optional_when_disabled() {
        for enabled in [true, false] {
            let report = inspect_server(&json!({"backup": {"enabled": enabled}}));
            for field in ["backup.run_as_user", "backup.config_file"] {
                let issue = report
                    .items
                    .iter()
                    .find(|item| item.field == field)
                    .unwrap();
                assert_eq!(
                    issue.kind,
                    if enabled {
                        ConfigIssueKind::Default
                    } else {
                        ConfigIssueKind::Optional
                    }
                );
                assert!(issue.default_value.is_none());
                if enabled && field == "backup.config_file" {
                    assert!(issue.description.contains("默认配置文件查找规则"));
                }
            }
            let explicit = inspect_server(&json!({"backup": {"enabled": enabled,
                "run_as_user": "postgres", "config_file": "/etc/pgbackrest.conf"}}));
            assert!(!explicit.items.iter().any(|item| matches!(
                item.field.as_str(),
                "backup.run_as_user" | "backup.config_file"
            )));
        }
    }

    #[test]
    fn unpublished_defaults_never_generate_notices() {
        let report = inspect_server(&json!({}));
        assert!(
            report
                .items
                .iter()
                .all(|item| PUBLIC_CONFIG_FIELDS.contains(&item.field.as_str()))
        );
        assert!(
            !report
                .items
                .iter()
                .any(|item| item.field.starts_with("scanner_diagnostics.")
                    || item.field.starts_with("elasticsearch.projection_"))
        );
    }

    #[test]
    fn tracked_public_configuration_has_no_notices() {
        // Docker deliberately replaces this file with a smaller, sanitized example.
        if option_env!("NM_PUBLIC_CONFIG_FIELDS_FILE").is_some() {
            return;
        }
        let content =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.toml")).unwrap();
        let raw: Value = toml::from_str(&content).unwrap();
        assert!(inspect_server(&raw).items.is_empty());
    }

    #[test]
    fn compares_paths_not_counts_and_never_echoes_config_values() {
        let report = ConfigCheck::inspect(
            &json!({"server":{"extra": 1}, "password":"private-secret"}),
            &json!({"server":{"timeout": 30},"password":"fallback-secret"}),
            &[],
            "server",
        );
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].field, "server.timeout");
        let output = serde_json::to_string(&report).unwrap();
        assert!(!output.contains("private-secret"));
        assert!(!output.contains("fallback-secret"));
    }

    #[test]
    fn disabled_deployment_features_remain_optional_and_database_seeds_are_excluded() {
        let report = ConfigCheck::inspect(
            &json!({"backup":{"enabled":false}}),
            &json!({"backup":{"enabled":false,"timeout":30},"requests":{"enabled":true}}),
            &[],
            "server",
        );
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].field, "backup.timeout");
        assert_eq!(report.items[0].kind, ConfigIssueKind::Optional);
        assert_eq!(report.items[0].source, "startup");
    }

    #[test]
    fn server_catalog_excludes_all_database_managed_sections() {
        let report = inspect_server(&json!({}));
        for section in [
            "requests",
            "monitor",
            "automatic_target",
            "dns_follow_up",
            "analytics_snapshot",
            "report_mail",
        ] {
            assert!(
                !report
                    .items
                    .iter()
                    .any(|item| item.field.starts_with(&format!("{section}."))),
                "database-managed section {section} must not generate file notices"
            );
        }
        assert!(report.items.iter().any(|item| {
            item.field == "server.max_body_size" && item.kind == ConfigIssueKind::Default
        }));
        assert!(report.items.iter().any(|item| {
            item.field == "database.pool_wait_timeout_ms" && item.kind == ConfigIssueKind::Default
        }));
    }

    #[test]
    fn required_keys_are_reported_without_defaults_and_explicit_values_are_preserved() {
        let report = ConfigCheck::inspect(
            &json!({"server":{"timeout":0}}),
            &json!({"server":{"timeout":30}}),
            &["database.password"],
            "server",
        );
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.items[0].field, "database.password");
        assert!(report.items[0].default_value.is_none());
    }

    #[test]
    fn server_catalog_uses_real_defaults_and_excludes_sensitive_and_unpublished_options() {
        let report = inspect_server(&json!({}));
        let item = report
            .items
            .iter()
            .find(|item| item.field == "database.pool_wait_timeout_ms")
            .unwrap();
        assert_eq!(item.default_value.as_deref(), Some("2000"));
        assert!(!report.items.iter().any(|item| matches!(
            item.field.as_str(),
            "elasticsearch.password" | "elasticsearch.username"
        )));
        assert!(report.items.iter().any(
            |item| item.field == "server.encrypt_key" && item.kind == ConfigIssueKind::Required
        ));
    }
}

#[cfg(test)]
mod deployment_tests {
    use super::*;

    #[test]
    fn custom_path_and_read_only_docker_style_files_are_not_modified() {
        use crate::config::Config;
        use std::fs;
        let directory =
            std::env::temp_dir().join(format!("nm-config-check-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("custom-server.toml");
        let content = include_str!("../docker/config.example.toml")
            .lines()
            .filter(|line| {
                !line.starts_with("max_body_size =") && !line.starts_with("pool_wait_timeout_ms =")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut raw: toml::Value = toml::from_str(&content).unwrap();
        let backup = raw.get_mut("backup").unwrap().as_table_mut().unwrap();
        backup.insert("enabled".into(), toml::Value::Boolean(true));
        backup.remove("run_as_user");
        backup.remove("config_file");
        let content = toml::to_string(&raw).unwrap();
        fs::write(&path, &content).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let (config, report) = Config::from_file_with_check(&path).unwrap();
        assert_eq!(config.server.max_body_size, 67_108_864);
        assert_eq!(config.database.pool_wait_timeout_ms, 2000);
        assert_eq!(report.error_count(), 0);
        assert!(config.backup.run_as_user.is_none());
        assert!(config.backup.config_file.is_none());
        for field in ["backup.run_as_user", "backup.config_file"] {
            let issue = report
                .items
                .iter()
                .find(|item| item.field == field)
                .unwrap();
            assert_eq!(issue.kind, ConfigIssueKind::Default);
            assert!(issue.default_value.is_none());
        }
        assert!(
            report
                .items
                .iter()
                .any(|item| item.field == "server.max_body_size")
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn dotted_keys_and_inline_tables_are_recognized() {
        let raw: Value =
            toml::from_str("server.max_body_size = 100\ndatabase = { pool_wait_timeout_ms = 500 }")
                .unwrap();
        let report = inspect_server(&raw);
        assert!(
            !report
                .items
                .iter()
                .any(|item| item.field == "server.max_body_size"
                    || item.field == "database.pool_wait_timeout_ms")
        );
    }

    #[test]
    fn scanner_report_limits_reject_secrets_and_oversized_details() {
        let mut report = ConfigCheck::inspect(
            &json!({}),
            &json!({"scanner":{"timeout":5}}),
            &[],
            "scanner",
        );
        assert!(report.valid_scanner_report());
        report.public_fields = vec!["scanner.connect_timeout_seconds".into()];
        assert!(report.valid_scanner_report());
        report.public_fields.push("invalid field name".into());
        assert!(!report.valid_scanner_report());
        report.public_fields.clear();
        report.items[0].default_value = Some("x".repeat(1025));
        assert!(!report.valid_scanner_report());
        report.items[0].default_value = None;
        report.items[0].field = "scanner.runtime_token".into();
        assert!(!report.valid_scanner_report());
    }

    #[actix_web::test]
    async fn config_check_api_is_admin_only_without_database_access() {
        use actix_web::{App, HttpMessage, dev::Service, http::StatusCode, test, web};
        for role in [0, 1] {
            let report =
                ConfigCheck::inspect(&json!({}), &json!({"server":{"timeout":30}}), &[], "server");
            let app = test::init_service(
                App::new()
                    .app_data(web::Data::new(report))
                    .wrap_fn(move |req, service| {
                        req.extensions_mut().insert(crate::admin::UserBaseI {
                            id: 1,
                            username: "test-user".into(),
                            role,
                            email: None,
                            limit_login: false,
                            enable_2fa: false,
                        });
                        service.call(req)
                    })
                    .configure(crate::http::configure),
            )
            .await;
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/api/config/check")
                    .to_request(),
            )
            .await;
            assert_eq!(
                response.status(),
                if role == 1 {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                }
            );
            let body: Value = test::read_body_json(response).await;
            assert_eq!(body["success"], role == 1);
            if role == 1 {
                assert_eq!(body["data"]["items"][0]["field"], "server.timeout");
            } else {
                assert!(body.get("data").is_none());
            }
        }
    }
}
