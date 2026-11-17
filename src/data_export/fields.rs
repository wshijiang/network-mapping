//! 导出字段目录（单一事实来源）：Web modal、导出页与 CLI 共用。
//!
//! 列顺序与标签对齐搜索页原「导出当前页 CSV」表头；提取函数作用于
//! `ElasticsearchSearchItem`（本地索引视图）。导出只读本地索引，
//! 「数据来源」恒为「本地」（联测完成的数据已自动入库，自然被覆盖）。

use serde_json::{Value, json};

use crate::elasticsearch::ElasticsearchSearchItem;

/// 时间格式化上下文（系统时区设置）。
pub(crate) struct FormatCtx {
    pub tz: chrono_tz::Tz,
}

impl FormatCtx {
    pub fn new(timezone: &str) -> Self {
        Self {
            tz: timezone.parse().unwrap_or(chrono_tz::Tz::Asia__Shanghai),
        }
    }

    fn time(&self, millis: Option<i64>) -> String {
        millis
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|value| {
                value
                    .with_timezone(&self.tz)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
            })
            .unwrap_or_default()
    }
}

pub(crate) struct FieldDef {
    pub key: &'static str,
    pub label: &'static str,
    pub group: &'static str,
    pub extract: fn(&ElasticsearchSearchItem, &FormatCtx) -> String,
}

fn opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn yes_no(value: bool) -> String {
    if value { "是".into() } else { "否".into() }
}

fn os_value(
    os: &Option<crate::os_detection::OsInference>,
    pick: fn(&crate::os_detection::OsInference) -> String,
) -> String {
    match os {
        Some(os) if os.status == "identified" => pick(os),
        _ => String::new(),
    }
}

fn tech_label(tech: &crate::web_detection::Technology) -> String {
    let mut label = if tech.name.is_empty() {
        tech.id.clone()
    } else {
        tech.name.clone()
    };
    if let Some(version) = &tech.version
        && !tech.version_conflict
    {
        label.push(' ');
        label.push_str(version);
    }
    if tech.version_conflict {
        label.push_str("（版本冲突）");
    }
    label
}

fn network_owner(item: &ElasticsearchSearchItem) -> String {
    let asn = item.asn.as_deref().map(|value| {
        if value.to_ascii_uppercase().starts_with("AS") {
            value.to_owned()
        } else {
            format!("AS{value}")
        }
    });
    let org = item.as_org.as_deref().or(item.isp.as_deref());
    [asn.as_deref(), org]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ")
}

fn location(item: &ElasticsearchSearchItem) -> String {
    let country = match (
        item.country_name.as_deref().filter(|v| !v.is_empty()),
        item.country_code.as_deref().filter(|v| !v.is_empty()),
    ) {
        (Some(name), Some(code)) => format!("{name} ({code})"),
        (Some(name), None) => name.to_owned(),
        (None, Some(code)) => code.to_owned(),
        (None, None) => String::new(),
    };
    [
        country,
        item.region_name.clone().unwrap_or_default(),
        item.city_name.clone().unwrap_or_default(),
    ]
    .into_iter()
    .filter(|value| !value.is_empty())
    .collect::<Vec<_>>()
    .join(" · ")
}

/// 目录顺序即默认 CSV 列顺序（对齐搜索页原当前页导出表头）。
pub(crate) static CATALOG: &[FieldDef] = &[
    FieldDef {
        key: "ip",
        label: "IP",
        group: "基础",
        extract: |item, _| item.ip_address.clone(),
    },
    FieldDef {
        key: "port",
        label: "端口",
        group: "基础",
        extract: |item, _| item.port.to_string(),
    },
    FieldDef {
        key: "protocol",
        label: "协议",
        group: "基础",
        extract: |item, _| opt(&item.protocol),
    },
    FieldDef {
        key: "service",
        label: "服务",
        group: "基础",
        extract: |item, _| opt(&item.service),
    },
    FieldDef {
        key: "banner",
        label: "Banner",
        group: "基础",
        extract: |item, _| opt(&item.banner),
    },
    FieldDef {
        key: "os_family",
        label: "系统家族",
        group: "系统",
        extract: |item, _| os_value(&item.os, |os| opt(&os.family)),
    },
    FieldDef {
        key: "os_distribution",
        label: "系统发行版",
        group: "系统",
        extract: |item, _| os_value(&item.os, |os| opt(&os.distribution)),
    },
    FieldDef {
        key: "os_version",
        label: "系统版本",
        group: "系统",
        extract: |item, _| os_value(&item.os, |os| opt(&os.version)),
    },
    FieldDef {
        key: "os_status",
        label: "系统识别状态",
        group: "系统",
        extract: |item, _| {
            item.os
                .as_ref()
                .map(|os| os.status.clone())
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "os_confidence",
        label: "系统置信度",
        group: "系统",
        extract: |item, _| os_value(&item.os, |os| os.confidence.clone()),
    },
    FieldDef {
        key: "os_scope",
        label: "系统判断对象",
        group: "系统",
        extract: |item, _| {
            item.os
                .as_ref()
                .map(|os| os.inference_scope.clone())
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "os_observed_at",
        label: "系统证据时间",
        group: "系统",
        extract: |item, ctx| {
            item.os
                .as_ref()
                .map(|os| ctx.time(os.observed_at))
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "os_stale",
        label: "系统证据过期",
        group: "系统",
        extract: |item, _| {
            item.os
                .as_ref()
                .map(|os| yes_no(os.stale))
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "tech",
        label: "技术栈",
        group: "技术栈",
        extract: |item, _| {
            item.web
                .as_ref()
                .map(|web| {
                    if matches!(web.status.as_str(), "identified" | "partial") {
                        web.technologies
                            .iter()
                            .map(tech_label)
                            .collect::<Vec<_>>()
                            .join("；")
                    } else {
                        String::new()
                    }
                })
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "web_status",
        label: "Web 识别状态",
        group: "技术栈",
        extract: |item, _| {
            item.web
                .as_ref()
                .map(|web| web.status.clone())
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "web_observed_at",
        label: "Web 证据时间",
        group: "技术栈",
        extract: |item, ctx| {
            item.web
                .as_ref()
                .map(|web| ctx.time(web.observed_at))
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "web_stale",
        label: "Web 证据过期",
        group: "技术栈",
        extract: |item, _| {
            item.web
                .as_ref()
                .map(|web| yes_no(web.stale))
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "web_ruleset_version",
        label: "Web 规则版本",
        group: "技术栈",
        extract: |item, _| {
            item.web
                .as_ref()
                .map(|web| web.ruleset_version.clone())
                .unwrap_or_default()
        },
    },
    FieldDef {
        key: "title",
        label: "网页标题",
        group: "基础",
        extract: |item, _| opt(&item.title),
    },
    FieldDef {
        key: "tls_mode",
        label: "TLS 模式",
        group: "TLS",
        extract: |item, _| opt(&item.tls_mode),
    },
    FieldDef {
        key: "tls_version",
        label: "TLS 版本",
        group: "TLS",
        extract: |item, _| opt(&item.tls_version),
    },
    FieldDef {
        key: "tls_cipher_suite",
        label: "TLS 密码套件",
        group: "TLS",
        extract: |item, _| opt(&item.tls_cipher_suite),
    },
    FieldDef {
        key: "tls_subject",
        label: "证书主体",
        group: "TLS",
        extract: |item, _| opt(&item.tls_subject),
    },
    FieldDef {
        key: "tls_issuer",
        label: "证书签发者",
        group: "TLS",
        extract: |item, _| opt(&item.tls_issuer),
    },
    FieldDef {
        key: "tls_names",
        label: "证书名称",
        group: "TLS",
        extract: |item, _| item.tls_names.join("、"),
    },
    FieldDef {
        key: "tls_serial_number",
        label: "证书序列号",
        group: "TLS",
        extract: |item, _| opt(&item.tls_serial_number),
    },
    FieldDef {
        key: "tls_not_before",
        label: "证书生效时间",
        group: "TLS",
        extract: |item, ctx| ctx.time(item.tls_not_before),
    },
    FieldDef {
        key: "tls_not_after",
        label: "证书失效时间",
        group: "TLS",
        extract: |item, ctx| ctx.time(item.tls_not_after),
    },
    FieldDef {
        key: "tls_fingerprint_sha256",
        label: "证书 SHA-256 指纹",
        group: "TLS",
        extract: |item, _| opt(&item.tls_fingerprint_sha256),
    },
    FieldDef {
        key: "tls_self_signed",
        label: "是否自签名",
        group: "TLS",
        extract: |item, _| item.tls_self_signed.map(yes_no).unwrap_or_default(),
    },
    FieldDef {
        key: "network_owner",
        label: "ASN / AS 组织",
        group: "归属",
        extract: |item, _| network_owner(item),
    },
    FieldDef {
        key: "location",
        label: "位置",
        group: "归属",
        extract: |item, _| location(item),
    },
    FieldDef {
        key: "scan_time",
        label: "扫描时间",
        group: "基础",
        extract: |item, ctx| ctx.time(Some(item.scan_time)),
    },
    FieldDef {
        key: "tags",
        label: "标签",
        group: "基础",
        extract: |item, _| {
            item.tags
                .iter()
                .map(|tag| tag.name.clone())
                .collect::<Vec<_>>()
                .join("、")
        },
    },
    FieldDef {
        key: "data_origin",
        label: "数据来源",
        group: "基础",
        extract: |_, _| "本地".into(),
    },
];

pub(crate) fn find(key: &str) -> Option<&'static FieldDef> {
    CATALOG.iter().find(|field| field.key == key)
}

pub(crate) fn default_keys() -> Vec<String> {
    CATALOG.iter().map(|field| field.key.to_owned()).collect()
}

/// 校验用户选择的字段：非空、全部已知、无重复；保留用户给定顺序。
pub(crate) fn resolve_keys(keys: &[String]) -> Result<Vec<&'static FieldDef>, String> {
    if keys.is_empty() {
        return Err("至少选择一个导出字段".into());
    }
    let mut resolved = Vec::with_capacity(keys.len());
    for key in keys {
        let field = find(key).ok_or_else(|| format!("未知的导出字段：{key}"))?;
        if resolved.iter().any(|f: &&FieldDef| f.key == field.key) {
            return Err(format!("导出字段重复：{key}"));
        }
        resolved.push(field);
    }
    Ok(resolved)
}

/// `GET /api/data-export/schema` 的字段目录部分。
pub(crate) fn catalog_json() -> Value {
    Value::Array(
        CATALOG
            .iter()
            .map(|field| json!({"key": field.key, "label": field.label, "group": field.group}))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_keys_are_unique_and_defaults_cover_all() {
        let mut keys: Vec<&str> = CATALOG.iter().map(|f| f.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len());
        assert_eq!(default_keys().len(), CATALOG.len());
    }

    #[test]
    fn resolve_rejects_empty_unknown_and_duplicate() {
        assert!(resolve_keys(&[]).is_err());
        assert!(resolve_keys(&["nope".into()]).is_err());
        assert!(resolve_keys(&["ip".into(), "ip".into()]).is_err());
        let resolved = resolve_keys(&["port".into(), "ip".into()]).unwrap();
        assert_eq!(resolved[0].key, "port");
        assert_eq!(resolved[1].key, "ip");
    }

    #[test]
    fn network_owner_and_location_match_frontend_rules() {
        let mut item = ElasticsearchSearchItem::test_stub("192.0.2.1", 443);
        item.asn = Some("4134".into());
        item.as_org = Some("Example Network".into());
        item.country_name = Some("China".into());
        item.country_code = Some("CN".into());
        item.city_name = Some("Shanghai".into());
        assert_eq!(network_owner(&item), "AS4134 · Example Network");
        assert_eq!(location(&item), "China (CN) · Shanghai");
        item.asn = Some("AS4134".into());
        assert_eq!(network_owner(&item), "AS4134 · Example Network");
    }

    #[test]
    fn time_formats_in_configured_timezone() {
        let ctx = FormatCtx::new("Asia/Shanghai");
        // 2026-11-17T00:00:00Z → 08:00 北京时间。
        assert_eq!(ctx.time(Some(1_794_873_600_000)), "2026-11-17 08:00:00");
        assert_eq!(ctx.time(None), "");
        assert_eq!(
            FormatCtx::new("Invalid/Zone").time(Some(0)),
            "1970-01-01 08:00:00"
        );
    }
}
