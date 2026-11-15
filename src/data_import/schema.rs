//! CSV 导入头部规范（单一事实来源）。
//!
//! Web 经 `GET /api/data-import/schema` 获取本规范做自动配对与映射校验；
//! CLI `import check` 与后端校验共用同一份别名/必须标记/类型定义。

use serde::Serialize;
use std::collections::BTreeMap;

/// 字段类型标签，驱动 [`crate::data_import::csv`] 的逐字段校验。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Ip,
    Port,
    Protocol,
    Timestamp,
    Service,
    Banner,
    Source,
    Asn,
    AsOrg,
    CountryCode,
    CountryName,
    RegionName,
    CityName,
    Latitude,
    Longitude,
    Os,
    OsConfidence,
    Tech,
    Title,
}

impl FieldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Port => "port",
            Self::Protocol => "protocol",
            Self::Timestamp => "timestamp",
            Self::Service => "service",
            Self::Banner => "banner",
            Self::Source => "source",
            Self::Asn => "asn",
            Self::AsOrg => "as_org",
            Self::CountryCode => "country_code",
            Self::CountryName => "country_name",
            Self::RegionName => "region_name",
            Self::CityName => "city_name",
            Self::Latitude => "latitude",
            Self::Longitude => "longitude",
            Self::Os => "os",
            Self::OsConfidence => "os_confidence",
            Self::Tech => "tech",
            Self::Title => "title",
        }
    }
}

#[derive(Clone, Debug)]
pub struct HeaderField {
    pub name: &'static str,
    pub required: bool,
    pub kind: FieldKind,
    pub aliases: &'static [&'static str],
    pub description: &'static str,
}

/// 内部头部规范。必须头部：ip / port / protocol / observed_at。
pub const HEADERS: &[HeaderField] = &[
    HeaderField {
        name: "ip",
        required: true,
        kind: FieldKind::Ip,
        aliases: &[
            "ip",
            "ip_address",
            "ipaddr",
            "address",
            "host",
            "目标ip",
            "ip地址",
        ],
        description: "IPv4/IPv6 地址（拒绝 CIDR/主机名与非单播地址）",
    },
    HeaderField {
        name: "port",
        required: true,
        kind: FieldKind::Port,
        aliases: &["port", "端口"],
        description: "端口号 1–65535",
    },
    HeaderField {
        name: "protocol",
        required: true,
        kind: FieldKind::Protocol,
        aliases: &["protocol", "proto", "协议"],
        description: "tcp 或 udp",
    },
    HeaderField {
        name: "observed_at",
        required: true,
        kind: FieldKind::Timestamp,
        aliases: &[
            "observed_at",
            "last_seen",
            "time",
            "timestamp",
            "时间",
            "观测时间",
        ],
        description: "观测时间：epoch 毫秒/秒或 ISO8601（无时区按 UTC），不得晚于当前时间+容差",
    },
    HeaderField {
        name: "service",
        required: false,
        kind: FieldKind::Service,
        aliases: &["service", "service_name", "服务"],
        description: "服务名（≤128 字符）",
    },
    HeaderField {
        name: "banner",
        required: false,
        kind: FieldKind::Banner,
        aliases: &["banner", "response", "横幅"],
        description: "服务横幅（≤64KB，剔除 NUL）",
    },
    HeaderField {
        name: "source",
        required: false,
        kind: FieldKind::Source,
        aliases: &["source", "来源"],
        description: "数据来源标记（≤64 字符，默认 import）",
    },
    HeaderField {
        name: "asn",
        required: false,
        kind: FieldKind::Asn,
        aliases: &["asn", "as_number", "as号"],
        description: "AS 号（AS12345 或 12345，归一化为纯数字）；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "as_org",
        required: false,
        kind: FieldKind::AsOrg,
        aliases: &["as_org", "as_organization", "as组织", "as名称"],
        description: "AS 组织（≤256 字符）；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "country_code",
        required: false,
        kind: FieldKind::CountryCode,
        aliases: &["country_code", "country", "国家代码"],
        description: "ISO 3166-1 alpha-2 国家代码；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "country_name",
        required: false,
        kind: FieldKind::CountryName,
        aliases: &["country_name", "国家名称"],
        description: "国家名称（≤128 字符）；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "region_name",
        required: false,
        kind: FieldKind::RegionName,
        aliases: &["region_name", "region", "province", "省份", "地区"],
        description: "省/地区（≤128 字符）；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "city_name",
        required: false,
        kind: FieldKind::CityName,
        aliases: &["city_name", "city", "城市"],
        description: "城市（≤128 字符）；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "latitude",
        required: false,
        kind: FieldKind::Latitude,
        aliases: &["latitude", "lat", "纬度"],
        description: "纬度 -90..90；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "longitude",
        required: false,
        kind: FieldKind::Longitude,
        aliases: &["longitude", "lon", "lng", "经度"],
        description: "经度 -180..180；缺省由 MaxMind 补全",
    },
    HeaderField {
        name: "os",
        required: false,
        kind: FieldKind::Os,
        aliases: &["os", "os_family", "操作系统", "系统"],
        description: "操作系统家族（如 windows/linux/unix，≤64 字符）；缺省由检测管道派生",
    },
    HeaderField {
        name: "os_confidence",
        required: false,
        kind: FieldKind::OsConfidence,
        aliases: &["os_confidence", "系统置信度"],
        description: "OS 置信度 medium/high（默认 high）",
    },
    HeaderField {
        name: "tech",
        required: false,
        kind: FieldKind::Tech,
        aliases: &["tech", "web", "technologies", "web技术", "技术栈"],
        description: "Web 技术：分号分隔 id[@version]（如 nginx@1.25.3;jquery@3.7.1，≤64 项）",
    },
    HeaderField {
        name: "title",
        required: false,
        kind: FieldKind::Title,
        aliases: &["title", "web_title", "网页标题", "标题"],
        description: "网页标题（≤512 字符）",
    },
];

pub fn field(name: &str) -> Option<&'static HeaderField> {
    HEADERS.iter().find(|header| header.name == name)
}

pub fn required_headers() -> Vec<&'static str> {
    HEADERS
        .iter()
        .filter(|h| h.required)
        .map(|h| h.name)
        .collect()
}

/// 归一化头部名：去首尾空白 + 小写 + 去 BOM。
pub fn normalize_header(value: &str) -> String {
    value
        .trim_start_matches('\u{feff}')
        .trim()
        .to_ascii_lowercase()
}

/// 自动配对结果。
#[derive(Clone, Debug, Default)]
pub struct MatchResult {
    /// 内部头部 -> 文件头部（原文）。
    pub mapping: BTreeMap<String, String>,
    /// 未配对的必须头部。
    pub unmatched_required: Vec<String>,
    /// 未被映射的文件头部（将忽略）。
    pub ignored_file_headers: Vec<String>,
    /// 多个文件列匹配同一内部头部导致的冲突（内部头部名）。
    pub conflicts: Vec<String>,
}

/// 依据规范自动配对文件头部。冲突（多文件列匹配同一内部头部）时该内部头部留空待手动指定。
pub fn auto_match(file_headers: &[String]) -> MatchResult {
    let mut result = MatchResult::default();
    let normalized_file: Vec<(String, &String)> = file_headers
        .iter()
        .map(|raw| (normalize_header(raw), raw))
        .collect();
    let mut used_file: Vec<bool> = vec![false; file_headers.len()];

    for header in HEADERS {
        let mut candidates: Vec<usize> = Vec::new();
        for (index, (norm, _)) in normalized_file.iter().enumerate() {
            if used_file[index] {
                continue;
            }
            if header.aliases.iter().any(|alias| *alias == norm) {
                candidates.push(index);
            }
        }
        match candidates.len() {
            0 => {
                if header.required {
                    result.unmatched_required.push(header.name.to_owned());
                }
            }
            1 => {
                let index = candidates[0];
                used_file[index] = true;
                result
                    .mapping
                    .insert(header.name.to_owned(), file_headers[index].clone());
            }
            _ => {
                result.conflicts.push(header.name.to_owned());
                if header.required {
                    result.unmatched_required.push(header.name.to_owned());
                }
            }
        }
    }
    for (index, raw) in file_headers.iter().enumerate() {
        if !used_file[index] {
            result.ignored_file_headers.push(raw.clone());
        }
    }
    result
}

/// 校验用户提交的映射：必须头部齐全、内部头部合法、文件头部存在于文件、无重复占用。
pub fn validate_mapping(
    file_headers: &[String],
    mapping: &BTreeMap<String, String>,
) -> Result<(), String> {
    let normalized_file: Vec<String> = file_headers.iter().map(|h| normalize_header(h)).collect();
    let mut used: Vec<&str> = Vec::new();
    for (internal, file_header) in mapping {
        if field(internal).is_none() {
            return Err(format!("未知的内部头部：{internal}"));
        }
        let norm = normalize_header(file_header);
        if !normalized_file.contains(&norm) {
            return Err(format!("映射的文件头部不存在：{file_header}"));
        }
        if used.contains(&internal.as_str()) {
            return Err(format!("内部头部被重复映射：{internal}"));
        }
        used.push(internal);
    }
    for required in required_headers() {
        if !mapping.contains_key(required) {
            return Err(format!("缺少必须头部映射：{required}"));
        }
    }
    Ok(())
}

// ---- API 序列化 -----------------------------------------------------------

#[derive(Serialize)]
pub struct SchemaHeader {
    pub name: &'static str,
    pub required: bool,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub aliases: &'static [&'static str],
    pub description: &'static str,
}

#[derive(Serialize)]
pub struct SchemaLimits {
    pub max_upload_bytes: u64,
    pub max_rows: u64,
    pub default_batch_size: u32,
    pub max_batch_size: u32,
    pub default_concurrency: u32,
    pub max_concurrency: u32,
}

#[derive(Serialize)]
pub struct SchemaDocument {
    pub headers: Vec<SchemaHeader>,
    pub limits: SchemaLimits,
    pub enums: serde_json::Value,
}

pub fn schema_document(limits: SchemaLimits) -> SchemaDocument {
    SchemaDocument {
        headers: HEADERS
            .iter()
            .map(|h| SchemaHeader {
                name: h.name,
                required: h.required,
                kind: h.kind.as_str(),
                aliases: h.aliases,
                description: h.description,
            })
            .collect(),
        limits,
        enums: serde_json::json!({
            "protocol": ["tcp", "udp"],
            "on_invalid": ["skip", "abort"],
            "overwrite_policy": ["fill", "overwrite"],
            "os_confidence": ["medium", "high"],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn auto_match_exact_and_alias() {
        let result = auto_match(&headers(&["IP_Address", "端口", "proto", "时间"]));
        assert_eq!(
            result.mapping.get("ip").map(String::as_str),
            Some("IP_Address")
        );
        assert_eq!(result.mapping.get("port").map(String::as_str), Some("端口"));
        assert_eq!(
            result.mapping.get("protocol").map(String::as_str),
            Some("proto")
        );
        assert_eq!(
            result.mapping.get("observed_at").map(String::as_str),
            Some("时间")
        );
        assert!(result.unmatched_required.is_empty());
    }

    #[test]
    fn auto_match_missing_required() {
        let result = auto_match(&headers(&["ip", "port"]));
        assert!(result.unmatched_required.contains(&"protocol".to_string()));
        assert!(
            result
                .unmatched_required
                .contains(&"observed_at".to_string())
        );
    }

    #[test]
    fn auto_match_conflict_leaves_unmapped() {
        let result = auto_match(&headers(&["ip", "address", "port", "protocol", "time"]));
        assert!(result.conflicts.contains(&"ip".to_string()));
        assert!(!result.mapping.contains_key("ip"));
        assert!(result.unmatched_required.contains(&"ip".to_string()));
    }

    #[test]
    fn normalize_strips_bom_and_case() {
        assert_eq!(normalize_header("\u{feff} IP "), "ip");
    }

    #[test]
    fn validate_mapping_requires_all_required() {
        let file = headers(&["ip", "port", "protocol", "time"]);
        let mut mapping = BTreeMap::new();
        mapping.insert("ip".to_string(), "ip".to_string());
        assert!(validate_mapping(&file, &mapping).is_err());
        mapping.insert("port".to_string(), "port".to_string());
        mapping.insert("protocol".to_string(), "protocol".to_string());
        mapping.insert("observed_at".to_string(), "time".to_string());
        assert!(validate_mapping(&file, &mapping).is_ok());
    }

    #[test]
    fn validate_mapping_rejects_unknown_internal_and_missing_file() {
        let file = headers(&["ip", "port", "protocol", "time"]);
        let mut mapping = BTreeMap::new();
        mapping.insert("bogus".to_string(), "ip".to_string());
        assert!(validate_mapping(&file, &mapping).is_err());
        let mut mapping = BTreeMap::new();
        for (k, v) in [
            ("ip", "ip"),
            ("port", "port"),
            ("protocol", "protocol"),
            ("observed_at", "nope"),
        ] {
            mapping.insert(k.to_string(), v.to_string());
        }
        assert!(validate_mapping(&file, &mapping).is_err());
    }
}
