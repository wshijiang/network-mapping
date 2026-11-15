//! CSV 流式解析、逐字段校验与文件内去重。
//!
//! 解析与校验均为纯逻辑（不依赖数据库/ES），便于单元测试。
//! 写入由 [`crate::data_import::worker`] 经现有 result_ingest 管道完成。

use std::collections::{HashMap, VecDeque};
use std::io::Read;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::schema;

/// 单行解析错误（行号从 1 起，不含头部）。
#[derive(Clone, Debug, Serialize)]
pub struct RowError {
    pub row: i64,
    pub column: String,
    pub value: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TechEntry {
    pub id: String,
    pub version: Option<String>,
}

/// 校验并归一化后的一行。
#[derive(Clone, Debug)]
pub struct ImportRow {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub observed_at: i64,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub source: String,
    pub asn: Option<String>,
    pub as_org: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region_name: Option<String>,
    pub city_name: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub os: Option<String>,
    pub os_confidence: Option<String>,
    pub tech: Vec<TechEntry>,
    pub title: Option<String>,
    pub kind: &'static str,
}

impl ImportRow {
    pub fn endpoint_key(&self) -> String {
        format!("{}|{}|{}", self.ip, self.port, self.protocol)
    }

    /// 内容指纹（用于去重）：覆盖所有可能影响观察的字段。
    pub fn content_hash(&self) -> String {
        let payload = serde_json::json!([
            self.kind,
            self.ip,
            self.port,
            self.protocol,
            self.observed_at,
            self.service,
            self.banner,
            self.source,
            self.asn,
            self.as_org,
            self.country_code,
            self.country_name,
            self.region_name,
            self.city_name,
            self.latitude,
            self.longitude,
            self.os,
            self.os_confidence,
            self.tech
                .iter()
                .map(|t| format!("{}@{}", t.id, t.version.clone().unwrap_or_default()))
                .collect::<Vec<_>>(),
            self.title,
        ]);
        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let digest = Sha256::digest(&bytes);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Clone, Debug)]
pub struct ParseOptions {
    pub now_ms: i64,
    pub future_tolerance_ms: i64,
    pub max_banner_bytes: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            now_ms: Utc::now().timestamp_millis(),
            future_tolerance_ms: 300_000,
            max_banner_bytes: 64 * 1024,
        }
    }
}

/// 内部头部 -> 文件列下标。
pub type ColumnMap = HashMap<String, usize>;

pub fn build_column_map(
    file_headers: &[String],
    mapping: &std::collections::BTreeMap<String, String>,
) -> Result<ColumnMap, String> {
    let normalized: Vec<String> = file_headers
        .iter()
        .map(|h| schema::normalize_header(h))
        .collect();
    let mut map = ColumnMap::new();
    for (internal, file_header) in mapping {
        let norm = schema::normalize_header(file_header);
        let index = normalized
            .iter()
            .position(|h| *h == norm)
            .ok_or_else(|| format!("映射的文件头部不存在：{file_header}"))?;
        map.insert(internal.clone(), index);
    }
    Ok(map)
}

/// 读取首个逻辑 CSV 记录作为头部（处理 BOM/引号内换行）。
pub fn read_headers<R: Read>(reader: R) -> Result<Vec<String>, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(reader);
    let mut record = csv::StringRecord::new();
    if !csv
        .read_record(&mut record)
        .map_err(|e| format!("CSV 头部解析失败：{e}"))?
    {
        return Err("文件为空或缺少头部".into());
    }
    let headers: Vec<String> = record
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let trimmed = value.trim();
            if i == 0 {
                trimmed.trim_start_matches('\u{feff}').to_owned()
            } else {
                trimmed.to_owned()
            }
        })
        .collect();
    if headers.iter().any(|h| h.is_empty()) {
        return Err("头部存在空列名".into());
    }
    let mut seen = std::collections::HashSet::new();
    for header in &headers {
        if !seen.insert(schema::normalize_header(header)) {
            return Err(format!("头部存在重复列名：{header}"));
        }
    }
    if headers.len() > 128 {
        return Err("头部列数超过上限 128".into());
    }
    Ok(headers)
}

fn cell<'a>(record: &'a csv::StringRecord, map: &ColumnMap, name: &str) -> Option<&'a str> {
    map.get(name)
        .and_then(|index| record.get(*index))
        .map(str::trim)
}

fn clean_text(value: &str) -> String {
    value
        .replace('\0', "")
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect::<String>()
        .trim()
        .to_owned()
}

fn optional_text(
    value: Option<&str>,
    max_chars: usize,
    column: &str,
    errors: &mut Vec<RowError>,
    row: i64,
) -> Option<String> {
    let raw = value?;
    if raw.is_empty() {
        return None;
    }
    let cleaned = clean_text(raw);
    if cleaned.is_empty() {
        return None;
    }
    if cleaned.chars().count() > max_chars {
        errors.push(RowError {
            row,
            column: column.into(),
            value: truncate(raw),
            reason: format!("超过长度上限 {max_chars} 字符"),
        });
        return None;
    }
    Some(cleaned)
}

fn truncate(value: &str) -> String {
    value.chars().take(128).collect()
}

fn parse_ip(value: &str) -> Result<String, String> {
    let ip: std::net::IpAddr = value
        .parse()
        .map_err(|_| "不是合法的 IPv4/IPv6 地址".to_string())?;
    let rejected = ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast());
    if rejected {
        return Err("拒绝非单播地址（回环/组播/广播/未指定）".into());
    }
    Ok(ip.to_string())
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port: u32 = value.parse().map_err(|_| "端口不是整数".to_string())?;
    if port == 0 || port > 65535 {
        return Err("端口超出范围 1–65535".into());
    }
    Ok(port as u16)
}

fn parse_protocol(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok("tcp".into()),
        "udp" => Ok("udp".into()),
        _ => Err("协议必须为 tcp 或 udp".into()),
    }
}

pub fn parse_timestamp(value: &str, opts: &ParseOptions) -> Result<i64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("观测时间为空".into());
    }
    let ms = if trimmed.bytes().all(|b| b.is_ascii_digit()) {
        let number: i64 = trimmed.parse().map_err(|_| "时间戳超出范围".to_string())?;
        if number > 1_000_000_000_000 {
            number
        } else {
            number.saturating_mul(1000)
        }
    } else if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        dt.timestamp_millis()
    } else if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S"))
    {
        Utc.from_utc_datetime(&naive).timestamp_millis()
    } else if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap())
            .timestamp_millis()
    } else {
        return Err("无法解析时间（epoch 毫秒/秒或 ISO8601）".into());
    };
    if ms <= 0 {
        return Err("观测时间必须为正".into());
    }
    if ms > opts.now_ms.saturating_add(opts.future_tolerance_ms) {
        return Err("观测时间晚于当前时间+容差".into());
    }
    Ok(ms)
}

fn parse_asn(value: &str) -> Result<String, String> {
    let digits = value
        .trim()
        .trim_start_matches("AS")
        .trim_start_matches("as")
        .trim();
    let number: u32 = digits
        .parse()
        .map_err(|_| "AS 号必须为数字（可带 AS 前缀）".to_string())?;
    Ok(number.to_string())
}

fn parse_float(value: &str, min: f64, max: f64) -> Result<f64, String> {
    let number: f64 = value.parse().map_err(|_| "不是合法数值".to_string())?;
    if !number.is_finite() || number < min || number > max {
        return Err(format!("超出范围 {min}..{max}"));
    }
    Ok(number)
}

fn parse_tech(value: &str) -> Result<Vec<TechEntry>, String> {
    let mut entries = Vec::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (id, version) = match part.split_once('@') {
            Some((id, version)) => (id.trim(), Some(version.trim().to_owned())),
            None => (part, None),
        };
        let id = id.to_ascii_lowercase();
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("技术 id 非法：{id}"));
        }
        if let Some(version) = &version
            && version.len() > 64
        {
            return Err(format!("技术版本超长：{id}"));
        }
        entries.push(TechEntry {
            id,
            version: version.filter(|v| !v.is_empty()),
        });
        if entries.len() > 64 {
            return Err("技术项数超过上限 64".into());
        }
    }
    Ok(entries)
}

/// 解析并校验单行。成功返回归一化行；失败返回错误列表（可能多条）。
pub fn parse_record(
    record: &csv::StringRecord,
    row: i64,
    map: &ColumnMap,
    opts: &ParseOptions,
) -> Result<ImportRow, Vec<RowError>> {
    let mut errors: Vec<RowError> = Vec::new();
    let mut require = |name: &str| -> Option<String> {
        let column = name.to_string();
        match cell(record, map, name) {
            None => {
                errors.push(RowError {
                    row,
                    column,
                    value: String::new(),
                    reason: "缺少必须字段".into(),
                });
                None
            }
            Some(value) if value.is_empty() => {
                errors.push(RowError {
                    row,
                    column,
                    value: String::new(),
                    reason: "必须字段为空".into(),
                });
                None
            }
            Some(value) => Some(value.to_owned()),
        }
    };

    let ip_raw = require("ip");
    let port_raw = require("port");
    let protocol_raw = require("protocol");
    let time_raw = require("observed_at");

    let ip = ip_raw.and_then(|v| {
        parse_ip(&v)
            .map_err(|e| {
                errors.push(RowError {
                    row,
                    column: "ip".into(),
                    value: truncate(&v),
                    reason: e,
                });
            })
            .ok()
    });
    let port = port_raw.and_then(|v| {
        parse_port(&v)
            .map_err(|e| {
                errors.push(RowError {
                    row,
                    column: "port".into(),
                    value: truncate(&v),
                    reason: e,
                });
            })
            .ok()
    });
    let protocol = protocol_raw.and_then(|v| {
        parse_protocol(&v)
            .map_err(|e| {
                errors.push(RowError {
                    row,
                    column: "protocol".into(),
                    value: truncate(&v),
                    reason: e,
                });
            })
            .ok()
    });
    let observed_at = time_raw.and_then(|v| {
        parse_timestamp(&v, opts)
            .map_err(|e| {
                errors.push(RowError {
                    row,
                    column: "observed_at".into(),
                    value: truncate(&v),
                    reason: e,
                });
            })
            .ok()
    });

    let service = optional_text(
        cell(record, map, "service"),
        128,
        "service",
        &mut errors,
        row,
    );
    let banner = cell(record, map, "banner")
        .filter(|v| !v.is_empty())
        .and_then(|v| {
            let cleaned = clean_text(v);
            if cleaned.len() > opts.max_banner_bytes {
                errors.push(RowError {
                    row,
                    column: "banner".into(),
                    value: truncate(v),
                    reason: "横幅超过 64KB".into(),
                });
                None
            } else {
                Some(cleaned)
            }
        });
    let source = optional_text(cell(record, map, "source"), 64, "source", &mut errors, row)
        .unwrap_or_else(|| "import".to_owned());
    let asn = cell(record, map, "asn")
        .filter(|v| !v.is_empty())
        .and_then(|v| {
            parse_asn(v)
                .map_err(|e| {
                    errors.push(RowError {
                        row,
                        column: "asn".into(),
                        value: truncate(v),
                        reason: e,
                    });
                })
                .ok()
        });
    let as_org = optional_text(cell(record, map, "as_org"), 256, "as_org", &mut errors, row);
    let country_code = cell(record, map, "country_code")
        .filter(|v| !v.is_empty())
        .and_then(|v| {
            let upper = v.trim().to_ascii_uppercase();
            if upper.len() == 2 && upper.bytes().all(|b| b.is_ascii_alphabetic()) {
                Some(upper)
            } else {
                errors.push(RowError {
                    row,
                    column: "country_code".into(),
                    value: truncate(v),
                    reason: "国家代码须为两位字母".into(),
                });
                None
            }
        });
    let country_name = optional_text(
        cell(record, map, "country_name"),
        128,
        "country_name",
        &mut errors,
        row,
    );
    let region_name = optional_text(
        cell(record, map, "region_name"),
        128,
        "region_name",
        &mut errors,
        row,
    );
    let city_name = optional_text(
        cell(record, map, "city_name"),
        128,
        "city_name",
        &mut errors,
        row,
    );
    let latitude = cell(record, map, "latitude")
        .filter(|v| !v.is_empty())
        .and_then(|v| {
            parse_float(v, -90.0, 90.0)
                .map_err(|e| {
                    errors.push(RowError {
                        row,
                        column: "latitude".into(),
                        value: truncate(v),
                        reason: e,
                    });
                })
                .ok()
        });
    let longitude = cell(record, map, "longitude")
        .filter(|v| !v.is_empty())
        .and_then(|v| {
            parse_float(v, -180.0, 180.0)
                .map_err(|e| {
                    errors.push(RowError {
                        row,
                        column: "longitude".into(),
                        value: truncate(v),
                        reason: e,
                    });
                })
                .ok()
        });
    let os = optional_text(cell(record, map, "os"), 64, "os", &mut errors, row)
        .map(|v| v.to_ascii_lowercase());
    let os_confidence = cell(record, map, "os_confidence")
        .filter(|v| !v.is_empty())
        .and_then(|v| match v.to_ascii_lowercase().as_str() {
            "medium" => Some("medium".to_owned()),
            "high" => Some("high".to_owned()),
            _ => {
                errors.push(RowError {
                    row,
                    column: "os_confidence".into(),
                    value: truncate(v),
                    reason: "置信度须为 medium/high".into(),
                });
                None
            }
        });
    let tech = cell(record, map, "tech")
        .filter(|v| !v.is_empty())
        .map(|v| {
            parse_tech(v)
                .map_err(|e| {
                    errors.push(RowError {
                        row,
                        column: "tech".into(),
                        value: truncate(v),
                        reason: e,
                    });
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let title = optional_text(cell(record, map, "title"), 512, "title", &mut errors, row);

    if os_confidence.is_some() && os.is_none() {
        errors.push(RowError {
            row,
            column: "os_confidence".into(),
            value: String::new(),
            reason: "指定 os_confidence 但未指定 os".into(),
        });
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let kind = if service.is_some() || title.is_some() || os.is_some() || !tech.is_empty() {
        "service"
    } else {
        "port"
    };
    Ok(ImportRow {
        ip: ip.unwrap(),
        port: port.unwrap(),
        protocol: protocol.unwrap(),
        observed_at: observed_at.unwrap(),
        service,
        banner,
        source,
        asn,
        as_org,
        country_code,
        country_name,
        region_name,
        city_name,
        latitude,
        longitude,
        os,
        os_confidence,
        tech,
        title,
        kind,
    })
}

/// 去重判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DedupOutcome {
    New,
    Duplicate,
    Conflict,
}

/// 有界文件内去重窗口（FIFO 淘汰）。
pub struct DedupWindow {
    capacity: usize,
    seen: HashMap<(String, i64), String>,
    order: VecDeque<(String, i64)>,
}

impl DedupWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn observe(&mut self, row: &ImportRow) -> DedupOutcome {
        let key = (row.endpoint_key(), row.observed_at);
        let hash = row.content_hash();
        let outcome = match self.seen.get(&key) {
            None => DedupOutcome::New,
            Some(existing) if *existing == hash => DedupOutcome::Duplicate,
            Some(_) => DedupOutcome::Conflict,
        };
        if outcome != DedupOutcome::Duplicate {
            if self.seen.insert(key.clone(), hash).is_none() {
                self.order.push_back(key.clone());
                while self.order.len() > self.capacity {
                    if let Some(evicted) = self.order.pop_front() {
                        self.seen.remove(&evicted);
                    }
                }
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn opts() -> ParseOptions {
        ParseOptions {
            now_ms: 1_800_000_000_000,
            future_tolerance_ms: 300_000,
            max_banner_bytes: 64 * 1024,
        }
    }

    fn map_for(headers: &[&str]) -> ColumnMap {
        let file: Vec<String> = headers.iter().map(|s| s.to_string()).collect();
        let mut mapping = BTreeMap::new();
        for name in ["ip", "port", "protocol", "observed_at"] {
            mapping.insert(name.to_string(), name.to_string());
        }
        build_column_map(&file, &mapping).unwrap()
    }

    fn record(values: &[&str]) -> csv::StringRecord {
        csv::StringRecord::from(values.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_valid_row() {
        let map = map_for(&["ip", "port", "protocol", "observed_at"]);
        let rec = record(&["192.0.2.1", "443", "TCP", "1700000000000"]);
        let row = parse_record(&rec, 1, &map, &opts()).unwrap();
        assert_eq!(row.ip, "192.0.2.1");
        assert_eq!(row.port, 443);
        assert_eq!(row.protocol, "tcp");
        assert_eq!(row.observed_at, 1_700_000_000_000);
        assert_eq!(row.kind, "port");
        assert_eq!(row.source, "import");
    }

    #[test]
    fn rejects_non_unicast_and_bad_port() {
        let map = map_for(&["ip", "port", "protocol", "observed_at"]);
        for ip in [
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
        ] {
            let rec = record(&[ip, "80", "tcp", "1700000000000"]);
            assert!(parse_record(&rec, 1, &map, &opts()).is_err(), "{ip}");
        }
        let rec = record(&["192.0.2.1", "0", "tcp", "1700000000000"]);
        assert!(parse_record(&rec, 1, &map, &opts()).is_err());
    }

    #[test]
    fn rejects_future_timestamp() {
        let map = map_for(&["ip", "port", "protocol", "observed_at"]);
        let rec = record(&["192.0.2.1", "80", "tcp", "1900000000000"]);
        assert!(parse_record(&rec, 1, &map, &opts()).is_err());
    }

    #[test]
    fn timestamp_formats() {
        let o = opts();
        assert_eq!(
            parse_timestamp("1700000000", &o).unwrap(),
            1_700_000_000_000
        );
        assert_eq!(
            parse_timestamp("1700000000000", &o).unwrap(),
            1_700_000_000_000
        );
        assert_eq!(
            parse_timestamp("2023-11-14T22:13:20Z", &o).unwrap(),
            1_700_000_000_000
        );
        assert_eq!(
            parse_timestamp("2023-11-14 22:13:20", &o).unwrap(),
            1_700_000_000_000
        );
        assert!(parse_timestamp("not-a-time", &o).is_err());
    }

    #[test]
    fn service_kind_and_tech() {
        let file: Vec<String> = [
            "ip",
            "port",
            "protocol",
            "observed_at",
            "service",
            "tech",
            "title",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut mapping = BTreeMap::new();
        for name in [
            "ip",
            "port",
            "protocol",
            "observed_at",
            "service",
            "tech",
            "title",
        ] {
            mapping.insert(name.to_string(), name.to_string());
        }
        let map = build_column_map(&file, &mapping).unwrap();
        let rec = record(&[
            "192.0.2.1",
            "443",
            "tcp",
            "1700000000000",
            "https",
            "nginx@1.25.3;jquery",
            "Example",
        ]);
        let row = parse_record(&rec, 1, &map, &opts()).unwrap();
        assert_eq!(row.kind, "service");
        assert_eq!(row.tech.len(), 2);
        assert_eq!(row.tech[0].id, "nginx");
        assert_eq!(row.tech[0].version.as_deref(), Some("1.25.3"));
        assert_eq!(row.title.as_deref(), Some("Example"));
    }

    #[test]
    fn asn_normalization_and_confidence_requires_os() {
        let file: Vec<String> = [
            "ip",
            "port",
            "protocol",
            "observed_at",
            "asn",
            "os_confidence",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut mapping = BTreeMap::new();
        for name in [
            "ip",
            "port",
            "protocol",
            "observed_at",
            "asn",
            "os_confidence",
        ] {
            mapping.insert(name.to_string(), name.to_string());
        }
        let map = build_column_map(&file, &mapping).unwrap();
        let rec = record(&["192.0.2.1", "80", "tcp", "1700000000000", "AS12345", "high"]);
        let err = parse_record(&rec, 1, &map, &opts()).unwrap_err();
        assert!(err.iter().any(|e| e.column == "os_confidence"));
        let rec = record(&["192.0.2.1", "80", "tcp", "1700000000000", "AS12345", ""]);
        let row = parse_record(&rec, 1, &map, &opts()).unwrap();
        assert_eq!(row.asn.as_deref(), Some("12345"));
    }

    #[test]
    fn dedup_new_duplicate_conflict() {
        let map = map_for(&["ip", "port", "protocol", "observed_at"]);
        let row = parse_record(
            &record(&["192.0.2.1", "80", "tcp", "1700000000000"]),
            1,
            &map,
            &opts(),
        )
        .unwrap();
        let mut window = DedupWindow::new(10);
        assert_eq!(window.observe(&row), DedupOutcome::New);
        assert_eq!(window.observe(&row), DedupOutcome::Duplicate);
        let mut changed = row.clone();
        changed.service = Some("http".into());
        changed.kind = "service";
        assert_eq!(window.observe(&changed), DedupOutcome::Conflict);
    }

    #[test]
    fn reads_headers_with_bom_and_quotes() {
        let data = "\u{feff}ip,\"port,extra\",protocol\r\n192.0.2.1,80,tcp\r\n";
        let headers = read_headers(data.as_bytes()).unwrap();
        assert_eq!(headers, vec!["ip", "port,extra", "protocol"]);
    }

    #[test]
    fn rejects_duplicate_header() {
        let data = "ip,IP,port\n";
        assert!(read_headers(data.as_bytes()).is_err());
    }
}
