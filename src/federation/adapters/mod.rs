//! 平台适配器：Hunter / Quake / FOFA / Shodan。
//!
//! 端点/参数/字段以 2026-11-16 核实的官方文档为准（FEDERATION_PLAN.md §4）。
//! 每个适配器负责：请求构造、响应解析、错误分类、记录归一化、账号探测（probe）。

pub mod fofa;
pub mod hunter;
pub mod quake;
pub mod shodan;

use std::time::Duration;

use serde_json::Value;

use crate::federation::model::{
    Capabilities, FieldSelection, NormalizedRecord, PageRequest, RawPage, SourceError, SourceKind,
};
use crate::federation::translate::PlatformQuery;
use crate::outbound_proxy::ProxyConfig;

pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;
pub const USER_AGENT: &str = "NetworkMapping/1.0 federation";

/// 一次平台查询请求。
pub(crate) struct SearchRequest<'a> {
    pub query: &'a PlatformQuery,
    pub page: PageRequest,
    /// 解析后的时间窗（天）；None = 不指定（§8.6）。
    pub window_days: Option<u32>,
    pub fields: &'a FieldSelection,
    /// 单一 IP 目标（Shodan 免费 host 端点分支）。
    pub single_ip: Option<String>,
    /// include/fields 白名单覆盖（会员降级时由执行器传入）。
    pub field_override: Option<Vec<String>>,
}

#[allow(async_fn_in_trait)]
pub(crate) trait FederationAdapter: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    /// 发起一页查询。
    async fn search(
        &self,
        client: &reqwest::Client,
        credential: &Value,
        request: &SearchRequest<'_>,
    ) -> Result<RawPage, SourceError>;
    /// 原始记录 → 归一化记录；缺 ip/port 或非法返回 None（计入 invalid）。
    fn normalize(
        &self,
        raw: &Value,
        fields: &FieldSelection,
        now_ms: i64,
        future_tolerance_ms: i64,
    ) -> Option<NormalizedRecord>;
    /// 账号信息探测（免费端点）：会员等级、配额。
    async fn probe(
        &self,
        client: &reqwest::Client,
        credential: &Value,
    ) -> Result<Value, SourceError>;
}

/// 枚举分发（async trait 方法不做 dyn 对象，保持对象安全无关）。
pub(crate) enum Adapter {
    Hunter(hunter::Hunter),
    Quake(quake::Quake),
    Fofa(fofa::Fofa),
    Shodan(shodan::Shodan),
}

impl Adapter {
    pub fn for_kind(kind: SourceKind) -> Self {
        match kind {
            SourceKind::Hunter => Self::Hunter(hunter::Hunter),
            SourceKind::Quake => Self::Quake(quake::Quake),
            SourceKind::Fofa => Self::Fofa(fofa::Fofa),
            SourceKind::Shodan => Self::Shodan(shodan::Shodan),
        }
    }

    pub fn capabilities(&self) -> Capabilities {
        match self {
            Self::Hunter(a) => a.capabilities(),
            Self::Quake(a) => a.capabilities(),
            Self::Fofa(a) => a.capabilities(),
            Self::Shodan(a) => a.capabilities(),
        }
    }

    pub async fn search(
        &self,
        client: &reqwest::Client,
        credential: &Value,
        request: &SearchRequest<'_>,
    ) -> Result<RawPage, SourceError> {
        match self {
            Self::Hunter(a) => a.search(client, credential, request).await,
            Self::Quake(a) => a.search(client, credential, request).await,
            Self::Fofa(a) => a.search(client, credential, request).await,
            Self::Shodan(a) => a.search(client, credential, request).await,
        }
    }

    pub fn normalize(
        &self,
        raw: &Value,
        fields: &FieldSelection,
        now_ms: i64,
        future_tolerance_ms: i64,
    ) -> Option<NormalizedRecord> {
        match self {
            Self::Hunter(a) => a.normalize(raw, fields, now_ms, future_tolerance_ms),
            Self::Quake(a) => a.normalize(raw, fields, now_ms, future_tolerance_ms),
            Self::Fofa(a) => a.normalize(raw, fields, now_ms, future_tolerance_ms),
            Self::Shodan(a) => a.normalize(raw, fields, now_ms, future_tolerance_ms),
        }
    }

    pub async fn probe(
        &self,
        client: &reqwest::Client,
        credential: &Value,
    ) -> Result<Value, SourceError> {
        match self {
            Self::Hunter(a) => a.probe(client, credential).await,
            Self::Quake(a) => a.probe(client, credential).await,
            Self::Fofa(a) => a.probe(client, credential).await,
            Self::Shodan(a) => a.probe(client, credential).await,
        }
    }
}

/// 每源 HTTP 客户端：代理语义复用 outbound_proxy，超时/UA 独立。
pub fn http_client(proxy: &ProxyConfig, timeout: Duration) -> Result<reqwest::Client, SourceError> {
    proxy
        .apply_to(
            reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(timeout)
                .user_agent(USER_AGENT),
        )
        .map_err(|_| SourceError::permanent("proxy_invalid"))?
        .build()
        .map_err(|_| SourceError::permanent("proxy_invalid"))
}

/// 读取响应体（限长）并解析 JSON。
pub async fn response_json(response: reqwest::Response) -> Result<Value, SourceError> {
    let bytes = response
        .bytes()
        .await
        .map_err(|_| SourceError::transient("timeout"))?;
    if bytes.len() > MAX_RESPONSE {
        return Err(SourceError::permanent("invalid_response"));
    }
    serde_json::from_slice(&bytes).map_err(|_| SourceError::permanent("invalid_response"))
}

/// 传输层错误分类（reqwest 不暴露类型化代理错误，沿用共享分类口径）。
pub fn transport_error(error: &reqwest::Error) -> SourceError {
    if error.is_timeout() {
        return SourceError::transient("timeout");
    }
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("dns") || message.contains("resolve") || message.contains("lookup") {
        return SourceError::transient("proxy_dns_failed");
    }
    if message.contains("proxy") || message.contains("tunnel") || message.contains("socks") {
        return SourceError::transient("proxy_connection_failed");
    }
    SourceError::transient("transport")
}

// ---- 时间戳解析 ----

/// ISO8601（带 Z/偏移，或无时区后缀按 UTC）→ epoch ms。Shodan/Quake 用。
pub fn parse_iso_utc(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Some(dt.timestamp_millis());
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, format) {
            return Some(naive.and_utc().timestamp_millis());
        }
    }
    None
}

/// 国内平台日期时间（"YYYY-MM-DD HH:MM:SS" 或 "YYYY-MM-DD"，暂按 UTC+8）→ epoch ms。
/// Hunter/FOFA 用；仅日期按当日 00:00（保守，降低新者胜竞争力）。
pub fn parse_cn_datetime(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let offset = chrono::FixedOffset::east_opt(8 * 3600)?;
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
        return naive
            .and_local_timezone(offset)
            .single()
            .map(|dt| dt.timestamp_millis());
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        let naive = date.and_hms_opt(0, 0, 0)?;
        return naive
            .and_local_timezone(offset)
            .single()
            .map(|dt| dt.timestamp_millis());
    }
    None
}

/// 时间窗日期串（UTC+8，YYYY-MM-DD），Hunter/FOFA 用。
pub fn window_dates_cn(window_days: u32) -> (String, String) {
    let now = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap());
    let start = now - chrono::Duration::days(i64::from(window_days));
    (
        start.format("%Y-%m-%d").to_string(),
        now.format("%Y-%m-%d").to_string(),
    )
}

/// 时间窗日期时间串（UTC，"YYYY-MM-DD HH:MM:SS"），Quake 用。
pub fn window_datetimes_utc(window_days: u32) -> (String, String) {
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::days(i64::from(window_days));
    (
        start.format("%Y-%m-%d %H:%M:%S").to_string(),
        now.format("%Y-%m-%d %H:%M:%S").to_string(),
    )
}

/// 观测时间戳容差处理：超未来容差钳制到 now；缺失 → 拉取时间 + inferred。
pub fn resolve_observed_at(
    parsed: Option<i64>,
    now_ms: i64,
    future_tolerance_ms: i64,
) -> (i64, bool) {
    match parsed {
        Some(ts) if ts > now_ms + future_tolerance_ms => (now_ms, true),
        Some(ts) if ts > 0 => (ts, false),
        _ => (now_ms, true),
    }
}

/// 标准 base64（FOFA qbase64）。
pub fn base64_standard(value: &str) -> String {
    openssl::base64::encode_block(value.as_bytes())
}

/// base64url（RFC 4648，带 padding，Hunter search）。
pub fn base64_url(value: &str) -> String {
    base64_standard(value).replace('+', "-").replace('/', "_")
}

/// 字符串/数字皆可的端口解析。
pub fn parse_port_value(raw: &Value) -> Option<u16> {
    match raw {
        Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
        Value::String(s) => s.trim().parse::<u16>().ok(),
        _ => None,
    }
}

pub fn string_field(raw: &Value, key: &str) -> Option<String> {
    raw.get(key).and_then(Value::as_str).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_formats() {
        // Shodan：无时区后缀按 UTC
        assert_eq!(
            parse_iso_utc("2021-01-25T21:33:49.154513"),
            Some(1611610429154)
        );
        // Quake：带 Z
        assert_eq!(
            parse_iso_utc("2026-07-03T05:08:19.848Z"),
            Some(1783055299848)
        );
        // Hunter/FOFA：日期时间按 UTC+8
        assert_eq!(
            parse_cn_datetime("2021-01-01 00:00:00"),
            Some(1609430400000)
        );
        // 仅日期按当日 00:00 UTC+8
        assert_eq!(parse_cn_datetime("2025-01-01"), Some(1735660800000));
        assert_eq!(parse_cn_datetime("garbage"), None);
    }

    #[test]
    fn observed_at_tolerance_and_inferred() {
        let now = 1_000_000_000_000i64;
        assert_eq!(
            resolve_observed_at(Some(now - 5000), now, 300_000),
            (now - 5000, false)
        );
        assert_eq!(
            resolve_observed_at(Some(now + 400_000), now, 300_000),
            (now, true)
        );
        assert_eq!(resolve_observed_at(None, now, 300_000), (now, true));
    }

    #[test]
    fn base64_encodings() {
        assert_eq!(base64_standard("title=\"bing\""), "dGl0bGU9ImJpbmci");
        let url = base64_url("subjects?and+more");
        assert!(!url.contains('+') && !url.contains('/'));
    }

    #[test]
    fn port_value_forms() {
        assert_eq!(parse_port_value(&serde_json::json!(443)), Some(443));
        assert_eq!(parse_port_value(&serde_json::json!("443")), Some(443));
        assert_eq!(parse_port_value(&serde_json::json!("x")), None);
        assert_eq!(parse_port_value(&serde_json::json!(70000)), None);
    }
}
