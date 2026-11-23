//! A mail-safe projection of one immutable report; never exposes raw task inputs.
use super::mail_config::ReportMailConfig;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

pub struct MailMetadata {
    pub revision: i32,
    pub generated_at: DateTime<Utc>,
    pub cutoff_at: DateTime<Utc>,
}

pub fn build(
    payload: &Value,
    quality: &Value,
    id: Uuid,
    meta: &MailMetadata,
    config: &ReportMailConfig,
    image_url: &str,
) -> Result<Value, String> {
    let timezone = payload["period"]["timezone"]
        .as_str()
        .unwrap_or(crate::system_time::DEFAULT_TIMEZONE);
    let tz = timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|_| "无效报告时区")?;
    let date = |key: &str| -> Result<String, String> {
        let text = payload["period"][key].as_str().ok_or("缺少报告周期")?;
        Ok(DateTime::parse_from_rfc3339(text)
            .map_err(|e| e.to_string())?
            .with_timezone(&tz)
            .date_naive()
            .to_string())
    };
    let scanners = payload["scanners"].as_array().cloned().unwrap_or_default();
    let mut aliases = Vec::new();
    let rows: Vec<Value> = scanners.iter().take(config.scanner_row_limit).enumerate().map(|(i, scanner)| {
        let raw_name = scanner["name"].as_str().unwrap_or("");
        let raw_id = scanner["scanner_id"].as_str().unwrap_or("");
        let name = if raw_name.is_empty() || (!raw_id.is_empty() && raw_name == raw_id) || Uuid::parse_str(raw_name).is_ok() {
            format!("扫描器 {}", i + 1)
        } else { raw_name.chars().take(80).collect() };
        if name != raw_name && !raw_name.is_empty() { aliases.push((raw_name.to_owned(), name.clone())); }
        json!({"name": name, "total": scanner["total"], "succeeded": scanner["succeeded"], "failed": scanner["failed"], "cancelled": scanner["cancelled"],
            "avg_duration": seconds(&scanner["avg_duration_ms"]), "p50": seconds(&scanner["p50_ms"]), "p95": seconds(&scanner["p95_ms"])})
    }).collect();
    let recommendations: Vec<String> = payload["recommendations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|text| {
            let mut text = text.to_owned();
            for (raw, alias) in &aliases {
                text = text.replace(raw, alias);
            }
            // The most-failed scanner may be outside the displayed rows.
            for (i, scanner) in scanners.iter().enumerate() {
                if let Some(id) = scanner["scanner_id"].as_str() {
                    text = text.replace(id, &format!("扫描器 {}", i + 1));
                }
            }
            text
        })
        .collect();
    let previous = payload["previous_available"] == true;
    let comparison: Vec<Value> = [
        ("新建任务", "created_growth_percent", "%"),
        ("去重 IP", "unique_ips_growth_percent", "%"),
        ("日均去重 IP", "daily_unique_ips_growth_percent", "%"),
        ("成功率", "success_rate_change_points", " 个百分点"),
    ].into_iter().map(|(label, key, unit)| json!({"label": label, "value": signed(&payload["comparison"][key], unit)})).collect();
    Ok(json!({
        "system_name": "Network Mapping",
        "report_label": match payload["period"]["type"].as_str() {
            Some("daily") => "日报",
            Some("weekly") => "周报",
            _ => "月报",
        },
        "period_label": format!("{} 至 {}（不含），{}", date("start_at")?, date("end_at")?, timezone),
        "tasks": payload["tasks"], "scan_output": payload["scan_output"],
        "recommendations": recommendations, "detail_path": format!("/reports/{id}"),
        "detail_url": config.url(&format!("/reports/{id}")),
        "report_meta": {"revision": meta.revision, "timezone": timezone,
            "generated_at": meta.generated_at.with_timezone(&tz).format("%Y-%m-%d %H:%M:%S").to_string(),
            "cutoff_at": meta.cutoff_at.with_timezone(&tz).format("%Y-%m-%d %H:%M:%S").to_string()},
        "previous_available": previous, "comparison": if previous { payload["comparison"].clone() } else { Value::Null },
        "comparison_rows": comparison, "trend_rows": payload["trend"].as_array().cloned().unwrap_or_default(),
        "trend_image_url": image_url, "scanners": rows,
        "scanner_omitted": scanners.len().saturating_sub(config.scanner_row_limit),
        "quality_summary": {"ready": quality["current"]["ready"], "expected": quality["current"]["expected"]},
        "notes": payload["notes"].as_array().cloned().unwrap_or_default()
    }))
}

fn seconds(value: &Value) -> String {
    value
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0)
        .map(|n| format!("{:.1} 秒", n / 1000.0))
        .unwrap_or_else(|| "--".into())
}
fn signed(value: &Value, unit: &str) -> String {
    value
        .as_f64()
        .filter(|n| n.is_finite())
        .map(|n| format!("{}{n}{unit}", if n > 0.0 { "+" } else { "" }))
        .unwrap_or_else(|| "上期为 0 或无可比较值".into())
}

pub fn sample() -> Value {
    let payload = json!({"period": {"type":"weekly", "start_at":"2026-09-20T16:00:00Z", "end_at":"2026-09-27T16:00:00Z", "timezone":"Asia/Shanghai"},
        "tasks":{"created":12,"succeeded":10,"failed":1,"partial":1,"cancelled":0,"success_rate":83.3},
        "scan_output":{"unique_ips":100,"port_observations":240,"service_observations":180,"ports":[{"name":"443","count":120}],"services":[{"name":"https","count":100}]},
        "previous_available":true,"comparison":{"created_growth_percent":20,"unique_ips_growth_percent":null,"daily_unique_ips_growth_percent":-5,"success_rate_change_points":3.3},
        "trend":(21..=27).map(|day| json!({"day":format!("2026-09-{day}"),"succeeded":if day==21 {10} else {0},"failed":if day==21 {1} else {0},"partial":if day==21 {1} else {0},"cancelled":0})).collect::<Vec<_>>(),
        "scanners":[{"name":"示例扫描器","total":12,"succeeded":10,"failed":1,"cancelled":0,"avg_duration_ms":1000,"p50_ms":900,"p95_ms":1400}],
        "recommendations":["存在失败任务，请检查失败原因。"],"notes":["IP 跨执行去重；端口与服务是观测次数，不是资产存量。","统计基于生成时保留的历史。"]});
    let at = DateTime::parse_from_rfc3339("2026-09-28T01:00:00Z")
        .expect("fixed sample time")
        .with_timezone(&Utc);
    build(
        &payload,
        &json!({"current":{"ready":10,"expected":10}}),
        Uuid::nil(),
        &MailMetadata {
            revision: 1,
            generated_at: at,
            cutoff_at: at,
        },
        &ReportMailConfig {
            public_base_url: "https://reports.example.invalid".into(),
            ..Default::default()
        },
        "",
    )
    .expect("fixed sample context")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comparison_and_duration_preserve_empty_values() {
        assert_eq!(signed(&Value::Null, "%"), "上期为 0 或无可比较值");
        assert_eq!(signed(&json!(-12.5), "%"), "-12.5%");
        assert_eq!(signed(&json!(3), " 个百分点"), "+3 个百分点");
        assert_eq!(seconds(&Value::Null), "--");
        assert_eq!(seconds(&json!(1234)), "1.2 秒");
    }
}
