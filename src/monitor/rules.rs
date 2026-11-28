//! Slow-operation policy shared by the catalogue, validation and observers.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::config::MonitorConfig;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MonitorService {
    WebApi,
    Postgresql,
    ElasticsearchQuery,
    ElasticsearchWrite,
}

impl MonitorService {
    pub const ALL: [Self; 4] = [
        Self::WebApi,
        Self::Postgresql,
        Self::ElasticsearchQuery,
        Self::ElasticsearchWrite,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::WebApi => "Web API",
            Self::Postgresql => "PostgreSQL",
            Self::ElasticsearchQuery => "ES 查询",
            Self::ElasticsearchWrite => "ES 写入",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SlowRule {
    pub enabled: bool,
    pub warning_threshold_ms: i64,
    /// None preserves legacy request/SQL policies, which had warning only.
    pub critical_threshold_ms: Option<i64>,
    pub cooldown_seconds: u64,
}

impl SlowRule {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=86_400_000).contains(&self.warning_threshold_ms) {
            return Err("警告阈值必须为 1～86400000 毫秒的整数".into());
        }
        if let Some(critical) = self.critical_threshold_ms
            && (!(1..=86_400_000).contains(&critical) || critical < self.warning_threshold_ms)
        {
            return Err("严重阈值必须不小于警告阈值且不超过 86400000 毫秒".into());
        }
        if !(1..=604_800).contains(&self.cooldown_seconds) {
            return Err("冷却时间必须为 1～604800 秒的整数".into());
        }
        Ok(())
    }

    pub fn severity(&self, duration_ms: f64) -> Option<&'static str> {
        if !self.enabled
            || !duration_ms.is_finite()
            || duration_ms < self.warning_threshold_ms as f64
        {
            None
        } else if self
            .critical_threshold_ms
            .is_some_and(|value| duration_ms >= value as f64)
        {
            Some("critical")
        } else {
            Some("warning")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperationRule {
    pub service: MonitorService,
    pub operation: String,
    pub rule: SlowRule,
}

#[derive(Clone, Debug)]
pub struct AppliedRule {
    pub rule: SlowRule,
    pub source: String,
    pub revision: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct OperationDescriptor {
    pub service: MonitorService,
    pub operation: String,
    pub label: String,
    pub description: String,
}

pub const ES_OPERATIONS: &[(MonitorService, &str, &str)] = &[
    (
        MonitorService::ElasticsearchQuery,
        "scan-query",
        "扫描结果查询",
    ),
    (
        MonitorService::ElasticsearchQuery,
        "execution-summary",
        "执行结果汇总",
    ),
    (
        MonitorService::ElasticsearchQuery,
        "conflict-check",
        "写入冲突检查",
    ),
    (
        MonitorService::ElasticsearchQuery,
        "projection-search",
        "投影数据查询",
    ),
    (
        MonitorService::ElasticsearchQuery,
        "asset-search",
        "资产搜索",
    ),
    (
        MonitorService::ElasticsearchQuery,
        "search-values",
        "搜索字段值推荐",
    ),
    (
        MonitorService::ElasticsearchQuery,
        "endpoint-filter",
        "端点筛选",
    ),
    (
        MonitorService::ElasticsearchQuery,
        "domain-filter",
        "域名筛选",
    ),
    (
        MonitorService::ElasticsearchWrite,
        "refresh-tags",
        "资产标签更新",
    ),
    (
        MonitorService::ElasticsearchWrite,
        "bulk-write",
        "扫描结果批量写入",
    ),
];

pub fn static_catalogue() -> Vec<OperationDescriptor> {
    let mut items: Vec<_> = super::routes::WEB_OPERATIONS
        .iter()
        .map(|(operation, label)| OperationDescriptor {
            service: MonitorService::WebApi,
            operation: (*operation).to_owned(),
            label: (*label).to_owned(),
            description: "按请求方法和匹配路由模板统计响应耗时；不同资源 ID 共用一条规则。".into(),
        })
        .collect();
    items.extend(
        ES_OPERATIONS
            .iter()
            .map(|(service, operation, label)| OperationDescriptor {
                service: *service,
                operation: (*operation).to_owned(),
                label: (*label).to_owned(),
                description:
                    "使用应用侧操作总耗时，包含网络与响应处理耗时；关闭慢检测不关闭失败告警。"
                        .into(),
            }),
    );
    items
}

pub fn valid_operation(service: MonitorService, operation: &str) -> bool {
    match service {
        MonitorService::WebApi => super::routes::WEB_OPERATIONS
            .iter()
            .any(|(name, _)| *name == operation),
        MonitorService::Postgresql => operation
            .parse::<i64>()
            .is_ok_and(|id| id.to_string() == operation),
        _ => ES_OPERATIONS
            .iter()
            .any(|(kind, name, _)| *kind == service && *name == operation),
    }
}

impl MonitorConfig {
    pub fn default_rule(&self, service: MonitorService) -> SlowRule {
        if let Some(rule) = self.service_defaults.get(&service) {
            return rule.clone();
        }
        let (warning, critical) = match service {
            MonitorService::WebApi => (self.slow_request_threshold_ms, None),
            MonitorService::Postgresql => (self.slow_sql_threshold_ms, None),
            MonitorService::ElasticsearchQuery => (
                self.elasticsearch_query_warning_threshold_ms,
                Some(self.elasticsearch_query_critical_threshold_ms),
            ),
            MonitorService::ElasticsearchWrite => (
                self.elasticsearch_write_warning_threshold_ms,
                Some(self.elasticsearch_write_critical_threshold_ms),
            ),
        };
        SlowRule {
            enabled: true,
            warning_threshold_ms: warning,
            critical_threshold_ms: critical,
            cooldown_seconds: self.alert_cooldown_seconds,
        }
    }

    pub fn resolve_rule(
        &self,
        service: MonitorService,
        operation: &str,
        revision: i64,
    ) -> AppliedRule {
        let (rule, source) = match self
            .operation_rules
            .iter()
            .find(|item| item.service == service && item.operation == operation)
        {
            Some(item) => (
                item.rule.clone(),
                format!("操作覆盖：{} / {}", service.label(), operation),
            ),
            None => (
                self.default_rule(service),
                format!("继承{}默认", service.label()),
            ),
        };
        AppliedRule {
            rule,
            source,
            revision,
        }
    }

    pub fn validate_rules(&self) -> Result<(), String> {
        for service in MonitorService::ALL {
            self.default_rule(service).validate()?;
        }
        if self.operation_rules.len() > 512 {
            return Err("操作覆盖不能超过 512 条".into());
        }
        let mut seen = BTreeSet::new();
        for item in &self.operation_rules {
            if !valid_operation(item.service, &item.operation) {
                return Err(format!(
                    "未知操作：{} / {}，请从操作目录选择",
                    item.service.label(),
                    item.operation
                ));
            }
            if !seen.insert((item.service, &item.operation)) {
                return Err(format!("操作规则重复：{}", item.operation));
            }
            item.rule.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_defaults_and_operation_inheritance_survive_serialization() {
        let mut config: MonitorConfig =
            serde_json::from_value(serde_json::json!({"slow_request_threshold_ms": 4500})).unwrap();
        assert_eq!(
            config
                .default_rule(MonitorService::WebApi)
                .critical_threshold_ms,
            None
        );
        assert_eq!(
            config
                .resolve_rule(MonitorService::WebApi, "GET /api/task/all", 8)
                .rule
                .warning_threshold_ms,
            4500
        );
        let custom = SlowRule {
            enabled: true,
            warning_threshold_ms: 500,
            critical_threshold_ms: Some(1500),
            cooldown_seconds: 10,
        };
        config.operation_rules.push(OperationRule {
            service: MonitorService::WebApi,
            operation: "GET /api/task/all".into(),
            rule: custom.clone(),
        });
        config.slow_request_threshold_ms = 9000;
        assert_eq!(
            config
                .resolve_rule(MonitorService::WebApi, "GET /api/task/all", 9)
                .rule,
            custom
        );
        config.operation_rules.clear();
        assert_eq!(
            config
                .resolve_rule(MonitorService::WebApi, "GET /api/task/all", 10)
                .rule
                .warning_threshold_ms,
            9000
        );
    }

    #[test]
    fn boundaries_disable_and_severity_are_unambiguous() {
        let mut rule = SlowRule {
            enabled: true,
            warning_threshold_ms: 1000,
            critical_threshold_ms: Some(3000),
            cooldown_seconds: 300,
        };
        assert_eq!(rule.severity(999.9), None);
        assert_eq!(rule.severity(1000.0), Some("warning"));
        assert_eq!(rule.severity(3000.0), Some("critical"));
        assert_eq!(rule.severity(f64::NAN), None);
        rule.enabled = false;
        assert_eq!(rule.severity(5000.0), None);
    }

    #[test]
    fn rejects_unknown_duplicate_and_invalid_rules() {
        let mut config = MonitorConfig::default();
        let rule = config.default_rule(MonitorService::WebApi);
        let item = OperationRule {
            service: MonitorService::WebApi,
            operation: "GET /api/task/all".into(),
            rule,
        };
        config.operation_rules = vec![item.clone(), item];
        assert!(config.validate_rules().is_err());
        config.operation_rules.truncate(1);
        config.operation_rules[0].operation = "GET /api/task/actual-id".into();
        assert!(config.validate_rules().is_err());
        config.operation_rules.clear();
        let mut rule = config.default_rule(MonitorService::Postgresql);
        rule.critical_threshold_ms = Some(1);
        config
            .service_defaults
            .insert(MonitorService::Postgresql, rule);
        assert!(config.validate_rules().is_err());
        assert!(!valid_operation(MonitorService::Postgresql, "1 OR TRUE"));
        assert!(valid_operation(MonitorService::Postgresql, "-123"));
    }

    #[test]
    fn catalogue_covers_http_route_templates_without_concrete_resource_ids() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut paths: Vec<_> = std::fs::read_dir(root.join("handlers"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
            .collect();
        paths.push(root.join("scanner_config.rs"));
        let pattern =
            regex::Regex::new(r#"(?m)^#\[(get|post|put|patch|delete)\("([^"]+)"\)\]"#).unwrap();
        for path in paths {
            let source = std::fs::read_to_string(&path).unwrap();
            for captures in pattern.captures_iter(&source) {
                let route = &captures[2];
                if route.starts_with("/api/") || route == "/logout" {
                    let operation = format!("{} {route}", captures[1].to_uppercase());
                    assert!(
                        valid_operation(MonitorService::WebApi, &operation),
                        "Missing {operation} in operation catalogue ({})",
                        path.display()
                    );
                }
            }
        }
    }
}
