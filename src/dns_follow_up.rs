use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Policy controlling server-side port scan tasks derived from DNS A/AAAA answers.
/// A disabled policy is the safe default for existing installations.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsFollowUpConfig {
    pub enabled: bool,
    pub authorized_cidrs: Vec<String>,
    pub excluded_cidrs: Vec<String>,
    /// Applies to every DNS task, independently of the IP follow-up switch.
    #[serde(deserialize_with = "deserialize_exclusions")]
    pub excluded_domains: Vec<String>,
    pub max_targets_per_task: u16,
}

impl Default for DnsFollowUpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            authorized_cidrs: Vec::new(),
            excluded_cidrs: Vec::new(),
            excluded_domains: Vec::new(),
            max_targets_per_task: 100,
        }
    }
}

impl DnsFollowUpConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.excluded_domains.len() > 256 {
            return Err("DNS 域名排除最多允许 256 条规则".into());
        }
        for pattern in &self.excluded_domains {
            canonical_exclusion(pattern)?;
        }
        if self.max_targets_per_task == 0 || self.max_targets_per_task > 500 {
            return Err("dns_follow_up.max_targets_per_task 必须在 1 到 500 之间".into());
        }
        if self.enabled && self.authorized_cidrs.is_empty() {
            return Err("启用 DNS 后续端口任务时必须配置 dns_follow_up.authorized_cidrs".into());
        }
        let authorized = parse_cidrs(&self.authorized_cidrs, "授权")?;
        let excluded = parse_cidrs(&self.excluded_cidrs, "排除")?;
        reject_overlapping_cidrs(&authorized, "授权")?;
        reject_overlapping_cidrs(&excluded, "排除")?;
        Ok(())
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        let authorized = self.authorized_cidrs.iter().any(|value| {
            value
                .parse::<IpNet>()
                .is_ok_and(|network| network.contains(&ip))
        });
        authorized
            && !self.excluded_cidrs.iter().any(|value| {
                value
                    .parse::<IpNet>()
                    .is_ok_and(|network| network.contains(&ip))
            })
    }

    pub fn allows_domain(&self, value: &str) -> bool {
        let Ok(domain) = crate::dns::canonical_scan_domain(value) else {
            return false;
        };
        self.excluded_domains.iter().all(|pattern| {
            let Ok(pattern) = canonical_exclusion(pattern) else {
                return false;
            };
            if let Some(base) = pattern.strip_prefix("*.") {
                !domain.ends_with(&format!(".{base}"))
            } else {
                domain != pattern
            }
        })
    }
}

fn deserialize_exclusions<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    use serde::de::Error;
    let values = Vec::<String>::deserialize(d)?;
    if values.len() > 256 {
        return Err(D::Error::custom("DNS 域名排除最多允许 256 条规则"));
    }
    values
        .iter()
        .map(|value| canonical_exclusion(value).map_err(D::Error::custom))
        .collect()
}

pub fn canonical_exclusion(value: &str) -> Result<String, String> {
    let value = value.trim();
    if let Some(base) = value.strip_prefix("*.") {
        Ok(format!("*.{}", crate::dns::canonical_scan_domain(base)?))
    } else {
        crate::dns::canonical_scan_domain(value)
    }
}

fn parse_cidrs(values: &[String], kind: &str) -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|error| format!("无效的 DNS 后续任务{kind} CIDR {value}: {error}").into())
        })
        .collect()
}

fn reject_overlapping_cidrs(
    networks: &[IpNet],
    kind: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, network) in networks.iter().enumerate() {
        if networks[index + 1..]
            .iter()
            .any(|other| network.contains(&other.network()) || other.contains(&network.network()))
        {
            return Err(format!("DNS 后续任务{kind} CIDR 存在重复或重叠：{network}").into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DnsFollowUpConfig;

    #[test]
    fn domain_exclusions_are_exact_or_descendants_and_fail_closed() {
        let mut policy = DnsFollowUpConfig {
            excluded_domains: vec![" Example.COM. ".into(), "*.private.example.org".into()],
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
        for name in [
            "EXAMPLE.COM.",
            "a.private.example.org",
            "a.b.private.example.org",
        ] {
            assert!(!policy.allows_domain(name), "{name}");
        }
        for name in [
            "api.example.com",
            "private.example.org",
            "notexample.com",
            "example.com.evil.test",
        ] {
            assert!(policy.allows_domain(name), "{name}");
        }
        for invalid in [
            "*",
            "a*.example.org",
            "?.example.org",
            "https://example.org",
            "*.com",
        ] {
            policy.excluded_domains = vec![invalid.into()];
            assert!(policy.validate().is_err(), "{invalid}");
            assert!(!policy.allows_domain("valid.example.org"));
        }
    }

    #[test]
    fn enabled_policy_requires_authorized_cidrs() {
        let config = DnsFollowUpConfig {
            enabled: true,
            ..DnsFollowUpConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn postgres_exclusions_match_rust_and_migrate_old_policy_once() {
        use serde_json::json;
        let (c, connection) = tokio_postgres::connect(
            &std::env::var("STORAGE_TEST_DATABASE_URL").unwrap(),
            tokio_postgres::NoTls,
        )
        .await
        .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let schema = format!("dns_exclude_{}", uuid::Uuid::new_v4().simple());
        c.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema};"
        ))
        .await
        .unwrap();
        c.batch_execute(include_str!("../source/database/init.sql"))
            .await
            .unwrap();
        let policy = DnsFollowUpConfig {
            excluded_domains: vec![
                "\tExample.COM.\n".into(),
                "\u{00a0}*.Private.example.org\u{3000}".into(),
            ],
            ..Default::default()
        };
        c.execute("INSERT INTO runtime_configuration(namespace,document) VALUES('dns_follow_up',$1),('automatic_target',$2)", &[
            &serde_json::to_value(&policy).unwrap(), &json!({"search_generation":{"enabled":true,"domain_enabled":true,"authorized_domains":["example.com"]}})
        ]).await.unwrap();
        for name in [
            "example.com",
            "EXAMPLE.COM.",
            "api.example.com",
            "private.example.org",
            "x.private.example.org",
            "a.b.private.example.org",
            "notexample.com",
            "example.com.evil.test",
        ] {
            let excluded: bool = c
                .query_one("SELECT dns_domain_excluded($1)", &[&name])
                .await
                .unwrap()
                .get(0);
            assert_eq!(excluded, !policy.allows_domain(name), "{name}");
        }
        for _ in 0..2 {
            c.batch_execute(include_str!(
                "../source/database/migrate_dns_domain_exclusions.sql"
            ))
            .await
            .unwrap();
        }
        let row=c.query_one("SELECT revision,document FROM runtime_configuration WHERE namespace='automatic_target'", &[]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
        let document: serde_json::Value = row.get(1);
        assert_eq!(document["search_generation"]["domain_enabled"], false);
        assert!(
            document["search_generation"]
                .get("authorized_domains")
                .is_none()
        );
        c.execute(
            "UPDATE runtime_configuration SET document=$1 WHERE namespace='dns_follow_up'",
            &[&json!({"excluded_domains":["*"]})],
        )
        .await
        .unwrap();
        assert!(
            c.query_one("SELECT dns_domain_excluded('valid.example.com')", &[])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        c.execute(
            "UPDATE runtime_configuration SET document=$1 WHERE namespace='dns_follow_up'",
            &[&json!({"excluded_domains":"invalid"})],
        )
        .await
        .unwrap();
        assert!(
            c.query_one("SELECT dns_domain_excluded('valid.example.com')", &[])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[test]
    fn policy_matches_only_authorized_addresses() {
        let config = DnsFollowUpConfig {
            enabled: true,
            authorized_cidrs: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
            ..DnsFollowUpConfig::default()
        };
        assert!(config.allows("192.0.2.10".parse().unwrap()));
        assert!(config.allows("2001:db8::10".parse().unwrap()));
        assert!(!config.allows("198.51.100.10".parse().unwrap()));
    }

    #[test]
    fn excluded_cidrs_override_authorized_cidrs() {
        let config = DnsFollowUpConfig {
            enabled: true,
            authorized_cidrs: vec!["192.0.2.0/24".into()],
            excluded_cidrs: vec!["192.0.2.128/25".into()],
            ..DnsFollowUpConfig::default()
        };
        assert!(config.validate().is_ok());
        assert!(config.allows("192.0.2.10".parse().unwrap()));
        assert!(!config.allows("192.0.2.200".parse().unwrap()));
    }

    #[test]
    fn overlapping_exclusions_are_rejected() {
        let config = DnsFollowUpConfig {
            excluded_cidrs: vec!["192.0.2.0/24".into(), "192.0.2.128/25".into()],
            ..DnsFollowUpConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
