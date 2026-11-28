//! Offline diagnostics use the same compiler and inference as server startup.
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::ProductRulesCommand;

use super::{infer_with_rules, rules};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    name: String,
    data: Value,
    #[serde(default)]
    observed_at: i64,
    expected_rule_ids: BTreeSet<String>,
    expected_status: Option<String>,
    expected_coverage: Option<String>,
    expected_paths: Option<BTreeSet<String>>,
}

pub(crate) fn execute(command: &ProductRulesCommand) -> io::Result<()> {
    let file = match command {
        ProductRulesCommand::Validate { file, .. } | ProductRulesCommand::Test { file, .. } => file,
        ProductRulesCommand::Export => return io::stdout().lock().write_all(rules::BUILTIN),
    };
    let loaded = file.as_deref().map(rules::RuleSet::read).transpose()?;
    let pack = loaded.as_ref().unwrap_or_else(|| rules::default_rules());
    let summary = json!({
        "source": file.as_deref().map_or_else(|| "embedded".into(), |path| path.display().to_string()),
        "ruleset_revision": pack.stamp.revision,
        "evaluator_revision": pack.stamp.evaluator_revision,
        "ruleset_sha256": pack.stamp.sha256,
        "rules": pack.count()
    });
    match command {
        ProductRulesCommand::Validate { against, .. } => {
            if let Some(path) = against {
                let previous = rules::RuleSet::read(path)?;
                if pack.stamp != previous.stamp && pack.stamp.revision <= previous.stamp.revision {
                    return Err(invalid(format!(
                        "规则包内容有变化，ruleset_revision 必须大于参照包的 {}",
                        previous.stamp.revision
                    )));
                }
            }
            println!("{summary:#}");
        }
        ProductRulesCommand::Test { fixtures, .. } => {
            let (report, failed) = replay(fixtures, pack)?;
            println!(
                "{:#}",
                json!({"ruleset": summary, "failed": failed, "fixtures": report})
            );
            if failed > 0 {
                return Err(invalid(format!("{failed} 个产品规则样本结果与预期不符")));
            }
        }
        ProductRulesCommand::Export => {
            unreachable!("export is handled without loading a rule pack")
        }
    }
    Ok(())
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn replay(path: &Path, pack: &rules::RuleSet) -> io::Result<(Vec<Value>, usize)> {
    let bytes = rules::read_limited(path, 16 * 1024 * 1024)?;
    let fixtures: Vec<Fixture> = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
    if fixtures.is_empty() {
        return Err(invalid(format!("{}: 样本数组不能为空", path.display())));
    }
    let mut names = BTreeSet::new();
    let mut report = Vec::new();
    let mut failed = 0;
    for (index, fixture) in fixtures.into_iter().enumerate() {
        if fixture.name.trim().is_empty() || !names.insert(fixture.name.clone()) {
            return Err(invalid(format!(
                "{}: 样本 {index} 名称为空或重复",
                path.display()
            )));
        }
        if fixture.data["schema_version"] != 2 || !fixture.data["evidence"].is_array() {
            return Err(invalid(format!(
                "{}: 样本 {} 需要原始 schema_version=2 服务证据",
                path.display(),
                fixture.name
            )));
        }
        let inferred = infer_with_rules(Some(&fixture.data), fixture.observed_at, None, pack);
        let mut actual = BTreeSet::new();
        let mut hits = Vec::new();
        let mut paths = BTreeSet::new();
        for product in &inferred.products {
            for evidence in &product.evidence {
                actual.insert(evidence.rule_id.as_str());
                paths.insert(evidence.field_path.as_str());
                hits.push(json!({
                    "product": product.id, "category": product.category, "component": product.component,
                    "assessment": product.assessment, "rule_id": evidence.rule_id,
                    "path": evidence.field_path
                }));
            }
        }
        let passed = actual
            .iter()
            .copied()
            .eq(fixture.expected_rule_ids.iter().map(String::as_str))
            && fixture
                .expected_status
                .as_ref()
                .is_none_or(|status| status == &inferred.product_identification.status)
            && fixture
                .expected_coverage
                .as_ref()
                .is_none_or(|coverage| coverage == &inferred.product_identification.coverage)
            && fixture.expected_paths.as_ref().is_none_or(|expected| {
                paths
                    .iter()
                    .copied()
                    .eq(expected.iter().map(String::as_str))
            });
        failed += usize::from(!passed);
        report.push(json!({
            "name": fixture.name, "passed": passed,
            "expected_rule_ids": fixture.expected_rule_ids, "actual_rule_ids": actual,
            "expected_status": fixture.expected_status, "expected_coverage": fixture.expected_coverage,
            "expected_paths": fixture.expected_paths,
            "status": inferred.product_identification.status, "coverage": inferred.product_identification.coverage,
            "matches": hits
        }));
    }
    Ok((report, failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_product_fixtures_replay() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/examples/product-rules-fixtures.json");
        let (report, failed) = replay(&path, rules::default_rules()).unwrap();
        assert_eq!(report.len(), 43);
        let miner = report
            .iter()
            .find(|row| row["name"] == "xmrig-active-summary")
            .unwrap();
        assert_eq!(miner["matches"][0]["category"], "mining_software");
        let failures: Vec<_> = report
            .iter()
            .filter(|case| case["passed"] != true)
            .collect();
        assert_eq!(failed, 0, "{failures:#?}");
    }
}
