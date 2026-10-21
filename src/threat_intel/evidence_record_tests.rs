//! Reconstructed proposals matching the reported failure pattern, not a saved
//! provider response. The fixture preserves all ten published asset records.
use super::*;
use std::collections::HashSet;

fn proposal(kind: &str, value: &str, ioc: usize, context: usize, document: &Document<'_>) -> Value {
    json!({"type":kind,"value":value,"evidence_parts":[
        {"block_id":context,"kind":"context","quote":document.blocks[context-1].text},
        {"block_id":ioc,"kind":"ioc","quote":value}
    ]})
}

fn parse(body: &str, items: Vec<Value>) -> Result<(Vec<Indicator>, ValidationReport)> {
    parse::ai_result_isolated(&json!({"iocs":items}).to_string(), body)
}

#[test]
fn silverfox_all_46_iocs_accept_correct_citations_and_recover_reported_bad_contexts() {
    let body = include_str!("fixtures/silverfox_assets.txt");
    let document = Document::new(body);
    let intro = document
        .blocks
        .iter()
        .find(|b| b.text == "恶意网络资产信息如下：")
        .unwrap()
        .id;
    let mut seen = HashSet::new();
    let mut correct = Vec::new();
    let mut broken = Vec::new();
    for block in &document.blocks {
        let kind = if block.kind == "record_heading" {
            "ip"
        } else if block.text.starts_with("关联域名：") {
            "domain"
        } else {
            continue;
        };
        let (_, values) = field(block.text).unwrap();
        for value in values.split(';').map(str::trim) {
            if !seen.insert(value) {
                continue;
            }
            let scope = block.scope.unwrap();
            correct.push(proposal(kind, value, block.id, scope, &document));
            broken.push(proposal(
                kind,
                value,
                block.id,
                if kind == "ip" { scope + 4 } else { intro },
                &document,
            ));
        }
    }
    assert_eq!(correct.len(), 46);
    let (direct, direct_report) = parse(body, correct).unwrap();
    assert_eq!(direct_report.direct_accepted, 46);
    assert_eq!(direct_report.corrected, 0);
    let (recovered, report) = parse(body, broken).unwrap();
    assert_eq!(report.rejected, 0);
    assert_eq!(report.direct_accepted, 0);
    assert_eq!(report.corrected, 46);
    assert_eq!(report.correction_samples.len(), 46);
    assert_eq!(recovered.iter().filter(|i| i.kind == "ip").count(), 10);
    assert_eq!(recovered.iter().filter(|i| i.kind == "domain").count(), 36);
    for (actual, expected) in recovered.iter().zip(&direct) {
        assert_eq!(actual.value, expected.value);
        assert_eq!(actual.evidence, expected.evidence);
        assert_eq!(actual.evidence_spans.len(), 2);
        for span in &actual.evidence_spans {
            assert_eq!(&body[span.start..span.end], span.quote);
        }
    }
    let diagnostics = json!(report).to_string();
    assert!(!diagnostics.contains("134.122.164.65"));
    assert!(!diagnostics.contains("alonesad.com"));
    assert!(!diagnostics.contains("日控制规模"));
}

#[test]
fn bad_record_citations_are_not_repaired_across_records_or_without_semantic_support() {
    let cases = [
        // Another record's metadata cannot justify this record's domain.
        (
            "（一）恶意IP地址：192.0.2.1\n日控制规模：100\n（二）恶意IP地址：192.0.2.2\n关联域名：evil.example",
            "domain",
            "evil.example",
            4,
            2,
            "evidence_context_record_mismatch",
        ),
        // Exact labels exclude negation, examples, victims and recommendations.
        (
            "（一）非恶意IP地址：192.0.2.1\n关联域名：evil.example\n日控制规模：100",
            "domain",
            "evil.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "（一）示例恶意IP地址：192.0.2.1\n关联域名：evil.example\n日控制规模：100",
            "domain",
            "evil.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "（一）推荐IP地址：192.0.2.1\n关联域名：evil.example\n日控制规模：100",
            "domain",
            "evil.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "（一）恶意IP地址：invalid.example\n关联域名：evil.example\n日控制规模：100",
            "domain",
            "evil.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "（一）恶意IP地址：192.0.2.1\n关联域名：victim.evil.example\n日控制规模：100",
            "domain",
            "evil.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "（一）受害者IP地址：192.0.2.1\n关联域名：evil.example\n日控制规模：100",
            "domain",
            "evil.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "（一）恶意IP地址：192.0.2.1\n推荐公共DNS：8.8.8.8\n日控制规模：100",
            "ip",
            "8.8.8.8",
            2,
            3,
            "evidence_context_scope_mismatch",
        ),
        (
            "（一）恶意IP地址：192.0.2.1\n关联受害者域名：victim.example\n日控制规模：100",
            "domain",
            "victim.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "恶意网络资产信息如下：\n（一）恶意IP地址：192.0.2.1\n正文中断，以下用于演示。\n（二）恶意IP地址：192.0.2.2\n关联域名：example.org",
            "domain",
            "example.org",
            5,
            1,
            "evidence_context_record_heading_required",
        ),
        (
            "（一）恶意IP地址：192.0.2.1\n关联域名：evil.example\n推荐公共DNS：8.8.8.8",
            "domain",
            "evil.example",
            2,
            3,
            "evidence_context_record_field_unsupported",
        ),
        (
            "（一）恶意IP地址：192.0.2.1\n日控制规模：100\n举报邮箱silverfox@cert.org.cn。",
            "domain",
            "cert.org.cn",
            3,
            2,
            "evidence_context_scope_mismatch",
        ),
    ];
    for (body, kind, value, ioc, context, reason) in cases {
        let doc = Document::new(body);
        let error = parse(body, vec![proposal(kind, value, ioc, context, &doc)]).unwrap_err();
        assert_eq!(error.diagnostic["reason"], reason, "{body}");
        assert_eq!(error.diagnostic["validation"]["corrected"], 0);
    }
}

#[test]
fn record_repair_requires_verified_ioc_quotes_and_preserves_partial_success() {
    let body = "恶意网络资产信息如下：\n（一）恶意IP地址：192.0.2.1\n关联域名：evil.example\n日控制规模：100";
    let doc = Document::new(body);
    let valid = proposal("domain", "evil.example", 3, 2, &doc);
    let repairable = proposal("ip", "192.0.2.1", 2, 4, &doc);
    let mut missing_block = valid.clone();
    missing_block["evidence_parts"][1]["block_id"] = json!(999);
    let mut fabricated_quote = valid.clone();
    fabricated_quote["evidence_parts"][1]["quote"] = json!("invented.example");
    let wrong_value = proposal("domain", "invented.example", 3, 1, &doc);
    let (entries, report) = parse(
        body,
        vec![
            valid,
            repairable,
            missing_block,
            fabricated_quote,
            wrong_value,
        ],
    )
    .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (report.direct_accepted, report.corrected, report.rejected),
        (1, 1, 3)
    );
    assert_eq!(report.correction_samples[0]["record"], 2);
    assert_eq!(report.correction_samples[0]["expected_context_block_id"], 2);
    assert_eq!(
        report.rejection_samples[0]["reason"],
        "evidence_block_not_found"
    );
    assert_eq!(
        report.rejection_samples[1]["reason"],
        "evidence_not_in_body"
    );
    assert_eq!(
        report.rejection_samples[2]["reason"],
        "evidence_not_in_body"
    );
}

#[test]
fn bare_record_ioc_is_repaired_only_with_its_explicit_malicious_heading() {
    let body = "（一）恶意IP地址：192.0.2.1\n关联域名：evil.example";
    let (items, report) = parse(
        body,
        vec![
            json!({"type":"domain","value":"evil.example","evidence_parts":[
                {"block_id":2,"kind":"ioc","quote":"evil.example"}
            ]}),
        ],
    )
    .unwrap();
    assert_eq!(report.corrected, 1);
    assert_eq!(
        report.correction_samples[0]["reason"],
        "evidence_context_missing"
    );
    assert_eq!(items[0].evidence_spans[0].block_id, 1);
}

#[test]
fn multiline_defanged_records_and_repeated_domains_keep_exact_source_ranges() {
    let body = "恶意网络资产信息如下：\n\n（一）恶意IP地址：192[.]0[.]2[.]1\n关联域名：\n evil[.]example\n日控制规模：100\n（二）恶意IP地址：192.0.2.2\n关联域名：evil[.]example\n日控制规模：200";
    let doc = Document::new(body);
    let mut entries = Vec::new();
    for (ioc, context) in [(4, 5), (7, 8)] {
        let mut item = proposal("domain", "evil.example", ioc, context, &doc);
        item["evidence_parts"][1]["quote"] = json!("evil[.]example");
        entries.push(item);
    }
    let (items, report) = parse(body, entries).unwrap();
    assert_eq!(report.corrected, 2);
    assert_eq!(items[0].value, items[1].value);
    assert_ne!(items[0].evidence, items[1].evidence);
    for item in items {
        for span in item.evidence_spans {
            assert_eq!(&body[span.start..span.end], span.quote);
        }
    }
}

#[test]
fn legacy_validation_reports_deserialize_and_correction_samples_are_bounded() {
    let legacy: ValidationReport =
        serde_json::from_value(json!({"rejected":0,"rejection_samples":[]})).unwrap();
    assert_eq!(legacy, ValidationReport::default());
    let body = "（一）恶意IP地址：192.0.2.1\n日控制规模：100";
    let doc = Document::new(body);
    let item = proposal("ip", "192.0.2.1", 1, 2, &doc);
    let (_, report) = parse(body, vec![item; 101]).unwrap();
    assert_eq!(report.corrected, 101);
    assert_eq!(report.correction_samples.len(), 100);
}
