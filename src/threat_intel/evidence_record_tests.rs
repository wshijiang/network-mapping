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

#[test]
fn server_evidence_units_ground_all_46_silverfox_iocs_without_model_quotes() {
    let body = include_str!("fixtures/silverfox_assets.txt");
    let document = Document::new(body);
    let blocks = document.prompt_blocks();
    let mut seen = HashSet::new();
    let mut proposals = Vec::new();
    for block in &document.blocks {
        let Some(unit) = blocks[block.id - 1]["evidence_unit_id"].as_str() else {
            continue;
        };
        let kind = if block.kind == "record_heading" {
            "ip"
        } else {
            "domain"
        };
        for value in field(block.text).unwrap().1.split(';').map(str::trim) {
            if seen.insert(value) {
                proposals.push(json!({"type":kind,"value":value,"evidence_unit_id":unit}));
            }
        }
    }
    let (items, report) = parse(body, proposals).unwrap();
    assert_eq!(items.len(), 46);
    assert_eq!(
        (
            report.direct_accepted,
            report.unit_accepted,
            report.corrected,
            report.rejected
        ),
        (46, 46, 0, 0)
    );
    for item in items {
        assert_eq!(item.evidence_spans.len(), 2);
        assert_eq!(item.evidence_spans[0].kind, PartKind::Context);
        assert_eq!(item.evidence_spans[1].kind, PartKind::Ioc);
        assert_eq!(item.evidence_spans[1].quote, item.value);
        assert_eq!(
            document.blocks[item.evidence_spans[1].block_id - 1].scope,
            Some(item.evidence_spans[0].block_id)
        );
        for span in item.evidence_spans {
            assert_eq!(&body[span.start..span.end], span.quote);
        }
    }
}

#[test]
fn units_cannot_create_values_cross_records_or_select_benign_fields() {
    let body = "（一）恶意IP地址：192.0.2.1\n关联域名：evil.example\n推荐公共DNS：8.8.8.8\n（二）恶意IP地址：192.0.2.2\n关联域名：other.example\n归属地：中国 香港";
    for (kind, value, unit, reason) in [
        (
            "domain",
            "evil.example",
            "record:4:block:5",
            "ioc_not_in_evidence",
        ),
        (
            "domain",
            "invented.example",
            "record:1:block:2",
            "ioc_not_in_evidence",
        ),
        (
            "domain",
            "vil.example",
            "record:1:block:2",
            "ioc_not_in_evidence",
        ),
        (
            "ip",
            "8.8.8.8",
            "record:1:block:3",
            "evidence_unit_not_found",
        ),
        (
            "domain",
            "evil.example",
            "record:4:block:2",
            "evidence_unit_not_found",
        ),
        (
            "domain",
            "evil.example",
            "record:1:block:0",
            "evidence_unit_not_found",
        ),
        (
            "domain",
            "evil.example",
            "record:1:block:999",
            "evidence_unit_not_found",
        ),
        (
            "domain",
            "evil.example",
            "record:1:block:02",
            "evidence_unit_not_found",
        ),
        (
            "ip",
            "192.0.2.1",
            "record:1:block:2",
            "evidence_unit_not_found",
        ),
        (
            "domain",
            "evil.example",
            "invented-unit",
            "evidence_unit_not_found",
        ),
    ] {
        let error = parse(
            body,
            vec![json!({"type":kind,"value":value,"evidence_unit_id":unit})],
        )
        .unwrap_err();
        assert_eq!(error.diagnostic["reason"], reason, "{unit} {value}");
    }
    let blocks = Document::new(body).prompt_blocks();
    assert!(blocks[2].get("evidence_unit_id").is_none());
    assert!(blocks[5].get("evidence_unit_id").is_none());
    let benign = "（一）非恶意IP地址：192.0.2.1\n关联域名：benign.example";
    assert!(
        Document::new(benign)
            .prompt_blocks()
            .as_array()
            .unwrap()
            .iter()
            .all(|b| b.get("evidence_unit_id").is_none())
    );
}

#[test]
fn units_preserve_defanging_and_coexist_with_legacy_narrative_evidence() {
    let body = "（一）恶意IP地址：192[.]0[.]2[.]1\n关联域名：\n evil[.]example; other.example\n研究确认 third.example 为恶意域名。";
    let (items, report) = parse(body, vec![
        json!({"type":"ip","value":"192.0.2.1","evidence_unit_id":"record:1:block:1"}),
        json!({"type":"domain","value":"evil.example","evidence_unit_id":"record:1:block:3"}),
        json!({"type":"domain","value":"third.example","evidence":"研究确认 third.example 为恶意域名。"}),
    ]).unwrap();
    assert_eq!(report.direct_accepted, 3);
    assert_eq!(report.unit_accepted, 2);
    assert_eq!(items[0].evidence_spans[1].quote, "192[.]0[.]2[.]1");
    assert_eq!(items[1].evidence_spans[1].quote, "evil[.]example");
    for item in items {
        for span in item.evidence_spans {
            assert_eq!(&body[span.start..span.end], span.quote);
        }
    }
    for extra in [json!({"evidence_parts":[]}), json!({"evidence":""})] {
        let mut proposal =
            json!({"type":"ip","value":"192.0.2.1","evidence_unit_id":"record:1:block:1"});
        proposal
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(
            parse(body, vec![proposal]).unwrap_err().code,
            "intel_ai_invalid_schema"
        );
    }
}
