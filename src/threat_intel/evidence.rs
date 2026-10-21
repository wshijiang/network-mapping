//! Verbatim evidence for AI-proposed indicators. Blocks contain all report text;
//! this module never generates a candidate IOC list for the model.
use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum PartKind {
    Ioc,
    Context,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    block_id: usize,
    kind: PartKind,
    quote: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct VerifiedSpan {
    pub block_id: usize,
    pub kind: PartKind,
    pub start: usize,
    pub end: usize,
    pub quote: String,
}

struct Block<'a> {
    id: usize,
    start: usize,
    end: usize,
    text: &'a str,
    kind: &'static str,
    scope: Option<usize>,
}

pub(super) struct Document<'a> {
    body: &'a str,
    blocks: Vec<Block<'a>>,
}

impl<'a> Document<'a> {
    pub fn new(body: &'a str) -> Self {
        let mut start = 0;
        let mut scope = None;
        let mut in_record = false;
        let mut associated_list = false;
        let mut blocks = Vec::new();
        for line in body.split_inclusive('\n') {
            let text = line.trim();
            if !text.is_empty() {
                let offset = line.find(text).unwrap_or(0);
                let id = blocks.len() + 1;
                // Bound prompt overhead without dropping report text. The final
                // block keeps the remainder as prose, with no inherited list scope.
                if id == 2048 {
                    let text = body[start + offset..].trim_end();
                    blocks.push(Block {
                        id,
                        start: start + offset,
                        end: start + offset + text.len(),
                        text,
                        kind: "paragraph",
                        scope: None,
                    });
                    break;
                }
                let kind = if numbered_record(text) {
                    "record_heading"
                } else if in_record && associated_field(text) {
                    "record_field"
                } else if in_record && field(text).is_some() {
                    "record_metadata"
                } else if table_header(text) {
                    "table_header"
                } else if data_line(text) {
                    if in_record && associated_list {
                        "record_field"
                    } else {
                        "list_item"
                    }
                } else if heading(text) {
                    "heading"
                } else {
                    "paragraph"
                };
                match kind {
                    "record_heading" => {
                        scope = Some(id);
                        in_record = true;
                        associated_list = false;
                    }
                    "record_field" => associated_list = true,
                    "record_metadata" => associated_list = false,
                    "heading" => {
                        scope = Some(id);
                        in_record = false;
                        associated_list = false;
                    }
                    "paragraph" => {
                        scope = None;
                        in_record = false;
                        associated_list = false;
                    }
                    _ => {}
                }
                blocks.push(Block {
                    id,
                    start: start + offset,
                    end: start + offset + text.len(),
                    text,
                    kind,
                    scope,
                });
            }
            start += line.len();
        }
        Self { body, blocks }
    }

    pub fn prompt_blocks(&self) -> Value {
        json!(
            self.blocks
                .iter()
                .map(|block| json!({"block_id":block.id,"kind":block.kind,"scope_block_id":block.scope,"text":block.text}))
                .collect::<Vec<_>>()
        )
    }

    pub fn validate(
        &self,
        indicator: &mut Indicator,
        raw_value: &str,
        parts: Option<&Value>,
    ) -> Result<Option<Value>> {
        let Some(parts) = parts else {
            return self.legacy(indicator, raw_value).map(|()| None);
        };
        let parts: Vec<Part> = serde_json::from_value(parts.clone())
            .map_err(|_| Error::bad("intel_ai_invalid_schema"))?;
        if parts.is_empty()
            || parts.len() > 8
            || parts.iter().map(|part| part.quote.len()).sum::<usize>() > 4000
        {
            return Err(Error::bad("intel_ai_invalid_schema"));
        }
        let mut spans = Vec::new();
        for part in parts {
            let block = self
                .blocks
                .get(part.block_id.saturating_sub(1))
                .filter(|block| block.id == part.block_id)
                .ok_or_else(|| rejected("evidence_block_not_found"))?;
            let (start, end) =
                locate(block.text, &part.quote).ok_or_else(|| rejected("evidence_not_in_body"))?;
            spans.push(VerifiedSpan {
                block_id: block.id,
                kind: part.kind,
                start: block.start + start,
                end: block.start + end,
                quote: self.body[block.start + start..block.start + end].into(),
            });
        }
        let correction = match self.validate_spans(indicator, raw_value, &spans) {
            Ok(()) => None,
            Err(error) => {
                let Some(corrected) =
                    self.correct_record_context(indicator, raw_value, &spans, &error)
                else {
                    return Err(error);
                };
                // Corrections use exactly the same validator as model citations.
                self.validate_spans(indicator, raw_value, &corrected)?;
                spans = corrected;
                let mut diagnostic = error.diagnostic;
                diagnostic["correction_method"] = json!("record_heading");
                diagnostic["expected_context_block_id"] = json!(spans[0].block_id);
                Some(diagnostic)
            }
        };
        let evidence = spans
            .iter()
            .map(|span| span.quote.as_str())
            .collect::<Vec<_>>()
            .join("\n[…]\n");
        if evidence.len() > 4000 {
            return Err(Error::bad("intel_ai_invalid_schema"));
        }
        // Store only source substrings and server-computed UTF-8 byte ranges.
        indicator.evidence = evidence;
        indicator.evidence_spans = spans;
        Ok(correction)
    }

    fn validate_spans(
        &self,
        indicator: &Indicator,
        raw_value: &str,
        spans: &[VerifiedSpan],
    ) -> Result<()> {
        let iocs = spans
            .iter()
            .filter(|span| span.kind == PartKind::Ioc)
            .collect::<Vec<_>>();
        if iocs.is_empty()
            || iocs
                .iter()
                .any(|span| !mentions(&span.quote, &indicator.kind, raw_value, &indicator.value))
        {
            return Err(rejected("ioc_not_in_evidence"));
        }
        let contexts = spans
            .iter()
            .filter(|span| span.kind == PartKind::Context)
            .collect::<Vec<_>>();
        for context in &contexts {
            for ioc in &iocs {
                // A self-contained narrative naming THIS exact IOC is evidence
                // in its own right, even when a conclusion appears later.
                let explicit = !ioc_only(&context.quote, indicator)
                    && mentions(&context.quote, &indicator.kind, raw_value, &indicator.value);
                if !explicit && !self.related(context, ioc) {
                    return Err(rejected(self.context_failure(context, ioc)).context(json!({
                        "context_block_id":context.block_id,"ioc_block_id":ioc.block_id,
                        "context_block_kind":self.blocks[context.block_id-1].kind,
                        "ioc_block_kind":self.blocks[ioc.block_id-1].kind,
                        "ioc_scope_block_id":self.blocks[ioc.block_id-1].scope,
                        "expected_context_block_id":self.blocks[ioc.block_id-1].scope
                    })));
                }
            }
        }
        if iocs.iter().all(|span| ioc_only(&span.quote, indicator))
            && !contexts
                .iter()
                .any(|span| self.blocks[span.block_id - 1].kind != "table_header")
        {
            return Err(rejected("evidence_context_missing"));
        }
        Ok(())
    }

    fn context_failure(&self, context: &VerifiedSpan, ioc: &VerifiedSpan) -> &'static str {
        let block = &self.blocks[ioc.block_id - 1];
        let parent = &self.blocks[context.block_id - 1];
        if matches!(block.kind, "record_heading" | "record_field") {
            if matches!(
                parent.kind,
                "record_heading" | "record_field" | "record_metadata"
            ) {
                return if parent.scope != block.scope {
                    "evidence_context_record_mismatch"
                } else {
                    "evidence_context_record_field_unsupported"
                };
            }
            if parent.id < block.scope.unwrap_or(0) {
                return "evidence_context_record_heading_required";
            }
        }
        "evidence_context_scope_mismatch"
    }

    fn correct_record_context(
        &self,
        indicator: &Indicator,
        raw_value: &str,
        spans: &[VerifiedSpan],
        error: &Error,
    ) -> Option<Vec<VerifiedSpan>> {
        if !matches!(
            error.diagnostic["reason"].as_str()?,
            "evidence_context_record_field_unsupported"
                | "evidence_context_record_heading_required"
                | "evidence_context_missing"
        ) {
            return None;
        }
        let iocs = spans
            .iter()
            .filter(|span| span.kind == PartKind::Ioc)
            .collect::<Vec<_>>();
        let scope = self.blocks[iocs.first()?.block_id - 1].scope?;
        let title = &self.blocks[scope - 1];
        let title_kind = malicious_record_kind(title.text)?;
        let (_, title_value) = field(title.text)?;
        // An exact malicious field label and a complete, typed title value are
        // required. Merely sharing a structural scope is never sufficient.
        normalize(title_kind, title_value).ok()?;
        if title.kind != "record_heading"
            || !iocs.iter().all(|ioc| {
                let block = &self.blocks[ioc.block_id - 1];
                block.scope == Some(scope)
                    && mentions(&ioc.quote, &indicator.kind, raw_value, &indicator.value)
                    && mentions(block.text, &indicator.kind, raw_value, &indicator.value)
                    && ((block.id == scope && indicator.kind == title_kind)
                        || (block.kind == "record_field"
                            && indicator.kind == "domain"
                            && self.associated_domain_field(block)))
            })
        {
            return None;
        }
        // Only known metadata from THIS record or its contiguous list's exact
        // introductory heading may be replaced. Never discard cross-record,
        // benign/recommended, arbitrary narrative or unresolved citations.
        for context in spans.iter().filter(|span| span.kind == PartKind::Context) {
            let block = &self.blocks[context.block_id - 1];
            let same_title = block.id == scope;
            let metadata = block.scope == Some(scope)
                && field(block.text).is_some_and(|(label, _)| {
                    matches!(label, "日控制规模" | "归属地" | "关联端口" | "相关端口")
                });
            if !same_title && !metadata && !self.record_introduction(block.id, scope) {
                return None;
            }
        }
        let mut corrected = vec![VerifiedSpan {
            block_id: title.id,
            kind: PartKind::Context,
            start: title.start,
            end: title.end,
            quote: title.text.into(),
        }];
        corrected.extend(iocs.into_iter().cloned());
        (corrected.len() <= 8
            && corrected.iter().map(|span| span.quote.len()).sum::<usize>() <= 4000)
            .then_some(corrected)
    }

    fn associated_domain_field(&self, block: &Block<'_>) -> bool {
        for parent in self.blocks[..block.id].iter().rev() {
            if parent.scope != block.scope || parent.kind != "record_field" {
                return false;
            }
            if let Some((label, _)) = field(parent.text) {
                return matches!(
                    label.to_ascii_lowercase().as_str(),
                    "关联域名"
                        | "相关域名"
                        | "associated domain"
                        | "associated domains"
                        | "related domain"
                        | "related domains"
                );
            }
        }
        false
    }

    fn record_introduction(&self, context_id: usize, scope: usize) -> bool {
        let intro = self.blocks[..scope - 1].iter().rev().find(|block| {
            !matches!(
                block.kind,
                "record_heading" | "record_field" | "record_metadata"
            )
        });
        intro.is_some_and(|block| {
            block.id == context_id
                && block.kind == "heading"
                && matches!(
                    block.text.trim_end_matches(['：', ':']),
                    "恶意网络资产信息如下" | "恶意网络资产信息" | "恶意网络资产" | "恶意资产列表"
                )
        })
    }

    fn legacy(&self, indicator: &mut Indicator, raw_value: &str) -> Result<()> {
        let (start, end) = locate(self.body, &indicator.evidence)
            .ok_or_else(|| rejected("evidence_not_in_body"))?;
        let quote = &self.body[start..end];
        if !mentions(quote, &indicator.kind, raw_value, &indicator.value) {
            return Err(rejected("ioc_not_in_evidence"));
        }
        if ioc_only(quote, indicator) {
            return Err(rejected("evidence_context_missing"));
        }
        let block_id = self
            .blocks
            .iter()
            .find(|block| block.start <= start && block.end >= start)
            .map_or(1, |block| block.id);
        indicator.evidence = quote.into();
        indicator.evidence_spans = vec![VerifiedSpan {
            block_id,
            kind: PartKind::Ioc,
            start,
            end,
            quote: quote.into(),
        }];
        Ok(())
    }

    fn related(&self, context: &VerifiedSpan, ioc: &VerifiedSpan) -> bool {
        // A verbatim narrative/record heading may itself contain the complete
        // IOC; overlapping citations here refer to the same source statement.
        if context.block_id == ioc.block_id && context.start <= ioc.start && context.end >= ioc.end
        {
            return true;
        }
        if context.end > ioc.start {
            return false;
        }
        let block = &self.blocks[ioc.block_id - 1];
        if context.block_id != ioc.block_id {
            let parent = &self.blocks[context.block_id - 1];
            return ((matches!(parent.kind, "heading" | "table_header")
                && block.kind == "list_item")
                || (parent.kind == "record_heading" && block.kind == "record_field"))
                && block.scope.is_some()
                && (if parent.kind != "table_header" {
                    block.scope == Some(parent.id)
                } else {
                    block.scope == parent.scope
                })
                && compact(&context.quote) == compact(parent.text);
        }
        // Old snapshots may have flattened whitespace. Permit a shared heading
        // only across uninterrupted compact list data, never prose/new headings.
        let between = self.body[context.end..ioc.start].trim();
        heading(&context.quote) && (between.is_empty() || data_line(between))
    }
}

// Generic numbered key/value records, not publisher-specific IOC adapters.
fn field(text: &str) -> Option<(&str, &str)> {
    let index = text.find(['：', ':'])?;
    let label = text[..index].trim();
    if label.is_empty()
        || label.chars().count() > 80
        || !label.chars().any(char::is_alphabetic)
        || label.contains(['。', '！', '？', ';', '；', '!', '?'])
    {
        return None;
    }
    let delimiter = text[index..].chars().next()?.len_utf8();
    Some((label, text[index + delimiter..].trim()))
}

fn numbered_record(text: &str) -> bool {
    let Some((label, value)) = field(text) else {
        return false;
    };
    if !data_line(value) {
        return false;
    }
    let ordinal = |s: &str| {
        !s.is_empty()
            && s.chars().count() <= 10
            && s.chars()
                .all(|c| c.is_ascii_digit() || "一二三四五六七八九十百零〇".contains(c))
    };
    if let Some(label) = label.strip_prefix('（').or_else(|| label.strip_prefix('(')) {
        let Some(end) = label.find(['）', ')']) else {
            return false;
        };
        let delimiter = label[end..].chars().next().map_or(0, char::len_utf8);
        return ordinal(&label[..end]) && !label[end + delimiter..].trim().is_empty();
    }
    label
        .find(['、', '.', '．'])
        .is_some_and(|end| ordinal(&label[..end]) && label[end..].chars().count() > 1)
}

fn associated_field(text: &str) -> bool {
    let Some((label, value)) = field(text) else {
        return false;
    };
    let label = label.to_ascii_lowercase();
    ["关联", "相关", "associated ", "related "]
        .iter()
        .any(|prefix| label.starts_with(prefix))
        && (value.is_empty() || data_line(value))
}

fn malicious_record_kind(text: &str) -> Option<&'static str> {
    if !numbered_record(text) {
        return None;
    }
    let (label, _) = field(text)?;
    let end = label.find(['）', ')', '、', '.', '．'])?;
    let label = label[end..]
        .chars()
        .next()
        .map(|c| &label[end + c.len_utf8()..])?;
    let label = label
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    match label.as_str() {
        "恶意ip地址" | "恶意ip" | "maliciousipaddress" | "maliciousip" => Some("ip"),
        "恶意域名" | "maliciousdomain" => Some("domain"),
        _ => None,
    }
}

fn rejected(reason: &'static str) -> Error {
    Error::bad("intel_ai_evidence_not_found").context(json!({"reason":reason}))
}

fn compact(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// This recognizes structural compact rows, including obfuscation and table cells;
// it does not enumerate, normalize, or select any indicator in the input report.
fn table_header(text: &str) -> bool {
    // Text snapshots can flatten each table cell onto its own line. Neutral
    // column names preserve their enclosing heading instead of replacing it.
    let text = text.trim().trim_matches('|').trim();
    !text.is_empty()
        && text.split('|').all(|cell| {
            matches!(
                cell.trim().to_ascii_lowercase().as_str(),
                "序号"
                    | "ip"
                    | "ip地址"
                    | "ip 地址"
                    | "ip address"
                    | "domain"
                    | "域名"
                    | "端口"
                    | "port"
                    | "ioc"
                    | "indicator"
                    | "value"
                    | "类型"
                    | "type"
                    | "指标"
                    | "指标值"
                    | "地址"
                    | "哈希"
                    | "hash"
            )
        })
}

fn data_line(text: &str) -> bool {
    let text = text.replace(['、', '，'], ",");
    let text = text.trim().trim_start_matches(['-', '*', '•', ' ']);
    !text.is_empty()
        && text.len() <= 4000
        && text.chars().all(|c| {
            c.is_ascii_alphanumeric() || c.is_whitespace() || ".:[]()/\\-_?=&%#@+~,|;".contains(c)
        })
        && ((text.contains('|')
            && text
                .chars()
                .any(|c| c.is_ascii_digit() || ".:/[]".contains(c)))
            || text.split_whitespace().all(|token| {
                token
                    .chars()
                    .any(|c| c.is_ascii_digit() || ".:[]/|".contains(c))
                    || (token.len() >= 32 && token.bytes().all(|c| c.is_ascii_hexdigit()))
                    || token == "|"
                    || token == "-"
            }))
}

fn heading(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && text.chars().count() <= 120
        && !data_line(text)
        && !text.contains(['。', '！', '？', ';', '；', '.', '!', '?'])
        && text.chars().any(char::is_alphabetic)
}

fn ioc_only(quote: &str, indicator: &Indicator) -> bool {
    normalize(&indicator.kind, quote.trim()).is_ok_and(|(_, value)| value == indicator.value)
}

fn refang(text: &str) -> String {
    let text = text
        .replace("[.]", ".")
        .replace("[:]", ":")
        .replace("[://]", "://");
    regex::Regex::new("(?i)hxxps?://")
        .expect("static regex")
        .replace_all(&text, |captures: &regex::Captures<'_>| {
            if captures[0].len() == 8 {
                "https://"
            } else {
                "http://"
            }
        })
        .into_owned()
}

fn mentions(quote: &str, kind: &str, raw: &str, value: &str) -> bool {
    let quote = refang(quote);
    if kind == "asn" {
        return regex::Regex::new(r"(?i)(?-u:\b)AS\s*[0-9]+(?-u:\b)")
            .expect("static regex")
            .find_iter(&quote)
            .any(|m| normalize(kind, m.as_str()).is_ok_and(|(_, found)| found == value));
    }
    let fold = |text: &str| {
        if kind == "url" {
            text.to_owned()
        } else {
            text.to_ascii_lowercase()
        }
    };
    let quote = fold(&quote);
    [refang(raw.trim()), value.to_owned()].iter().any(|needle| {
        let needle = fold(needle);
        !needle.is_empty()
            && quote.match_indices(&needle).any(|(start, _)| {
                let end = start + needle.len();
                let before = quote[..start].chars().next_back();
                let after = quote[end..].chars().next();
                let continues = |c: char| c.is_ascii_alphanumeric() || "._-:/@%?=&#+[]".contains(c);
                let after_period = after == Some('.')
                    && quote[end + 1..]
                        .chars()
                        .next()
                        .is_none_or(|c| !continues(c));
                before.is_none_or(|c| !continues(c))
                    && (after.is_none_or(|c| !continues(c)) || after_period)
            })
    })
}

// Match whitespace only; punctuation, case, defanging and text must stay verbatim.
// The mapping keeps returned offsets tied to the immutable original snapshot.
fn locate(body: &str, quote: &str) -> Option<(usize, usize)> {
    let quote = compact(quote);
    if quote.is_empty() {
        return None;
    }
    let mut normalized = String::new();
    let mut offsets = Vec::new();
    let mut whitespace = None;
    for (offset, ch) in body.char_indices() {
        if ch.is_whitespace() {
            whitespace.get_or_insert(offset);
            continue;
        }
        if !normalized.is_empty()
            && let Some(offset) = whitespace.take()
        {
            normalized.push(' ');
            offsets.push(offset);
        }
        whitespace = None;
        normalized.push(ch);
        offsets.extend(offset..offset + ch.len_utf8());
    }
    let start = normalized.find(&quote)?;
    Some((offsets[start], offsets[start + quote.len() - 1] + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(
        value: &str,
        context_block: usize,
        context: &str,
        ioc_block: usize,
        quote: &str,
    ) -> Value {
        json!({"type":"ip","value":value,"role":"malicious_dns","evidence_parts":[
            {"block_id":context_block,"kind":"context","quote":context},
            {"block_id":ioc_block,"kind":"ioc","quote":quote}
        ]})
    }

    fn parse_item(body: &str, item: Value) -> Result<Vec<Indicator>> {
        parse::ai_result(&json!({"iocs":[item]}).to_string(), body)
    }

    #[test]
    fn shared_heading_accepts_all_51_defanged_entries_with_verifiable_byte_ranges() {
        let heading = "存活恶意DNS服务器";
        let values = (1..=51)
            .map(|n| format!("192[.]0[.]2[.]{n}"))
            .collect::<Vec<_>>();
        let body = format!("  {heading}\r\n{}\n", values.join("\n"));
        let output = values
            .iter()
            .enumerate()
            .map(|(n, value)| item(value, 1, heading, n + 2, value))
            .collect::<Vec<_>>();
        let (entries, report) =
            parse::ai_result_isolated(&json!({"iocs":output}).to_string(), &body).unwrap();
        assert_eq!(entries.len(), 51);
        assert_eq!(report.rejected, 0);
        assert_eq!(entries[50].value, "192.0.2.51");
        for entry in entries {
            assert_eq!(entry.evidence_spans.len(), 2);
            for span in entry.evidence_spans {
                assert_eq!(&body[span.start..span.end], span.quote);
            }
        }
    }

    #[test]
    fn short_ip_passes_with_context_and_bare_ip_without_context_is_rejected() {
        let body = "恶意DNS服务器\n143.92.56.8";
        assert_eq!("143.92.56.8".len(), 11);
        assert_eq!(
            parse_item(
                body,
                item("143.92.56.8", 1, "恶意DNS服务器", 2, "143.92.56.8")
            )
            .unwrap()
            .len(),
            1
        );
        let bare = json!({"type":"ip","value":"143.92.56.8","evidence":"143.92.56.8"});
        assert_eq!(
            parse_item(body, bare).unwrap_err().diagnostic["reason"],
            "evidence_context_missing"
        );
    }

    #[test]
    fn contexts_stop_at_new_headings_prose_and_other_table_groups() {
        for body in [
            "恶意DNS服务器\n192.0.2.1\n推荐公共DNS\n8.8.8.8",
            "Malicious DNS servers\n192.0.2.1\nRecommended public DNS\n8.8.8.8",
            "恶意DNS服务器\n192.0.2.1\n以下是供正常上网使用的公共解析服务。\n8.8.8.8",
        ] {
            let heading = body.lines().next().unwrap();
            let bad = item("8.8.8.8", 1, heading, 4, "8.8.8.8");
            assert_eq!(
                parse_item(body, bad).unwrap_err().diagnostic["reason"],
                "evidence_context_scope_mismatch"
            );
        }
        let table = "Malicious infrastructure\n192[.]0[.]2[.]1 | DNS\n192.0.2.2 | payload\nRecommended DNS\n8.8.8.8 | public";
        assert!(
            parse_item(
                table,
                item("192.0.2.2", 1, "Malicious infrastructure", 3, "192.0.2.2")
            )
            .is_ok()
        );
        assert_eq!(
            parse_item(
                table,
                item("8.8.8.8", 1, "Malicious infrastructure", 5, "8.8.8.8")
            )
            .unwrap_err()
            .diagnostic["reason"],
            "evidence_context_scope_mismatch"
        );
    }

    #[test]
    fn legacy_flattened_list_allows_only_compact_data_between_heading_and_item() {
        let body = "相关IOC 存活恶意DNS服务器 192[.]0[.]2[.]1 192[.]0[.]2[.]2 143.92.56.8 五、致谢";
        let hash = digest(body.as_bytes());
        assert!(
            parse_item(
                body,
                item("143.92.56.8", 1, "存活恶意DNS服务器", 1, "143.92.56.8")
            )
            .is_ok()
        );
        assert_eq!(digest(body.as_bytes()), hash);
        let mixed = "Malicious DNS servers 192.0.2.1 Recommended public DNS 8.8.8.8";
        assert_eq!(
            parse_item(
                mixed,
                item("8.8.8.8", 1, "Malicious DNS servers", 1, "8.8.8.8")
            )
            .unwrap_err()
            .diagnostic["reason"],
            "evidence_context_scope_mismatch"
        );
    }

    #[test]
    fn validates_exact_indicator_boundaries_and_preserves_url_path_case() {
        for (kind, value, quote, valid) in [
            ("ip", "192.0.2.1", "Malicious 192.0.2.10 address.", false),
            (
                "ip",
                "192.0.2.1",
                "Malicious 192.0.2.1:443 endpoint.",
                false,
            ),
            (
                "ip",
                "192.0.2.1",
                "Malicious 192[.]0[.]2[.]1 address.",
                true,
            ),
            (
                "domain",
                "evil.example",
                "Malicious not-evil.example domain.",
                false,
            ),
            (
                "domain",
                "evil.example",
                "Malicious sub.evil.example domain.",
                false,
            ),
            (
                "domain",
                "evil.example",
                "Malicious EVIL[.]EXAMPLE domain.",
                true,
            ),
            (
                "url",
                "https://evil.example/A",
                "Payload at HXXPS://evil[.]example/A",
                true,
            ),
            (
                "url",
                "https://evil.example/A",
                "Payload at hxxps://evil[.]example/a",
                false,
            ),
            ("asn", "AS64496", "该报告将AS 64496标为恶意基础设施。", true),
        ] {
            let output = json!({"type":kind,"value":value,"evidence":quote});
            assert_eq!(parse_item(quote, output).is_ok(), valid, "{kind} {value}");
        }
    }

    #[test]
    fn rejects_invented_quotes_blocks_and_server_owned_ranges_without_leaking_text() {
        let body = "恶意DNS服务器\n192[.]0[.]2[.]1";
        let mut bad = item("192.0.2.1", 1, "恶意DNS服务器", 2, "192.0.2.1");
        assert_eq!(
            parse_item(body, bad.clone()).unwrap_err().diagnostic["reason"],
            "evidence_not_in_body"
        );
        bad["evidence_parts"][1]["quote"] = json!("192[.]0[.]2[.]1");
        bad["evidence_parts"][1]["block_id"] = json!(999);
        let error = parse_item(body, bad.clone()).unwrap_err();
        assert_eq!(error.diagnostic["reason"], "evidence_block_not_found");
        assert!(!error.report().to_string().contains("192"));
        bad["evidence_spans"] = json!([]);
        assert_eq!(
            parse_item(body, bad).unwrap_err().code,
            "intel_ai_invalid_schema"
        );
        let mut forged = item("192.0.2.1", 1, "恶意DNS服务器", 2, "192[.]0[.]2[.]1");
        forged["evidence_parts"][0]["start"] = json!(0);
        assert_eq!(
            parse_item(body, forged).unwrap_err().code,
            "intel_ai_invalid_schema"
        );
    }

    #[test]
    fn all_text_reaches_prompt_including_defanged_values_without_a_candidate_list() {
        let body = "标题\nordinary non-IOC prose\nodd[.]example\n1[.]2[.]3[.]4\n";
        let blocks = Document::new(body).prompt_blocks();
        assert_eq!(blocks.as_array().unwrap().len(), 4);
        assert_eq!(blocks[1]["text"], "ordinary non-IOC prose");
        assert_eq!(blocks[2]["text"], "odd[.]example");
        let huge = (0..2100)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let doc = Document::new(&huge);
        assert_eq!(doc.blocks.len(), 2048);
        assert!(doc.blocks.last().unwrap().text.ends_with("line 2099"));
    }
    #[test]
    fn detached_table_headers_and_later_explicit_asn_statements_keep_report_evidence() {
        let body = "一、事件概述\n检测到 AS 64512 相关的异常流量。\n二、恶意IP地址\n序号\nIP地址\n序号\nIP地址\n1\n192.0.2.1\n2\n198.51.100.2\n三、防范建议\n应核查并注销 AS 64512 等恶意 AS 资源。";
        let document = Document::new(body);
        let find = |text: &str| {
            document
                .blocks
                .iter()
                .find(|block| block.text == text)
                .unwrap()
                .id
        };
        let title = "二、恶意IP地址";
        let addresses = ["192.0.2.1", "198.51.100.2"];
        let mut proposals = addresses
            .iter()
            .map(|ip| item(ip, find(title), title, find(ip), ip))
            .collect::<Vec<_>>();
        let context = "应核查并注销 AS 64512 等恶意 AS 资源。";
        let intro = document
            .blocks
            .iter()
            .find(|block| block.text.starts_with("检测到"))
            .unwrap();
        let mut asn = item("AS64512", find(context), context, intro.id, "AS 64512");
        asn["type"] = json!("asn");
        proposals.push(asn);
        let (entries, validation) =
            parse::ai_result_isolated(&json!({"iocs":proposals}).to_string(), body).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(validation.rejected, 0);
        // A later ASN statement cannot justify an unrelated IP or a different ASN.
        assert!(
            parse_item(
                body,
                item(
                    addresses[0],
                    find(context),
                    context,
                    find(addresses[0]),
                    addresses[0]
                )
            )
            .is_err()
        );
        let unrelated = "AS64513\n稍后将核查 AS64512 等恶意 AS 资源。";
        let mut bad = item(
            "AS64513",
            2,
            "稍后将核查 AS64512 等恶意 AS 资源。",
            1,
            "AS64513",
        );
        bad["type"] = json!("asn");
        assert!(parse_item(unrelated, bad).is_err());
    }

    #[test]
    fn numbered_asset_records_keep_inline_ips_and_associated_domains_in_their_own_scope() {
        let body = "恶意网络资产信息如下：\n（一）恶意IP地址：177.4.3.99\n关联域名：11x.mlcrosoft.vip、c72.mlcrosoft.my\n关联端口：443\n归属地：中国 中国香港\n日控制规模：6549\n（二）恶意IP地址：177.4.3.35\n关联域名：18.mlcro.net、23.mlcro.net\n二、排查方法\n推荐公共DNS：8.8.8.8";
        let first = "（一）恶意IP地址：177.4.3.99";
        let second = "（二）恶意IP地址：177.4.3.35";
        for (value, context_block, context, ioc_block) in [
            ("177.4.3.99", 2, first, 2),
            ("11x.mlcrosoft.vip", 2, first, 3),
            ("c72.mlcrosoft.my", 2, first, 3),
            ("177.4.3.35", 7, second, 7),
            ("18.mlcro.net", 7, second, 8),
            ("23.mlcro.net", 7, second, 8),
        ] {
            let mut proposal = item(value, context_block, context, ioc_block, value);
            if value.contains("mlcro") {
                proposal["type"] = json!("domain");
            }
            assert!(parse_item(body, proposal).is_ok(), "{value}");
        }
        let mut crossed = item("18.mlcro.net", 2, first, 8, "18.mlcro.net");
        crossed["type"] = json!("domain");
        assert_eq!(
            parse_item(body, crossed).unwrap_err().diagnostic["reason"],
            "evidence_context_record_mismatch"
        );
        assert!(parse_item(body, item("8.8.8.8", 2, first, 10, "8.8.8.8")).is_err());
        let benign_field = "（一）恶意IP地址：177.4.3.99\n推荐公共DNS：8.8.8.8";
        assert!(parse_item(benign_field, item("8.8.8.8", 1, first, 2, "8.8.8.8")).is_err());
    }

    #[test]
    fn table_column_headers_preserve_scope_but_cannot_supply_malicious_context_alone() {
        let body = "恶意 IP 地址\n序号 | IP地址\n1 | 192[.]0[.]2[.]1\n推荐正常 DNS\n序号 | IP地址\n1 | 8.8.8.8";
        let proposal = json!({"type":"ip","value":"192.0.2.1","evidence_parts":[
            {"block_id":1,"kind":"context","quote":"恶意 IP 地址"},
            {"block_id":2,"kind":"context","quote":"序号 | IP地址"},
            {"block_id":3,"kind":"ioc","quote":"192[.]0[.]2[.]1"}
        ]});
        assert_eq!(parse_item(body, proposal.clone()).unwrap().len(), 1);
        let mut weak = proposal.clone();
        weak["evidence_parts"].as_array_mut().unwrap().remove(0);
        assert_eq!(
            parse_item(body, weak).unwrap_err().diagnostic["reason"],
            "evidence_context_missing"
        );
        let mut crossed = proposal;
        crossed["value"] = json!("8.8.8.8");
        crossed["evidence_parts"][2] = json!({"block_id":6,"kind":"ioc","quote":"8.8.8.8"});
        assert_eq!(
            parse_item(body, crossed).unwrap_err().diagnostic["reason"],
            "evidence_context_scope_mismatch"
        );
    }
}

#[cfg(test)]
#[path = "evidence_record_tests.rs"]
mod record_tests;
