//! Deterministic parsing only. Finding a name in a file path never attributes an IOC.
use super::*;
use quick_xml::{Reader, events::Event};
use scraper::{Html, Selector};

pub(super) fn indicators(data: &[u8], format: &str) -> Result<Vec<Indicator>> {
    if data.len() > MAX_BYTES {
        return Err(Error::bad("intel_source_too_large"));
    }
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    if data.starts_with(b"PK\x03\x04") {
        // Read one data file in memory; never extract archive paths to disk.
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))
            .map_err(|_| Error::bad("intel_invalid_zip"))?;
        if archive.len() != 1 {
            return Err(Error::bad("intel_zip_single_file_required"));
        }
        let file = archive
            .by_index(0)
            .map_err(|_| Error::bad("intel_invalid_zip"))?;
        if file.is_dir() || file.size() > MAX_BYTES as u64 {
            return Err(Error::bad("intel_source_too_large"));
        }
        use std::io::Read;
        let mut content = vec![];
        file.take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut content)
            .map_err(|_| Error::bad("intel_invalid_zip"))?;
        if content.len() > MAX_BYTES || content.starts_with(b"PK\x03\x04") {
            return Err(Error::bad("intel_source_too_large"));
        }
        return indicators(&content, format);
    }
    if format == "threatfox" || format == "threatfox_export" {
        return threatfox_document(data, format, false).map(|(items, _)| items);
    }
    if format == "json" {
        let v: Value =
            serde_json::from_slice(data).map_err(|_| Error::bad("intel_invalid_json"))?;
        if v.get("Event").is_some() || v.get("response").is_some() {
            return misp(&v);
        }
        let rows = v
            .as_array()
            .or_else(|| v.get("iocs").and_then(Value::as_array))
            .ok_or_else(|| Error::bad("intel_invalid_ioc_document"))?;
        if rows.len() > MAX_ITEMS {
            return Err(Error::bad("intel_too_many_items"));
        }
        return rows
            .iter()
            .map(|v| {
                let mut i: Indicator = serde_json::from_value(v.clone())
                    .map_err(|_| Error::bad("intel_invalid_indicator"))?;
                i.normalize()?;
                Ok(i)
            })
            .collect();
    }
    let text = std::str::from_utf8(data).map_err(|_| Error::bad("intel_source_not_utf8"))?;
    if format == "markdown" {
        return markdown(text);
    }
    let rows = csv_rows(text)?;
    let header = rows.first().filter(|row| {
        row.iter().any(|s| {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "ioc" | "value" | "ioc_value"
            )
        })
    });
    if header.is_none() {
        let mut out = vec![];
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(mut i) = guess(line.trim_matches('`')) {
                i.normalize()?;
                out.push(i);
            }
            if out.len() > MAX_ITEMS {
                return Err(Error::bad("intel_too_many_items"));
            }
        }
        if out.is_empty() && !text.trim().is_empty() {
            return Err(Error::bad("intel_no_supported_indicators"));
        }
        return Ok(out);
    }
    let mut out = vec![];
    for row in rows.iter().skip(usize::from(header.is_some())) {
        if row.is_empty() || row[0].trim_start().starts_with('#') {
            continue;
        }
        if let Some(header) = header {
            if row.len() != header.len() {
                return Err(Error::bad("intel_invalid_csv"));
            }
            if header
                .iter()
                .any(|field| field.trim().eq_ignore_ascii_case("ioc_type"))
            {
                let object = import_parse::csv_object(
                    header
                        .iter()
                        .map(String::as_str)
                        .zip(row.iter().map(String::as_str)),
                )?;
                out.push(threatfox_row(&Value::Object(object), None)?);
                continue;
            }
            let at = |names: &[&str]| {
                header
                    .iter()
                    .position(|s| names.contains(&s.trim().to_ascii_lowercase().as_str()))
                    .and_then(|idx| row.get(idx))
                    .map(|s| s.trim())
                    .unwrap_or("")
            };
            let value = at(&["ioc", "value", "ioc_value"]);
            let kind = at(&["type", "ioc_type"]);
            let mut i = if kind.is_empty() {
                guess(value).ok_or_else(|| Error::bad("intel_invalid_indicator"))?
            } else {
                Indicator::simple(kind, value)
            };
            i.external_id = at(&["id", "ioc_id"]).to_owned();
            i.malware = at(&["malware_printable", "malware"]).to_owned();
            let reference = at(&["reference"]);
            if !reference.is_empty() {
                i.reference = Some(reference.to_owned());
            }
            let confidence = at(&["confidence_level", "confidence"]);
            if !confidence.is_empty() {
                i.confidence = Some(
                    confidence
                        .parse()
                        .map_err(|_| Error::bad("intel_invalid_confidence"))?,
                );
            }
            let verdict = at(&["verdict"]);
            if !verdict.is_empty() {
                i.verdict = verdict.into();
            }
            i.attack_types = at(&["attack_types"])
                .split('|')
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect();
            i.role = at(&["role"]).to_owned();
            i.resource_owner = at(&["resource_owner"]).to_owned();
            i.normalize()?;
            out.push(i);
        } else {
            // Whole tokens/cells only: never regex-mine arbitrary prose for IPs.
            for cell in row {
                if let Some(mut i) = guess(cell.trim().trim_matches('`')) {
                    i.normalize()?;
                    out.push(i);
                    break;
                }
            }
        }
        if out.len() > MAX_ITEMS {
            return Err(Error::bad("intel_too_many_items"));
        }
    }
    if out.is_empty() && !text.trim().is_empty() {
        return Err(Error::bad("intel_no_supported_indicators"));
    }
    Ok(out)
}
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
// ESET publishes native MISP event exports alongside its hash lists. Event
// titles/galaxies describe a report, not attribution for every attribute.
fn misp(document: &Value) -> Result<Vec<Indicator>> {
    misp_report(document, false).map(|(items, _)| items)
}
pub(super) fn github_indicators(
    data: &[u8],
    format: &str,
) -> Result<(Vec<Indicator>, ValidationReport)> {
    if data.len() > MAX_BYTES {
        return Err(Error::bad("intel_source_too_large"));
    }
    if format == "json" {
        let document: Value =
            serde_json::from_slice(data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data))
                .map_err(|_| Error::bad("intel_invalid_json"))?;
        if document.get("Event").is_some() || document.get("response").is_some() {
            return misp_report(&document, true);
        }
    }
    indicators(data, format).map(|items| (items, ValidationReport::default()))
}
fn misp_report(
    document: &Value,
    isolate_invalid: bool,
) -> Result<(Vec<Indicator>, ValidationReport)> {
    let events: Vec<&Value> = match document.get("response") {
        Some(Value::Array(events)) => events.iter().collect(),
        Some(event) => vec![event],
        None => vec![document],
    };
    let mut out = vec![];
    let mut report = ValidationReport::default();
    for event in events {
        let event = event.get("Event").unwrap_or(event);
        let attributes = event.get("Attribute").and_then(Value::as_array);
        let reference = attributes.into_iter().flatten().find_map(|a| {
            (text(a, "type") == "link" && text(a, "category") == "External analysis")
                .then(|| text(a, "value").to_owned())
        });
        let object_attributes = event
            .get("Object")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(|o| {
                o.get("Attribute")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            });
        for (index, a) in attributes
            .into_iter()
            .flatten()
            .chain(object_attributes)
            .enumerate()
        {
            if a.get("deleted")
                .is_some_and(|v| v == true || v == "1" || v == "true")
            {
                continue;
            }
            // Ignore victim identities, report links, email senders and normal
            // context. Older official exports set to_ids=false even on hashes;
            // that flag is not a confidence/review gate for these categories.
            if !matches!(
                text(a, "category"),
                "Network activity" | "Artifacts dropped" | "Payload delivery"
            ) {
                continue;
            }
            let kind = match text(a, "type") {
                "ip-dst" => "ip",
                "domain" | "hostname" => "domain",
                "url" => "url",
                "md5" => "md5",
                "sha1" => "sha1",
                "sha256" => "sha256",
                _ => continue,
            };
            let mut i = Indicator::simple(kind, text(a, "value"));
            i.external_id = text(a, "uuid").to_owned();
            i.reference = reference.clone();
            i.evidence = json!({"event_uuid":event.get("uuid"),"report":event.get("info"),
                "attribute_uuid":a.get("uuid"),"category":a.get("category"),
                "comment":a.get("comment"),"to_ids":a.get("to_ids")})
            .to_string();
            i.first_seen = a
                .get("first_seen")
                .and_then(Value::as_str)
                .map(str::to_owned);
            i.last_seen = a
                .get("last_seen")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Err(error) = i.normalize() {
                let raw = json!({"id":i.external_id,"ioc_type":kind,"ioc":text(a,"value")});
                if isolate_invalid && report.reject(&raw, None, index as i64 + 1, &error) {
                    continue;
                }
                return Err(error);
            }
            out.push(i);
            if out.len() > MAX_ITEMS {
                return Err(Error::bad("intel_too_many_items"));
            }
        }
    }
    if out.is_empty() && report.rejected == 0 {
        return Err(Error::bad("intel_no_supported_indicators"));
    }
    Ok((out, report))
}
fn guess(value: &str) -> Option<Indicator> {
    if value.get(..2).is_some_and(|v| v.eq_ignore_ascii_case("as")) {
        let number = value[2..].trim();
        if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
            return Some(Indicator::simple("asn", value));
        }
    }
    if value.contains(char::is_whitespace) {
        return None;
    }
    let kind = if (value.contains("://") || value.contains("[:]//") || value.contains("[://]"))
        && normalize("url", value).is_ok()
    {
        "url"
    } else if normalize("ip", value).is_ok() {
        "ip"
    } else if normalize("ip_port", value).is_ok() {
        "ip_port"
    } else if [32, 40, 64].contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        match value.len() {
            32 => "md5",
            40 => "sha1",
            _ => "sha256",
        }
    } else if value.contains('.') && normalize("domain", value).is_ok() {
        "domain"
    } else {
        return None;
    };
    Some(Indicator::simple(kind, value))
}
fn csv_rows(input: &str) -> Result<Vec<Vec<String>>> {
    let input = input.trim_start_matches('\u{feff}');
    let mut offset = 0;
    let mut unprefixed = None;
    for line in input.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(comment) = trimmed.strip_prefix('#') {
            let mut probe = csv::ReaderBuilder::new()
                .has_headers(false)
                .from_reader(import_parse::CsvPadding::new(comment.trim().as_bytes()));
            if let Some(Ok(record)) = probe.records().next()
                && record.iter().any(|field| {
                    matches!(
                        field.trim().to_ascii_lowercase().as_str(),
                        "ioc" | "ioc_value" | "value"
                    )
                })
                && record.iter().any(|field| {
                    matches!(
                        field.trim().to_ascii_lowercase().as_str(),
                        "type" | "ioc_type"
                    )
                })
            {
                unprefixed = Some(format!(
                    "{}\n{}",
                    comment.trim(),
                    &input[offset + line.len()..]
                ));
                break;
            }
        } else if !trimmed.is_empty() {
            break;
        }
        offset += line.len();
    }
    let content = unprefixed.as_deref().unwrap_or(&input[offset..]);
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .comment(Some(b'#'))
        .from_reader(import_parse::CsvPadding::new(content.as_bytes()));
    let mut rows = Vec::new();
    for row in csv.records() {
        let row = row.map_err(|_| Error::bad("intel_invalid_csv"))?;
        if row.len() > 128 {
            return Err(Error::bad("intel_invalid_csv"));
        }
        rows.push(row.iter().map(str::to_owned).collect());
        if rows.len() > MAX_ITEMS + 1 {
            return Err(Error::bad("intel_too_many_items"));
        }
    }
    Ok(rows)
}

fn markdown(text: &str) -> Result<Vec<Indicator>> {
    let mut columns = Vec::<(usize, &str)>::new();
    let mut result = vec![];
    for line in text.lines() {
        if !line.trim().starts_with('|') {
            columns.clear();
            continue;
        }
        let cells = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|s| s.trim().trim_matches('`'))
            .collect::<Vec<_>>();
        let headers = cells
            .iter()
            .enumerate()
            .filter_map(|(idx, s)| {
                let header = s.to_ascii_lowercase().replace(['-', ' ', '_'], "");
                let kind = match header.as_str() {
                    "sha1" => "sha1",
                    "sha256" => "sha256",
                    "md5" => "md5",
                    "ip" | "ipaddress" | "ipaddresses" | "ipv4" => "ip",
                    "domain" | "domains" | "domainname" => "domain",
                    "url" | "urls" => "url",
                    _ => return None,
                };
                Some((idx, kind))
            })
            .collect::<Vec<_>>();
        if !headers.is_empty() {
            columns = headers;
            continue;
        }
        for (idx, kind) in &columns {
            if let Some(cell) = cells.get(*idx) {
                let mut i = Indicator::simple(kind, cell);
                if i.normalize().is_ok() {
                    result.push(i);
                }
            }
        }
        if result.len() > MAX_ITEMS {
            return Err(Error::bad("intel_too_many_items"));
        }
    }
    if result.is_empty() {
        return Err(Error::bad("intel_no_supported_indicators"));
    }
    Ok(result)
}

pub(super) struct ArticleLink {
    pub url: String,
    pub title: String,
    pub fingerprint: String,
}
fn atom_link(element: &quick_xml::events::BytesStart<'_>) -> Result<Option<String>> {
    let mut href = None;
    let mut alternate = true;
    for attr in element.attributes() {
        let attr = attr.map_err(|_| Error::bad("intel_invalid_rss"))?;
        let raw = std::str::from_utf8(&attr.value).map_err(|_| Error::bad("intel_invalid_rss"))?;
        let value =
            quick_xml::escape::unescape(raw).map_err(|_| Error::bad("intel_invalid_rss"))?;
        match attr.key.as_ref() {
            b"href" => href = Some(value.into_owned()),
            b"rel" => alternate = value == "alternate",
            _ => {}
        }
    }
    Ok(if alternate { href } else { None })
}
pub(super) fn rss(data: &[u8], hosts: &[String]) -> Result<Vec<ArticleLink>> {
    if data.len() > 4 * 1024 * 1024 {
        return Err(Error::bad("intel_rss_too_large"));
    }
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(false);
    let mut active = false;
    let mut field = String::new();
    let mut title = String::new();
    let mut link = String::new();
    let mut content = String::new();
    let mut out = vec![];
    let mut depth = 0;
    loop {
        match reader
            .read_event()
            .map_err(|_| Error::bad("intel_invalid_rss"))?
        {
            Event::Start(e) => {
                depth += 1;
                if depth > 40 {
                    return Err(Error::bad("intel_invalid_rss"));
                }
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if name == "item" || name == "entry" {
                    active = true;
                    title.clear();
                    link.clear();
                    content.clear();
                }
                if active
                    && name == "link"
                    && let Some(href) = atom_link(&e)?
                {
                    link = href;
                }
                field = name;
            }
            Event::Empty(e) if active && e.local_name().as_ref() == b"link" => {
                if let Some(href) = atom_link(&e)? {
                    link = href;
                }
            }
            Event::Text(e) if active => {
                let s =
                    std::str::from_utf8(e.as_ref()).map_err(|_| Error::bad("intel_invalid_rss"))?;
                let decoded =
                    quick_xml::escape::unescape(s).map_err(|_| Error::bad("intel_invalid_rss"))?;
                match field.as_str() {
                    "title" => title.push_str(&decoded),
                    "link" => link.push_str(&decoded),
                    _ => content.push_str(&decoded),
                }
            }
            Event::CData(e) if active => {
                let s = String::from_utf8_lossy(e.as_ref());
                match field.as_str() {
                    "title" => title.push_str(&s),
                    "link" => link.push_str(&s),
                    _ => content.push_str(&s),
                }
            }
            Event::GeneralRef(e) if active => {
                let s = format!("&{};", String::from_utf8_lossy(e.as_ref()));
                let decoded =
                    quick_xml::escape::unescape(&s).map_err(|_| Error::bad("intel_invalid_rss"))?;
                match field.as_str() {
                    "title" => title.push_str(&decoded),
                    "link" => link.push_str(&decoded),
                    _ => content.push_str(&decoded),
                }
            }
            Event::End(e) => {
                depth -= 1;
                if active && matches!(e.local_name().as_ref(), b"item" | b"entry") {
                    if let Ok(url) = validate_url(link.trim(), hosts) {
                        let title = title.chars().take(500).collect::<String>();
                        let fingerprint = digest(format!("{title}\0{content}\0{url}").as_bytes());
                        out.push(ArticleLink {
                            url: url.to_string(),
                            title,
                            fingerprint,
                        });
                    }
                    active = false;
                }
                field.clear();
            }
            Event::DocType(_) => return Err(Error::bad("intel_rss_doctype_forbidden")),
            Event::Eof => break,
            _ => {}
        }
        if out.len() > 500 || title.len() + link.len() + content.len() > MAX_ARTICLE {
            return Err(Error::bad("intel_rss_too_large"));
        }
    }
    Ok(out)
}
#[cfg(test)]
pub(super) fn article_text(data: &[u8]) -> Result<String> {
    article_body::extract(data, None).map(|(body, _)| body)
}
pub(super) fn article_text_with_selector(data: &[u8], root: &str) -> Result<String> {
    let input = std::str::from_utf8(data).map_err(|_| Error::bad("intel_article_not_utf8"))?;
    let html = Html::parse_document(input);
    let selector = Selector::parse(root).expect("static selector");
    let node = html.select(&selector).next().ok_or_else(|| {
        Error::bad("intel_article_body_missing").context(json!({
            "selector":root,"html_bytes":data.len(),"reason":"selector_not_found"
        }))
    })?;
    let text = article_element_text(node)?;
    if text.len() < 40 {
        return Err(Error::bad("intel_article_body_missing").context(json!({
            "selector":root,"html_bytes":data.len(),"text_bytes":text.len(),"reason":"text_too_short"
        })));
    }
    Ok(text)
}

pub(super) fn article_element_text(node: scraper::ElementRef<'_>) -> Result<String> {
    let mut text = String::new();
    let mut previous_block = None;
    let mut previous_cell = None;
    for child in node.descendants() {
        if let scraper::node::Node::Text(t) = child.value() {
            if child.ancestors().any(|p| {
                p.value().as_element().is_some_and(|e| {
                    matches!(
                        e.name(),
                        "script"
                            | "style"
                            | "nav"
                            | "noscript"
                            | "header"
                            | "footer"
                            | "aside"
                            | "form"
                            | "button"
                            | "template"
                    ) || e.attr("hidden").is_some()
                        || e.attr("aria-hidden")
                            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
                        || matches!(
                            e.attr("role"),
                            Some("navigation" | "banner" | "contentinfo" | "complementary")
                        )
                        || e.classes().any(|class| {
                            matches!(
                                class,
                                "hidden"
                                    | "sr-only"
                                    | "visually-hidden"
                                    | "sidebar"
                                    | "related-posts"
                                    | "related-articles"
                                    | "post-related-articles"
                                    | "newsletter"
                                    | "social-share"
                                    | "share-buttons"
                                    | "comments"
                                    | "cookie-banner"
                            )
                        })
                        || e.attr("style").is_some_and(|style| {
                            let compact = style
                                .split_whitespace()
                                .collect::<String>()
                                .to_ascii_lowercase();
                            compact.contains("display:none")
                                || compact.contains("visibility:hidden")
                        })
                })
            }) {
                continue;
            }
            // Source indentation is HTML whitespace, not a document boundary.
            // Do not let whitespace between cells reset their row association.
            if t.trim().is_empty() {
                text.push(' ');
                continue;
            }
            let row = child.ancestors().find(|parent| {
                parent
                    .value()
                    .as_element()
                    .is_some_and(|e| e.name() == "tr")
            });
            let cell = child
                .ancestors()
                .find(|parent| {
                    parent
                        .value()
                        .as_element()
                        .is_some_and(|e| matches!(e.name(), "td" | "th"))
                })
                .map(|parent| parent.id());
            let block = row
                .or_else(|| {
                    child.ancestors().find(|parent| {
                        parent
                            .value()
                            .as_element()
                            .is_some_and(|e| article_block(e.name()))
                    })
                })
                .map(|parent| parent.id());
            if block != previous_block {
                text.push('\n');
            } else if cell.is_some() && previous_cell.is_some() && cell != previous_cell {
                text.push_str(" | ");
            }
            text.extend(
                t.chars()
                    .map(|ch| if ch.is_whitespace() { ' ' } else { ch }),
            );
            previous_block = block;
            previous_cell = cell;
        } else if child.value().as_element().is_some_and(|e| e.name() == "br") {
            text.push('\n');
        }
    }
    // Keep block boundaries for list/table evidence. Inline markup remains joined
    // inside a block, so defanged and ordinary indicators are not split apart.
    let text = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if text.len() > MAX_ARTICLE {
        return Err(Error::bad("intel_article_too_large"));
    }
    Ok(text)
}

fn article_block(name: &str) -> bool {
    matches!(
        name,
        "p" | "div"
            | "section"
            | "article"
            | "main"
            | "li"
            | "tr"
            | "td"
            | "th"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "pre"
            | "blockquote"
    )
}

#[cfg(test)]
pub(super) fn ai_result(content: &str, body: &str) -> Result<Vec<Indicator>> {
    ai_result_checked(content, body, false).map(|(entries, _)| entries)
}

pub(super) fn ai_result_isolated(
    content: &str,
    body: &str,
) -> Result<(Vec<Indicator>, ValidationReport)> {
    ai_result_checked(content, body, true)
}

fn ai_result_checked(
    content: &str,
    body: &str,
    isolate_evidence: bool,
) -> Result<(Vec<Indicator>, ValidationReport)> {
    let document = evidence::Document::new(body);
    let value: Value = serde_json::from_str(content).map_err(|error| {
        let format = ai_content_format(content);
        let mut values = serde_json::Deserializer::from_str(content).into_iter::<Value>();
        let trailing = matches!(values.next(), Some(Ok(_)))
            && !content[values.byte_offset()..].trim().is_empty();
        let reason = match format {
            "empty" => "empty_content",
            "markdown_fence" => "markdown_fence",
            "reasoning_prefix" => "reasoning_prefix",
            _ if trailing => "trailing_content",
            _ if error.is_eof() => "incomplete_json",
            "other_text" => "non_json_text",
            _ => "invalid_json_syntax",
        };
        Error::bad("intel_ai_invalid_json")
            .context(json_error_diagnostic(&error))
            .context(json!({
                "reason":reason,"content_bytes":content.len(),"content_format":format
            }))
    })?;
    if value
        .as_object()
        .is_none_or(|o| o.keys().any(|k| k != "iocs"))
    {
        return Err(Error::bad("intel_ai_invalid_schema"));
    }
    let items = value
        .get("iocs")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::bad("intel_ai_invalid_schema"))?;
    if items.len() > MAX_AI_IOCS {
        return Err(Error::bad("intel_ai_too_many_items"));
    }
    let mut validation = ValidationReport::default();
    let entries = items
        .iter()
        .enumerate()
        .filter_map(|(index, v)| {
            let result = (|| {
                let mut fields = v.clone();
                let object = fields
                    .as_object_mut()
                    .ok_or_else(|| Error::bad("intel_ai_invalid_schema"))?;
                // Ranges are server-owned; the model may only quote numbered blocks.
                if object.contains_key("evidence_spans") {
                    return Err(Error::bad("intel_ai_invalid_schema"));
                }
                let parts = object.remove("evidence_parts");
                let mut i: Indicator = serde_json::from_value(fields)
                    .map_err(|_| Error::bad("intel_ai_invalid_schema"))?;
                let raw = i.value.clone();
                i.normalize()?;
                document
                    .validate(&mut i, &raw, parts.as_ref())
                    .map_err(|error| error.context(json!({"record":index+1})))?;
                Ok(i)
            })();
            match result {
                Err(error) if isolate_evidence && error.code == "intel_ai_evidence_not_found" => {
                    validation.rejected += 1;
                    if validation.rejection_samples.len() < 100 {
                        // No AI response, IOC value, or report text in diagnostics.
                        validation.rejection_samples.push(error.diagnostic);
                    }
                    None
                }
                result => Some(result),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    if entries.is_empty() && validation.rejected > 0 {
        let first = validation
            .rejection_samples
            .first()
            .cloned()
            .unwrap_or_else(|| json!({}));
        return Err(Error::bad("intel_ai_evidence_not_found")
            .context(first)
            .context(json!({
                "rejected":validation.rejected,"validation":validation
            })));
    }
    Ok((entries, validation))
}

pub(super) fn ai_content_format(content: &str) -> &'static str {
    let content = content.trim();
    if content.is_empty() {
        "empty"
    } else if content.starts_with("```") || content.starts_with("~~~") {
        "markdown_fence"
    } else if content.starts_with("<think>") || content.starts_with("<analysis>") {
        "reasoning_prefix"
    } else if content.starts_with('{') {
        "json_object"
    } else if content.starts_with('[') {
        "json_array"
    } else {
        "other_text"
    }
}

pub(super) fn json_error_diagnostic(error: &serde_json::Error) -> Value {
    let category = match error.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    json!({"json_error_category":category,"json_line":error.line(),"json_column":error.column()})
}

pub(super) fn threatfox_document(
    data: &[u8],
    format: &str,
    isolate_invalid: bool,
) -> Result<(Vec<Indicator>, ValidationReport)> {
    if data.len() > MAX_BYTES {
        return Err(Error::bad("intel_source_too_large"));
    }
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    let v: Value = serde_json::from_slice(data).map_err(|_| Error::bad("intel_invalid_json"))?;
    if v.get("query_status").and_then(Value::as_str) == Some("no_result") {
        return Ok((vec![], ValidationReport::default()));
    }
    if v.get("query_status").is_some_and(|status| status != "ok") {
        return Err(Error::bad("intel_upstream_query_failed"));
    }
    let payload = v.get("data").unwrap_or(&v);
    let rows: Vec<(&Value, Option<&str>)> = match payload {
        Value::Array(rows) => rows.iter().map(|row| (row, None)).collect(),
        Value::Object(groups) if format == "threatfox_export" => groups
            .iter()
            .flat_map(|(id, rows)| {
                rows.as_array()
                    .into_iter()
                    .flatten()
                    .map(move |row| (row, Some(id.as_str())))
            })
            .collect(),
        _ => return Err(Error::bad("intel_invalid_threatfox")),
    };
    if rows.len() > MAX_ITEMS {
        return Err(Error::bad("intel_too_many_items"));
    }
    let mut report = ValidationReport::default();
    let mut items = Vec::new();
    for (index, (row, group)) in rows.into_iter().enumerate() {
        if let Some(item) =
            validated_threatfox_row(row, group, index as i64 + 1, &mut report, isolate_invalid)?
        {
            items.push(item);
        }
    }
    Ok((items, report))
}
pub(super) fn validated_threatfox_row(
    row: &Value,
    group: Option<&str>,
    record: i64,
    report: &mut ValidationReport,
    isolate_invalid: bool,
) -> Result<Option<Indicator>> {
    match threatfox_row(row, group) {
        Ok(item) => Ok(Some(item)),
        Err(error) if isolate_invalid && report.reject(row, group, record, &error) => Ok(None),
        Err(error) => Err(error),
    }
}
pub(super) fn threatfox_row(r: &Value, grouped_id: Option<&str>) -> Result<Indicator> {
    let mut i = Indicator::simple(
        match text(r, "ioc_type") {
            "md5_hash" => "md5",
            "sha1_hash" => "sha1",
            "sha256_hash" => "sha256",
            other => other,
        },
        r.get("ioc")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .or_else(|| r.get("ioc_value").and_then(Value::as_str))
            .unwrap_or(""),
    );
    i.external_id = r
        .get("id")
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| v.to_string())
        })
        .or_else(|| grouped_id.map(str::to_owned))
        .unwrap_or_default();
    i.malware = text(r, "malware_printable").to_owned();
    if i.malware.is_empty() {
        i.malware = text(r, "malware_alias").to_owned();
    }
    if i.malware.is_empty() {
        i.malware = text(r, "malware").to_owned();
    }
    i.reference = r
        .get("reference")
        .and_then(Value::as_str)
        .filter(|v| {
            !v.trim().is_empty()
                && !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "none" | "null" | "n/a"
                )
        })
        .map(str::to_owned);
    i.confidence = r
        .get("confidence_level")
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok());
    i.first_seen = r
        .get("first_seen")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            r.get("first_seen_utc")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })
        .map(str::to_owned);
    i.last_seen = r
        .get("last_seen")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            r.get("last_seen_utc")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })
        .map(str::to_owned);
    i.evidence=serde_json::to_string(&json!({"threat_type":r.get("threat_type"),"reporter":r.get("reporter"),"malware_id":r.get("malware"),"tags":r.get("tags"),"is_compromised":r.get("is_compromised")})).unwrap_or_default();
    i.normalize()?;
    Ok(i)
}
