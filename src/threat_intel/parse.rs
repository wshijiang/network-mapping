//! Deterministic parsing only. Finding a name in a file path never attributes an IOC.
use super::*;
use quick_xml::{Reader, events::Event};
use scraper::{Html, Selector};

pub(super) fn indicators(data: &[u8], format: &str) -> Result<Vec<Indicator>> {
    if data.len() > MAX_BYTES {
        return Err(Error::bad("intel_source_too_large"));
    }
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
        let v: Value =
            serde_json::from_slice(data).map_err(|_| Error::bad("intel_invalid_json"))?;
        if v.get("query_status").and_then(Value::as_str) == Some("no_result") {
            return Ok(vec![]);
        }
        if v.get("query_status").is_some_and(|s| s != "ok") {
            return Err(Error::bad("intel_upstream_query_failed"));
        }
        let payload = v.get("data").unwrap_or(&v);
        let rows: Vec<(&Value, Option<&str>)> = match payload {
            Value::Array(v) => v.iter().map(|r| (r, None)).collect(),
            Value::Object(v) if format == "threatfox_export" => v
                .iter()
                .flat_map(|(id, rows)| {
                    rows.as_array()
                        .into_iter()
                        .flatten()
                        .map(move |r| (r, Some(id.as_str())))
                })
                .collect(),
            _ => return Err(Error::bad("intel_invalid_threatfox")),
        };
        if rows.len() > MAX_ITEMS {
            return Err(Error::bad("intel_too_many_items"));
        }
        return rows.into_iter().map(|(r, grouped_id)| {
            let mut i=Indicator::simple(text(r,"ioc_type"),text(r,"ioc"));
            i.external_id=r.get("id").map(|v|v.as_str().map(str::to_owned).unwrap_or_else(||v.to_string())).or_else(||grouped_id.map(str::to_owned)).unwrap_or_default();
            i.malware=text(r,"malware_printable").to_owned();
            if i.malware.is_empty(){i.malware=text(r,"malware").to_owned();}
            i.reference=r.get("reference").and_then(Value::as_str).filter(|v|!v.is_empty()).map(str::to_owned);
            i.confidence=r.get("confidence_level").and_then(Value::as_i64).and_then(|v|i32::try_from(v).ok());
            i.first_seen=r.get("first_seen").or_else(||r.get("first_seen_utc")).and_then(Value::as_str).map(str::to_owned);
            i.last_seen=r.get("last_seen").or_else(||r.get("last_seen_utc")).and_then(Value::as_str).map(str::to_owned);
            i.valid_until=i.first_seen.as_deref().and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(s).ok().map(|v|v.with_timezone(&chrono::Utc))
                    .or_else(||chrono::NaiveDateTime::parse_from_str(s,"%Y-%m-%d %H:%M:%S UTC").ok().map(|v|v.and_utc()))
                    .or_else(||chrono::NaiveDateTime::parse_from_str(s,"%Y-%m-%d %H:%M:%S").ok().map(|v|v.and_utc()))
            }).and_then(|v|v.checked_add_months(chrono::Months::new(6)));
            i.evidence=serde_json::to_string(&json!({"threat_type":r.get("threat_type"),"reporter":r.get("reporter"),"malware_id":r.get("malware"),"tags":r.get("tags")})).unwrap_or_default();
            i.normalize()?;Ok(i)
        }).collect();
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
    let events: Vec<&Value> = match document.get("response") {
        Some(Value::Array(events)) => events.iter().collect(),
        Some(event) => vec![event],
        None => vec![document],
    };
    let mut out = vec![];
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
        for a in attributes.into_iter().flatten().chain(object_attributes) {
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
            i.normalize()?;
            out.push(i);
            if out.len() > MAX_ITEMS {
                return Err(Error::bad("intel_too_many_items"));
            }
        }
    }
    if out.is_empty() {
        return Err(Error::bad("intel_no_supported_indicators"));
    }
    Ok(out)
}
fn guess(value: &str) -> Option<Indicator> {
    if value.contains(char::is_whitespace) {
        return None;
    }
    let kind = if value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("hxxp://")
        || value.starts_with("hxxps://")
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
    let mut rows = vec![];
    let mut row = vec![];
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = input.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut cell)),
            '\n' if !quoted => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
                if rows.len() > MAX_ITEMS + 1 {
                    return Err(Error::bad("intel_too_many_items"));
                }
            }
            '\r' if !quoted => {}
            _ => cell.push(c),
        }
    }
    if quoted {
        return Err(Error::bad("intel_invalid_csv"));
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
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
                field = name;
            }
            Event::Empty(e) if active && e.local_name().as_ref() == b"link" => {
                let mut href = None;
                let mut alternate = true;
                for a in e.attributes() {
                    let a = a.map_err(|_| Error::bad("intel_invalid_rss"))?;
                    let v = String::from_utf8_lossy(&a.value).into_owned();
                    if a.key.as_ref() == b"href" {
                        href = Some(v.clone());
                    }
                    if a.key.as_ref() == b"rel" {
                        alternate = v == "alternate";
                    }
                }
                if alternate && let Some(href) = href {
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
pub(super) fn article_text(data: &[u8]) -> Result<String> {
    let input = std::str::from_utf8(data).map_err(|_| Error::bad("intel_article_not_utf8"))?;
    let html = Html::parse_document(input);
    let selector = Selector::parse("article, main").expect("static selector");
    let node = html
        .select(&selector)
        .next()
        .ok_or_else(|| Error::bad("intel_article_body_missing"))?;
    // Exclude scripts, styles, navigation, and hidden elements from evidence.
    let mut text = String::new();
    for child in node.descendants() {
        if let scraper::node::Node::Text(t) = child.value() {
            if child.ancestors().any(|p| {
                p.value().as_element().is_some_and(|e| {
                    matches!(e.name(), "script" | "style" | "nav" | "noscript")
                        || e.attr("hidden").is_some()
                        || e.attr("aria-hidden") == Some("true")
                })
            }) {
                continue;
            }
            text.push_str(t);
            text.push('\n');
            if text.len() > MAX_ARTICLE {
                return Err(Error::bad("intel_article_too_large"));
            }
        }
    }
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.len() < 40 {
        return Err(Error::bad("intel_article_body_missing"));
    }
    Ok(text)
}

pub(super) fn ai_result(content: &str, body: &str) -> Result<Vec<Indicator>> {
    let value: Value =
        serde_json::from_str(content).map_err(|_| Error::bad("intel_ai_invalid_json"))?;
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
    if items.len() > 200 {
        return Err(Error::bad("intel_ai_too_many_items"));
    }
    items
        .iter()
        .map(|v| {
            let mut i: Indicator = serde_json::from_value(v.clone())
                .map_err(|_| Error::bad("intel_ai_invalid_schema"))?;
            let raw = i.value.clone();
            i.normalize()?;
            let evidence = i.evidence.split_whitespace().collect::<Vec<_>>().join(" ");
            let normalized_evidence = evidence
                .replace("[.]", ".")
                .replace("hxxps://", "https://")
                .replace("hxxp://", "http://");
            if evidence.len() < 12
                || !body.contains(&evidence)
                || !(normalized_evidence.contains(&raw)
                    || normalized_evidence.contains(&i.value)
                    || normalized_evidence.to_ascii_lowercase().contains(&i.value))
            {
                return Err(Error::bad("intel_ai_evidence_not_found"));
            }
            i.evidence = evidence;
            Ok(i)
        })
        .collect()
}
