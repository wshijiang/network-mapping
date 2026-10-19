//! Stream offline JSON/CSV/ZIP into a private normalized spool, never extract paths.
use super::*;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ROW: usize = 1024 * 1024;

struct RowLimit<R> {
    inner: R,
    budget: std::sync::Arc<AtomicUsize>,
    total: u64,
}
impl<R: Read> Read for RowLimit<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let limit = buf.len().min(self.budget.load(Ordering::Relaxed));
        if limit == 0 || self.total >= MAX_EXPANDED {
            return Err(std::io::Error::other("offline input limit"));
        }
        let n = self.inner.read(&mut buf[..limit])?;
        self.budget.fetch_sub(n, Ordering::Relaxed);
        self.total += n as u64;
        Ok(n)
    }
}
pub(super) fn convert(mut raw: std::fs::File, output: std::fs::File) -> Result<(i64, u64)> {
    let mut magic = [0; 4];
    let n = raw
        .read(&mut magic)
        .map_err(|_| Error::bad("intel_import_read_failed"))?;
    raw.seek(SeekFrom::Start(0))
        .map_err(|_| Error::bad("intel_import_read_failed"))?;
    let mut writer = BufWriter::new(output);
    let result = if n == 4 && magic == *b"PK\x03\x04" {
        let mut archive = zip::ZipArchive::new(raw).map_err(|_| Error::bad("intel_invalid_zip"))?;
        if archive.len() != 1 {
            return Err(Error::bad("intel_zip_single_file_required"));
        }
        let entry = archive
            .by_index(0)
            .map_err(|_| Error::bad("intel_invalid_zip"))?;
        if entry.is_dir() || entry.size() > MAX_EXPANDED {
            return Err(Error::bad("intel_import_too_large"));
        }
        convert_reader(entry, &mut writer)
    } else {
        convert_reader(raw, &mut writer)
    }?;
    writer
        .flush()
        .map_err(|_| Error::bad("intel_import_write_failed"))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|_| Error::bad("intel_import_write_failed"))?;
    Ok(result)
}
fn convert_reader<R: Read, W: Write>(reader: R, writer: &mut W) -> Result<(i64, u64)> {
    let budget = std::sync::Arc::new(AtomicUsize::new(MAX_ROW));
    let mut reader = BufReader::new(RowLimit {
        inner: BufReader::new(reader),
        budget: budget.clone(),
        total: 0,
    });
    // Strip UTF-8 BOM before format detection.
    if reader
        .fill_buf()
        .map_err(|_| Error::bad("intel_import_read_failed"))?
        .starts_with(&[0xef, 0xbb, 0xbf])
    {
        reader.consume(3);
    }
    loop {
        let buf = reader
            .fill_buf()
            .map_err(|_| Error::bad("intel_import_read_failed"))?;
        if buf.is_empty() {
            return Err(Error::bad("intel_no_supported_indicators"));
        }
        let n = buf.iter().take_while(|b| b.is_ascii_whitespace()).count();
        if n == 0 {
            break;
        }
        reader.consume(n);
    }
    let json = matches!(
        reader
            .fill_buf()
            .map_err(|_| Error::bad("intel_import_read_failed"))?[0],
        b'{' | b'['
    );
    let mut count = 0_i64;
    let mut bytes = 0_u64;
    let mut emit = |mut i: Indicator| -> Result<()> {
        i.normalize()?;
        let encoded = serde_json::to_vec(&i).map_err(|_| Error::bad("intel_invalid_indicator"))?;
        bytes += encoded.len() as u64 + 1;
        count += 1;
        if encoded.len() + 1 > MAX_ROW || bytes > MAX_EXPANDED || count > 10_000_000 {
            return Err(Error::bad("intel_import_too_large"));
        }
        writer
            .write_all(&encoded)
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|_| Error::bad("intel_import_write_failed"))?;
        Ok(())
    };
    if json {
        let mut rows = |v: Value, group: Option<&str>| -> Result<()> {
            let i = if v.get("ioc_type").is_some() {
                parse::threatfox_row(&v, group)?
            } else {
                serde_json::from_value(v).map_err(|_| Error::bad("intel_invalid_indicator"))?
            };
            emit(i)
        };
        let mut deserializer = serde_json::Deserializer::from_reader(reader);
        Root {
            emit: &mut rows,
            budget: &budget,
            group: None,
        }
        .deserialize(&mut deserializer)
        .map_err(|_| Error::bad("intel_invalid_ioc_document"))?;
        budget.store(MAX_ROW, Ordering::Relaxed);
        deserializer
            .end()
            .map_err(|_| Error::bad("intel_invalid_ioc_document"))?;
    } else {
        csv_rows(reader, &budget, &mut emit)?;
    }
    Ok((count, bytes))
}
type Emit<'a> = &'a mut dyn FnMut(Value, Option<&str>) -> Result<()>;
struct Root<'a, 'b> {
    emit: Emit<'a>,
    budget: &'b AtomicUsize,
    group: Option<String>,
}
impl<'de> DeserializeSeed<'de> for Root<'_, '_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Root<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("IOC array or grouped export")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        loop {
            self.budget.store(MAX_ROW, Ordering::Relaxed);
            let Some(v) = seq.next_element::<Value>()? else {
                break;
            };
            (self.emit)(v, self.group.as_deref()).map_err(|_| de::Error::custom("invalid IOC"))?;
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut recognized = false;
        loop {
            self.budget.store(MAX_ROW, Ordering::Relaxed);
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            if matches!(key.as_str(), "data" | "iocs") || key.parse::<u64>().is_ok() {
                recognized = true;
                map.next_value_seed(Root {
                    emit: self.emit,
                    budget: self.budget,
                    group: if key.parse::<u64>().is_ok() {
                        Some(key)
                    } else {
                        None
                    },
                })?;
            } else if key == "query_status" {
                let status = map.next_value::<String>()?;
                if !matches!(status.as_str(), "ok" | "no_result") {
                    return Err(de::Error::custom("upstream status"));
                }
                if status == "no_result" {
                    recognized = true;
                }
            } else {
                map.next_value::<de::IgnoredAny>()?;
            }
        }
        if !recognized {
            return Err(de::Error::custom("unsupported document"));
        }
        Ok(())
    }
}
fn csv_rows<R: Read>(
    reader: R,
    budget: &AtomicUsize,
    emit: &mut dyn FnMut(Indicator) -> Result<()>,
) -> Result<()> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(reader);
    let mut header: Option<Vec<String>> = None;
    let mut row = csv::StringRecord::new();
    loop {
        budget.store(MAX_ROW, Ordering::Relaxed);
        if !csv
            .read_record(&mut row)
            .map_err(|_| Error::bad("intel_invalid_csv"))?
        {
            break;
        }
        if row.len() > 128 {
            return Err(Error::bad("intel_invalid_csv"));
        }
        let fields = row
            .iter()
            .map(|s| {
                s.trim()
                    .trim_start_matches('#')
                    .trim()
                    .trim_matches('"')
                    .to_ascii_lowercase()
            })
            .collect::<Vec<_>>();
        if header.is_none() {
            if fields
                .iter()
                .any(|s| matches!(s.as_str(), "ioc" | "ioc_value" | "value"))
            {
                header = Some(fields);
            }
            continue;
        }
        if row
            .get(0)
            .is_some_and(|v| v.trim().is_empty() || v.trim_start().starts_with('#'))
        {
            continue;
        }
        let header = header.as_ref().unwrap();
        if row.len() != header.len() {
            return Err(Error::bad("intel_invalid_csv"));
        }
        let mut object = serde_json::Map::new();
        for (key, value) in header.iter().zip(row.iter()) {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let key = match key.as_str() {
                "ioc_id" => "id",
                "ioc_value" => "ioc",
                other => other,
            };
            let parsed = if matches!(key, "confidence" | "confidence_level") {
                json!(
                    value
                        .parse::<i32>()
                        .map_err(|_| Error::bad("intel_invalid_confidence"))?
                )
            } else {
                json!(value)
            };
            object.insert(key.into(), parsed);
        }
        let native = object.contains_key("ioc_type");
        let indicator = if native {
            parse::threatfox_row(&Value::Object(object), None)?
        } else {
            if let Some(v) = object.remove("ioc") {
                object.insert("value".into(), v);
            }
            if let Some(v) = object.remove("id") {
                object.insert("external_id".into(), v);
            }
            serde_json::from_value(Value::Object(object))
                .map_err(|_| Error::bad("intel_invalid_indicator"))?
        };
        emit(indicator)?;
    }
    if header.is_none() {
        return Err(Error::bad("intel_invalid_csv"));
    }
    Ok(())
}
