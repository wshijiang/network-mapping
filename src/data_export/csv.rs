//! 导出 CSV 写入：UTF-8 BOM + CRLF，单元格转义与前端 `csvCell` 规则一致
//! （公式注入防护：`= + - @` 或制表符/换行开头前置单引号；引号翻倍）。

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::elasticsearch::ElasticsearchSearchItem;

use super::fields::{FieldDef, FormatCtx};

pub(crate) fn escape_cell(value: &str) -> String {
    let trimmed = value.trim_start();
    let guarded =
        if trimmed.starts_with(['=', '+', '-', '@']) || value.starts_with(['\t', '\r', '\n']) {
            format!("'{value}")
        } else {
            value.to_owned()
        };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

/// 流式 CSV 写入器：边写边累计 sha256 与字节数，避免大文件二次读取。
pub(crate) struct CsvWriter {
    file: tokio::fs::File,
    hasher: Sha256,
    pub bytes_written: i64,
}

impl CsvWriter {
    pub async fn create(
        path: &std::path::Path,
        fields: &[&FieldDef],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let file = tokio::fs::File::create(path).await?;
        let mut writer = Self {
            file,
            hasher: Sha256::new(),
            bytes_written: 0,
        };
        let header = fields
            .iter()
            .map(|field| escape_cell(field.label))
            .collect::<Vec<_>>()
            .join(",");
        writer.write_raw(&format!("\u{feff}{header}\r\n")).await?;
        Ok(writer)
    }

    async fn write_raw(
        &mut self,
        text: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bytes = text.as_bytes();
        self.file.write_all(bytes).await?;
        self.hasher.update(bytes);
        self.bytes_written += bytes.len() as i64;
        Ok(())
    }

    pub async fn write_row(
        &mut self,
        item: &ElasticsearchSearchItem,
        fields: &[&FieldDef],
        ctx: &FormatCtx,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let row = fields
            .iter()
            .map(|field| escape_cell(&(field.extract)(item, ctx)))
            .collect::<Vec<_>>()
            .join(",");
        self.write_raw(&format!("{row}\r\n")).await
    }

    pub async fn finish(
        mut self,
    ) -> Result<(i64, String), Box<dyn std::error::Error + Send + Sync>> {
        self.file.flush().await?;
        self.file.sync_all().await?;
        let sha256: String = self
            .hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok((self.bytes_written, sha256))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_commas_and_newlines() {
        assert_eq!(escape_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(escape_cell("a,b"), "\"a,b\"");
        assert_eq!(escape_cell("a\nb"), "\"a\nb\"");
        assert_eq!(escape_cell(""), "\"\"");
    }

    #[test]
    fn guards_formula_injection_like_frontend() {
        assert_eq!(escape_cell("=cmd|'/C calc'!A0"), "\"'=cmd|'/C calc'!A0\"");
        assert_eq!(escape_cell("+1"), "\"'+1\"");
        assert_eq!(escape_cell("-1"), "\"'-1\"");
        assert_eq!(escape_cell("@SUM(A1)"), "\"'@SUM(A1)\"");
        assert_eq!(escape_cell("  =x"), "\"'  =x\"");
        assert_eq!(escape_cell("\tx"), "\"'\tx\"");
        // 普通负数语义不受影响之外的正常值不加前缀。
        assert_eq!(escape_cell("nginx"), "\"nginx\"");
    }

    #[tokio::test]
    async fn writes_bom_header_rows_and_hashes() {
        let dir = std::env::temp_dir().join(format!("nm-export-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("t.csv");
        let fields = super::super::fields::resolve_keys(&["ip".into(), "port".into()]).unwrap();
        let ctx = FormatCtx::new("Asia/Shanghai");
        let mut writer = CsvWriter::create(&path, &fields).await.unwrap();
        let item = ElasticsearchSearchItem::test_stub("192.0.2.1", 443);
        writer.write_row(&item, &fields, &ctx).await.unwrap();
        let (size, sha256) = writer.finish().await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(content.starts_with("\u{feff}\"IP\",\"端口\"\r\n"));
        assert!(content.ends_with("\"192.0.2.1\",\"443\"\r\n"));
        assert_eq!(size as usize, content.len());
        assert_eq!(sha256.len(), 64);
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }
}
