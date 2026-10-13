use plotters::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const WIDTH: u32 = 1280;
pub const HEIGHT: u32 = 600;
pub const RENDERER_VERSION: i32 = 1;
pub const MAX_PNG_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrendDay {
    pub day: String,
    pub succeeded: i64,
    pub failed: i64,
    pub partial: i64,
    pub cancelled: i64,
}

pub fn render_trend_png(items: &[TrendDay]) -> Result<Vec<u8>, String> {
    if items.is_empty() || items.len() > 31 {
        return Err("趋势日期数量必须在 1 至 31 之间".into());
    }
    let mut maximum = 0_i64;
    let mut last = None;
    for item in items {
        let day = chrono::NaiveDate::parse_from_str(&item.day, "%Y-%m-%d")
            .map_err(|_| "趋势日期格式无效")?;
        if last.is_some_and(|previous| day != previous + chrono::Duration::days(1)) {
            return Err("趋势日期必须连续递增".into());
        }
        last = Some(day);
        let total = [item.succeeded, item.failed, item.partial, item.cancelled]
            .into_iter()
            .try_fold(0_i64, |sum, n| {
                if n < 0 {
                    return Err("趋势计数不能为负数");
                }
                sum.checked_add(n).ok_or("趋势计数溢出")
            })?;
        maximum = maximum.max(total);
    }
    static FONTS: OnceLock<Result<(), String>> = OnceLock::new();
    FONTS
        .get_or_init(|| {
            plotters::style::register_font(
                "report-chinese",
                FontStyle::Normal,
                include_bytes!("../../assets/fonts/ReportChinese.ttf"),
            )
            .map_err(|_| "报告中文字体加载失败".to_owned())?;
            plotters::style::register_font(
                "report-latin",
                FontStyle::Normal,
                include_bytes!("../../assets/fonts/ReportLatin.ttf"),
            )
            .map_err(|_| "报告数字字体加载失败".to_owned())
        })
        .clone()?;
    let mut rgb = vec![255_u8; (WIDTH * HEIGHT * 3) as usize];
    {
        let root = BitMapBackend::with_buffer(&mut rgb, (WIDTH, HEIGHT)).into_drawing_area();
        let error = |e| format!("趋势图片绘制失败：{e}");
        root.fill(&WHITE).map_err(error)?;
        root.draw(&Text::new(
            "每日完成任务",
            (48, 38),
            ("report-chinese", 30)
                .into_font()
                .color(&RGBColor(38, 50, 56)),
        ))
        .map_err(error)?;
        let left = 110;
        let right = 1232;
        let top = 90;
        let bottom = 470;
        let step = (maximum as f64 / 4.0).ceil().max(1.0);
        let ymax = step * 4.0;
        for i in 0..=4 {
            let y = bottom - (bottom - top) * i / 4;
            root.draw(&PathElement::new(
                vec![(left, y), (right, y)],
                RGBColor(229, 231, 235),
            ))
            .map_err(error)?;
            root.draw(&Text::new(
                format!("{:.0}", step * i as f64),
                (24, y + 8),
                ("report-latin", 20)
                    .into_font()
                    .color(&RGBColor(71, 85, 105)),
            ))
            .map_err(error)?;
        }
        let colors = [
            RGBColor(34, 197, 94),
            RGBColor(239, 68, 68),
            RGBColor(245, 158, 11),
            RGBColor(148, 163, 184),
        ];
        let slot = (right - left) as f64 / items.len() as f64;
        for (i, item) in items.iter().enumerate() {
            let x0 = left + (slot * (i as f64 + 0.18)) as i32;
            let x1 = left + (slot * (i as f64 + 0.82)) as i32;
            let mut sum = 0.0;
            for (n, color) in [item.succeeded, item.failed, item.partial, item.cancelled]
                .into_iter()
                .zip(colors)
            {
                let y0 = bottom - (sum / ymax * (bottom - top) as f64).round() as i32;
                sum += n as f64;
                let y1 = bottom - (sum / ymax * (bottom - top) as f64).round() as i32;
                if n > 0 {
                    root.draw(&Rectangle::new([(x0, y1), (x1, y0)], color.filled()))
                        .map_err(error)?;
                }
            }
            let interval = if items.len() > 14 { 4 } else { 1 };
            if i % interval == 0 || i == items.len() - 1 {
                let x = left + (slot * (i as f64 + 0.5)) as i32 - 27;
                root.draw(&Text::new(
                    item.day[5..].to_owned(),
                    (x, bottom + 35),
                    ("report-latin", 18)
                        .into_font()
                        .color(&RGBColor(71, 85, 105)),
                ))
                .map_err(error)?;
            }
        }
        if maximum == 0 {
            root.draw(&Text::new(
                "本期无完成任务",
                (490, 265),
                ("report-chinese", 26)
                    .into_font()
                    .color(&RGBColor(100, 116, 139)),
            ))
            .map_err(error)?;
        }
        for (i, (name, color)) in ["成功", "失败", "部分完成", "取消"]
            .into_iter()
            .zip(colors)
            .enumerate()
        {
            let x = 300 + i as i32 * 180;
            root.draw(&Rectangle::new([(x, 545), (x + 22, 567)], color.filled()))
                .map_err(error)?;
            root.draw(&Text::new(
                name,
                (x + 34, 565),
                ("report-chinese", 22)
                    .into_font()
                    .color(&RGBColor(38, 50, 56)),
            ))
            .map_err(error)?;
        }
        root.present().map_err(error)?;
    }
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, WIDTH, HEIGHT);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
        writer.write_image_data(&rgb).map_err(|e| e.to_string())?;
        writer.finish().map_err(|e| e.to_string())?;
    }
    if bytes.len() > MAX_PNG_BYTES {
        return Err("趋势图片超过 1 MiB".into());
    }
    Ok(bytes)
}

/// The permit lives inside the blocking closure even if its async caller times out.
pub async fn render_async(items: Vec<TrendDay>) -> Result<Vec<u8>, String> {
    render_async_checked(items).await.map_err(|e| e.to_string())
}

pub(crate) async fn render_async_checked(
    items: Vec<TrendDay>,
) -> Result<Vec<u8>, crate::module_runtime::ModuleError> {
    run_render_job(move || render_trend_png(&items)).await
}

async fn run_render_job<F>(render: F) -> Result<Vec<u8>, crate::module_runtime::ModuleError>
where
    F: FnOnce() -> Result<Vec<u8>, String> + Send + 'static,
{
    use crate::module_runtime::ModuleError;
    static RENDER_LOCK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let permit = RENDER_LOCK
        .acquire()
        .await
        .map_err(|e| ModuleError::Unavailable(e.to_string()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        render()
    })
    .await
    .map_err(|e| ModuleError::Unavailable(e.to_string()))?
    .map_err(ModuleError::Execution)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn failed_chart_task_is_retryable_and_releases_the_render_permit() {
        let error = run_render_job(|| panic!("simulated chart task failure"))
            .await
            .unwrap_err();
        assert!(error.is_retryable());
        let recovered = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_render_job(|| Ok(vec![1, 2, 3])),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recovered, [1, 2, 3]);
    }

    #[tokio::test]
    async fn invalid_chart_input_remains_a_permanent_content_error() {
        let error = render_async_checked(Vec::new()).await.unwrap_err();
        assert!(!error.is_retryable());
    }
    #[test]
    fn renders_month_and_empty_week_as_valid_png() {
        for days in [7, 28, 29, 30, 31] {
            let items: Vec<_> = (1..=days)
                .map(|day| TrendDay {
                    day: format!("2026-01-{day:02}"),
                    succeeded: if days == 7 { 0 } else { day },
                    failed: 2,
                    partial: 1,
                    cancelled: 0,
                })
                .collect();
            let bytes = render_trend_png(&items).unwrap();
            let reader = png::Decoder::new(std::io::Cursor::new(bytes))
                .read_info()
                .unwrap();
            assert_eq!((reader.info().width, reader.info().height), (WIDTH, HEIGHT));
        }
        let zeros = vec![
            TrendDay {
                day: "2026-01-01".into(),
                succeeded: 0,
                failed: 0,
                partial: 0,
                cancelled: 0
            };
            1
        ];
        assert!(render_trend_png(&zeros).is_ok());
    }
    #[test]
    fn rejects_invalid_or_unbounded_trends() {
        assert!(render_trend_png(&[]).is_err());
        let mut item = TrendDay {
            day: "bad".into(),
            succeeded: 0,
            failed: 0,
            partial: 0,
            cancelled: 0,
        };
        assert!(render_trend_png(&[item.clone()]).is_err());
        item.day = "2026-01-01".into();
        item.failed = -1;
        assert!(render_trend_png(&[item]).is_err());
    }
}
