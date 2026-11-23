use chrono::{DateTime, Datelike, Days, Months, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

pub const TIMEZONE: &str = crate::system_time::DEFAULT_TIMEZONE;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeriodType {
    Daily,
    Weekly,
    Monthly,
}

impl PeriodType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Daily => "日报",
            Self::Weekly => "周报",
            Self::Monthly => "月报",
        }
    }
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            _ => Err("周期必须为 daily、weekly 或 monthly".into()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Period {
    pub timezone: String,
    pub settings_revision: i64,
    pub kind: PeriodType,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

pub fn local_date(value: DateTime<Utc>) -> Result<NaiveDate, String> {
    Ok(value
        .with_timezone(&crate::system_time::timezone())
        .date_naive())
}

pub fn local_time(date: NaiveDate, hour: u32, minute: u32) -> Result<DateTime<Utc>, String> {
    crate::system_time::scheduled_time(
        crate::system_time::timezone(),
        date.and_hms_opt(hour, minute, 0).ok_or("无效发送时间")?,
    )
}

impl Period {
    pub fn containing(kind: PeriodType, date: NaiveDate) -> Result<Self, String> {
        let settings = crate::system_time::snapshot();
        Self::containing_in(kind, date, &settings.document.timezone, settings.revision)
    }
    pub fn containing_in(
        kind: PeriodType,
        date: NaiveDate,
        timezone: &str,
        settings_revision: i64,
    ) -> Result<Self, String> {
        let tz = timezone
            .parse::<chrono_tz::Tz>()
            .map_err(|_| "无效报告时区")?;
        let start = match kind {
            PeriodType::Daily => Some(date),
            PeriodType::Weekly => {
                date.checked_sub_days(Days::new(u64::from(date.weekday().num_days_from_monday())))
            }
            PeriodType::Monthly => NaiveDate::from_ymd_opt(date.year(), date.month(), 1),
        }
        .ok_or("日期超出支持范围")?;
        let end = match kind {
            PeriodType::Daily => start.checked_add_days(Days::new(1)),
            PeriodType::Weekly => start.checked_add_days(Days::new(7)),
            PeriodType::Monthly => start.checked_add_months(Months::new(1)),
        }
        .ok_or("日期超出支持范围")?;
        Ok(Self {
            kind,
            timezone: timezone.to_owned(),
            settings_revision,
            start: crate::system_time::scheduled_time(
                tz,
                start.and_hms_opt(0, 0, 0).ok_or("无效日期")?,
            )?,
            end: crate::system_time::scheduled_time(
                tz,
                end.and_hms_opt(0, 0, 0).ok_or("无效日期")?,
            )?,
        })
    }
    pub fn date(&self, instant: DateTime<Utc>) -> Result<NaiveDate, String> {
        let tz = self
            .timezone
            .parse::<chrono_tz::Tz>()
            .map_err(|_| "无效报告时区")?;
        Ok(instant.with_timezone(&tz).date_naive())
    }
    pub fn days(&self) -> Result<i64, String> {
        Ok((self.date(self.end)? - self.date(self.start)?).num_days())
    }
    pub fn previous(&self) -> Result<Self, String> {
        let day = self
            .date(self.start)?
            .checked_sub_days(Days::new(1))
            .ok_or("日期超出支持范围")?;
        Self::containing_in(self.kind, day, &self.timezone, self.settings_revision)
    }
    pub fn last_closed(kind: PeriodType, now: DateTime<Utc>) -> Result<Self, String> {
        let settings = crate::system_time::snapshot();
        let tz = settings
            .document
            .timezone
            .parse::<chrono_tz::Tz>()
            .map_err(|_| "无效报告时区")?;
        Self::containing_in(
            kind,
            now.with_timezone(&tz).date_naive(),
            &settings.document.timezone,
            settings.revision,
        )?
        .previous()
    }
    pub fn validate_closed(&self, now: DateTime<Utc>) -> Result<(), String> {
        if self.end > now {
            return Err("只能生成已结束的完整周期".into());
        }
        if self.start < now - chrono::Duration::days(366) {
            return Err("仅支持最近一年内的报告".into());
        }
        Ok(())
    }
    pub fn due_at(&self, hour: u32, minute: u32) -> Result<DateTime<Utc>, String> {
        let tz = self
            .timezone
            .parse::<chrono_tz::Tz>()
            .map_err(|_| "无效报告时区")?;
        crate::system_time::scheduled_time(
            tz,
            self.date(self.end)?
                .and_hms_opt(hour, minute, 0)
                .ok_or("无效发送时间")?,
        )
    }
}

pub fn growth(current: f64, previous: f64) -> Option<f64> {
    (previous > 0.0).then(|| ((current - previous) / previous * 1000.0).round() / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("test date")
    }
    #[test]
    fn weekly_crosses_calendar_year_at_shanghai_midnight() {
        let p = Period::containing(PeriodType::Weekly, date("2026-01-01")).expect("period");
        assert_eq!(p.start.to_rfc3339(), "2025-12-28T16:00:00+00:00");
        assert_eq!(p.end.to_rfc3339(), "2026-01-04T16:00:00+00:00");
    }
    #[test]
    fn monthly_respects_leap_february_and_previous_year() {
        let p = Period::containing(PeriodType::Monthly, date("2024-02-15")).expect("period");
        assert_eq!((p.end - p.start).num_days(), 29);
        let january = Period::containing(PeriodType::Monthly, date("2026-01-15")).expect("period");
        assert_eq!(
            local_date(january.previous().expect("previous").start).expect("date"),
            date("2025-12-01")
        );
    }
    #[test]
    fn schedule_uses_local_send_time_and_closed_period() {
        let now = DateTime::parse_from_rfc3339("2026-09-28T09:00:00+08:00")
            .expect("now")
            .with_timezone(&Utc);
        let p = Period::last_closed(PeriodType::Weekly, now).expect("period");
        assert_eq!(p.due_at(9, 0).expect("due"), now);
        assert!(p.validate_closed(now).is_ok());
        assert!(
            Period::containing(PeriodType::Weekly, date("2026-09-28"))
                .expect("current")
                .validate_closed(now)
                .is_err()
        );
    }
    #[test]
    fn new_york_calendar_week_is_seven_days_across_dst() {
        let p = Period::containing_in(
            PeriodType::Weekly,
            date("2026-03-08"),
            "America/New_York",
            7,
        )
        .expect("period");
        assert_eq!(p.days().expect("days"), 7);
        assert_eq!((p.end - p.start).num_hours(), 167);
        assert_eq!(p.timezone, "America/New_York");
        assert_eq!(p.previous().expect("previous").timezone, p.timezone);
        assert_eq!(p.settings_revision, 7);
    }
    #[test]
    fn china_calendar_boundaries_do_not_change_with_season() {
        for day in ["2026-01-15", "2026-07-15"] {
            let p = Period::containing_in(PeriodType::Weekly, date(day), "Asia/Shanghai", 1)
                .expect("period");
            assert_eq!((p.end - p.start).num_hours(), 168);
            assert_eq!(
                p.due_at(9, 0).expect("due").format("%H:%M").to_string(),
                "01:00"
            );
        }
    }
    #[test]
    fn daily_period_is_one_local_day_and_previous_crosses_month() {
        let p = Period::containing_in(PeriodType::Daily, date("2026-03-08"), "America/New_York", 3)
            .expect("period");
        // DST 起始日只有 23 小时，仍是一个完整本地日。
        assert_eq!(p.days().expect("days"), 1);
        assert_eq!((p.end - p.start).num_hours(), 23);
        let prev = p.previous().expect("previous");
        assert_eq!(local_date(prev.start).expect("date"), date("2026-03-07"));
        let month = Period::containing(PeriodType::Daily, date("2026-01-01")).expect("period");
        assert_eq!(
            local_date(month.previous().expect("previous").start).expect("date"),
            date("2025-12-31")
        );
        assert_eq!(
            PeriodType::parse("daily").expect("parse"),
            PeriodType::Daily
        );
        assert_eq!(PeriodType::Daily.label(), "日报");
    }
    #[test]
    fn zero_baseline_is_not_an_infinite_growth_rate() {
        assert_eq!(growth(10.0, 0.0), None);
        assert_eq!(growth(110.0, 100.0), Some(10.0));
    }
}
