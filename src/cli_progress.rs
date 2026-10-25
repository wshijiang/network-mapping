use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const REPORT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressUpdate {
    pub phase: String,
    pub completed: Option<u64>,
    pub total: Option<u64>,
    pub unit: Option<String>,
    pub detail: Option<String>,
}

impl ProgressUpdate {
    pub fn phase(phase: impl Into<String>) -> Self {
        Self {
            phase: phase.into(),
            completed: None,
            total: None,
            unit: None,
            detail: None,
        }
    }

    pub fn count(
        phase: impl Into<String>,
        completed: u64,
        total: Option<u64>,
        unit: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let detail = detail.into();
        Self {
            phase: phase.into(),
            completed: Some(completed),
            total,
            unit: Some(unit.into()),
            detail: (!detail.is_empty()).then_some(detail),
        }
    }
}

pub trait ProgressReporter: Send + Sync {
    fn is_enabled(&self) -> bool {
        true
    }

    fn report(&self, update: ProgressUpdate);
}

#[derive(Debug, Default)]
pub struct NoopProgressReporter;

impl ProgressReporter for NoopProgressReporter {
    fn is_enabled(&self) -> bool {
        false
    }

    fn report(&self, _update: ProgressUpdate) {}
}

enum ProgressCommand {
    Update,
    Finish(String),
    Fail(String),
    Stop,
}

pub struct CliProgressReporter {
    sender: SyncSender<ProgressCommand>,
    latest: Arc<Mutex<Option<ProgressUpdate>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl CliProgressReporter {
    pub fn new(task: impl Into<String>) -> Self {
        let task = task.into();
        let (sender, receiver) = mpsc::sync_channel(1);
        let latest: Arc<Mutex<Option<ProgressUpdate>>> = Arc::new(Mutex::new(None));
        let worker_latest = latest.clone();
        let worker = thread::spawn(move || {
            let started_at = Instant::now();
            let mut current: Option<ProgressUpdate> = None;
            let mut rate = ProgressRate::default();
            let mut next_report_at = Instant::now() + REPORT_INTERVAL;

            loop {
                let wait = next_report_at.saturating_duration_since(Instant::now());
                match receiver.recv_timeout(wait) {
                    Ok(ProgressCommand::Update) => {
                        let Some(update) =
                            worker_latest.lock().expect("progress slot poisoned").take()
                        else {
                            continue;
                        };
                        rate.observe(&update, started_at.elapsed());
                        let phase_changed = current
                            .as_ref()
                            .is_none_or(|previous| previous.phase != update.phase);
                        current = Some(update);
                        if phase_changed || Instant::now() >= next_report_at {
                            if let Some(update) = current.as_ref() {
                                eprintln!(
                                    "{}",
                                    format_live_update(&task, update, started_at.elapsed(), &rate)
                                );
                            }
                            next_report_at = Instant::now() + REPORT_INTERVAL;
                        }
                    }
                    Ok(ProgressCommand::Finish(summary)) => {
                        eprintln!(
                            "[{task}] 完成：{summary}，总耗时 {}",
                            format_duration(started_at.elapsed())
                        );
                        break;
                    }
                    Ok(ProgressCommand::Fail(reason)) => {
                        let context = current
                            .as_ref()
                            .map(|update| {
                                format_live_update(&task, update, started_at.elapsed(), &rate)
                            })
                            .unwrap_or_else(|| format!("[{task}] 尚未开始"));
                        eprintln!("{context}");
                        eprintln!(
                            "[{task}] 失败：{reason}，总耗时 {}",
                            format_duration(started_at.elapsed())
                        );
                        break;
                    }
                    Ok(ProgressCommand::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        if let Some(update) = current.as_ref() {
                            eprintln!(
                                "{}",
                                format_live_update(&task, update, started_at.elapsed(), &rate)
                            );
                        }
                        next_report_at = Instant::now() + REPORT_INTERVAL;
                    }
                }
            }
        });
        Self {
            sender,
            latest,
            worker: Mutex::new(Some(worker)),
            closed: AtomicBool::new(false),
        }
    }

    pub fn finish(&self, summary: impl Into<String>) {
        self.close(ProgressCommand::Finish(summary.into()));
    }

    pub fn fail(&self, reason: impl Into<String>) {
        self.close(ProgressCommand::Fail(reason.into()));
    }

    fn close(&self, command: ProgressCommand) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.sender.send(command);
        if let Some(worker) = self
            .worker
            .lock()
            .expect("progress worker lock poisoned")
            .take()
        {
            let _ = worker.join();
        }
    }
}

impl ProgressReporter for CliProgressReporter {
    fn report(&self, update: ProgressUpdate) {
        if !self.closed.load(Ordering::Acquire) {
            *self.latest.lock().expect("progress slot poisoned") = Some(update);
            let _ = self.sender.try_send(ProgressCommand::Update);
        }
    }
}

impl Drop for CliProgressReporter {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = self.sender.send(ProgressCommand::Stop);
        }
        if let Some(worker) = self
            .worker
            .get_mut()
            .expect("progress worker lock poisoned")
            .take()
        {
            let _ = worker.join();
        }
    }
}

#[derive(Default)]
struct ProgressRate {
    phase: String,
    samples: VecDeque<(Duration, u64)>,
    changed_at: Duration,
}
impl ProgressRate {
    fn observe(&mut self, update: &ProgressUpdate, now: Duration) {
        let Some(count) = update.completed else {
            self.samples.clear();
            self.phase = update.phase.clone();
            return;
        };
        if self.phase != update.phase || self.samples.back().is_some_and(|(_, n)| count < *n) {
            self.samples.clear();
            self.phase = update.phase.clone();
        }
        if self.samples.back().is_none_or(|(_, n)| *n != count) {
            self.changed_at = now;
        }
        self.samples.push_back((now, count));
        while self.samples.len() > 2
            && self
                .samples
                .get(1)
                .is_some_and(|(t, _)| now.saturating_sub(*t) > Duration::from_secs(30))
        {
            self.samples.pop_front();
        }
        // Bound memory even when callers report thousands of pages per second.
        if self.samples.len() > 256 {
            self.samples.remove(1);
        }
    }
    fn rate(&self, now: Duration) -> Option<f64> {
        if now.saturating_sub(self.changed_at) > REPORT_INTERVAL {
            return None;
        }
        let (start, first) = self.samples.front()?;
        let (_, last) = self.samples.back()?;
        let elapsed = now.saturating_sub(*start).as_secs_f64();
        (elapsed >= 1.0 && last > first).then(|| (last - first) as f64 / elapsed)
    }
}

fn format_live_update(
    task: &str,
    update: &ProgressUpdate,
    elapsed: Duration,
    rate: &ProgressRate,
) -> String {
    let speed = rate.rate(elapsed);
    let mut text = render_update(task, update, elapsed, speed);
    if let (Some(rate), Some(done), Some(total)) = (speed, update.completed, update.total)
        && rate > 0.0
    {
        text.push_str(&format!(
            "，阶段剩余约 {}",
            format_duration(Duration::from_secs_f64(
                (total.saturating_sub(done) as f64 / rate).min(315360000.0)
            ))
        ));
    }
    text
}

#[cfg(test)]
fn format_update(task: &str, update: &ProgressUpdate, elapsed: Duration) -> String {
    render_update(
        task,
        update,
        elapsed,
        Some(if elapsed.is_zero() {
            0.0
        } else {
            update.completed.unwrap_or(0) as f64 / elapsed.as_secs_f64()
        }),
    )
}

fn render_update(
    task: &str,
    update: &ProgressUpdate,
    elapsed: Duration,
    rate: Option<f64>,
) -> String {
    let elapsed_text = format_duration(elapsed);
    let detail = update
        .detail
        .as_deref()
        .map(|value| format!("，{value}"))
        .unwrap_or_default();
    match (update.completed, update.total) {
        (Some(completed), Some(total)) => {
            let percentage = if total == 0 {
                100.0
            } else {
                completed as f64 * 100.0 / total as f64
            };
            let unit = update.unit.as_deref().unwrap_or("项");
            let speed = match rate {
                Some(rate) => format!("速度 {rate:.1} {unit}/秒"),
                None => "速度待采样或等待当前请求".into(),
            };
            format!(
                "[{task}] {}：{completed}/{total} {unit} ({percentage:.1}%)，耗时 {elapsed_text}，{speed}{detail}",
                update.phase
            )
        }
        (Some(completed), None) => {
            let unit = update.unit.as_deref().unwrap_or("项");
            format!(
                "[{task}] {}：已完成 {completed} {unit}，耗时 {elapsed_text}{detail}",
                update.phase
            )
        }
        _ => format!("[{task}] {}，已运行 {elapsed_text}{detail}", update.phase),
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CliProgressReporter, NoopProgressReporter, ProgressReporter, ProgressUpdate,
        format_duration, format_update,
    };
    use std::time::Duration;

    #[test]
    fn formats_determinate_progress_with_rate_and_detail() {
        let output = format_update(
            "扫描数据迁移",
            &ProgressUpdate::count("迁移扫描批次", 25, Some(100), "批次", "观察 900/3000 条"),
            Duration::from_secs(10),
        );

        assert_eq!(
            output,
            "[扫描数据迁移] 迁移扫描批次：25/100 批次 (25.0%)，耗时 00:00:10，速度 2.5 批次/秒，观察 900/3000 条"
        );
    }

    #[test]
    fn formats_indeterminate_phase_as_heartbeat() {
        let output = format_update(
            "搜索投影重建",
            &ProgressUpdate::phase("正在执行 PostgreSQL 投影 SQL"),
            Duration::from_secs(65),
        );

        assert_eq!(
            output,
            "[搜索投影重建] 正在执行 PostgreSQL 投影 SQL，已运行 00:01:05"
        );
    }

    #[test]
    fn zero_total_is_complete_without_division_by_zero() {
        let output = format_update(
            "任务",
            &ProgressUpdate::count("处理", 0, Some(0), "项", ""),
            Duration::ZERO,
        );

        assert!(output.contains("0/0 项 (100.0%)"));
        assert!(output.contains("速度 0.0 项/秒"));
    }

    #[test]
    fn formats_long_duration() {
        assert_eq!(format_duration(Duration::from_secs(3661)), "01:01:01");
    }

    #[test]
    fn noop_reporter_disables_optional_progress_queries() {
        assert!(!NoopProgressReporter.is_enabled());
    }

    #[test]
    fn cli_reporter_flushes_updates_before_finishing() {
        let reporter = CliProgressReporter::new("测试任务");
        reporter.report(ProgressUpdate::count(
            "处理",
            1,
            Some(1),
            "项",
            "最后成功 id=1",
        ));
        reporter.finish("1 项");
    }
}

#[cfg(test)]
mod rate_tests {
    use super::*;
    #[test]
    fn resumed_history_and_phase_changes_do_not_inflate_rate() {
        let mut rate = ProgressRate::default();
        rate.observe(
            &ProgressUpdate::count("replay", 50000, Some(60000), "items", ""),
            Duration::ZERO,
        );
        assert_eq!(rate.rate(Duration::from_secs(1)), None);
        rate.observe(
            &ProgressUpdate::count("replay", 50020, Some(60000), "items", ""),
            Duration::from_secs(2),
        );
        assert_eq!(rate.rate(Duration::from_secs(2)), Some(10.0));
        assert_eq!(rate.rate(Duration::from_secs(8)), None);
        rate.observe(
            &ProgressUpdate::count("tags", 2000, Some(3000), "items", ""),
            Duration::from_secs(9),
        );
        assert_eq!(rate.rate(Duration::from_secs(10)), None);
        for n in 2001..10000 {
            rate.observe(
                &ProgressUpdate::count("tags", n, None, "items", ""),
                Duration::from_secs(10),
            );
        }
        assert!(rate.samples.len() <= 256);
    }
}
