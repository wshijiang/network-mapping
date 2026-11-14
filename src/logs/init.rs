use crate::logs::{ConsoleTime, LogRollingMode, LogTime};
use std::{io::IsTerminal, path::Path};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init(
    log_directory: impl AsRef<Path>,
    log_file_name: impl AsRef<Path>,
    log_file_rolling: &LogRollingMode,
    log_debug_mode: &bool,
    terminal_verbose: bool,
) -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = log_file_rolling.build(log_directory, log_file_name);
    let (nb, guard) = tracing_appender::non_blocking(file_appender);

    let default_level = if *log_debug_mode { "debug" } else { "info" };
    let file_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let console_filter = if terminal_verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level))
    } else {
        EnvFilter::new("warn,server::startup=info")
    };

    let console_layer = fmt::layer()
        .compact()
        .with_writer(std::io::stdout)
        .with_timer(ConsoleTime)
        .with_ansi(std::io::stdout().is_terminal())
        .with_target(*log_debug_mode)
        .with_line_number(*log_debug_mode)
        .with_file(*log_debug_mode)
        .with_filter(console_filter);

    let json_layer = fmt::layer()
        .json()
        .with_writer(nb)
        .with_timer(LogTime)
        .with_current_span(true)
        // A request currently has a single `http_request` span. Emitting both the
        // current span and its span list duplicates the same request_id in every
        // JSON event without adding call-path information.
        .with_span_list(false)
        .with_target(*log_debug_mode)
        // .with_ansi(false)
        // .with_env_filter("info") //支持RUST_LOG
        .with_line_number(*log_debug_mode)
        .with_file(*log_debug_mode)
        .with_filter(file_filter);

    tracing_subscriber::registry()
        .with(console_layer)
        .with(json_layer)
        .with(crate::syslog::forwarder::SyslogLayer)
        .init();

    guard // 返回guard 以确
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::{Layer, layer::SubscriberExt};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter(self.0.clone())
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_events_emit_only_the_current_request_span() {
        let output = Buffer::default();
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(output.clone())
            .with_current_span(true)
            .with_span_list(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
        let subscriber = tracing_subscriber::registry().with(layer);
        let request_id = "02a6ef14-9adf-4117-bddd-2984ace255fe";
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http_request", request_id);
            let _guard = span.enter();
            tracing::info!(event = "TestError", error_code = "test", "test event");
        });

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|value| {
                value.pointer("/fields/event").and_then(|v| v.as_str()) == Some("TestError")
            })
            .unwrap();
        assert_eq!(
            event
                .pointer("/span/request_id")
                .and_then(|value| value.as_str()),
            Some(request_id)
        );
        assert!(event.get("spans").is_none());
        assert!(event.pointer("/fields/request_id").is_none());
    }
}
