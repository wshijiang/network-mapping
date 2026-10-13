//! Standalone process-replacement experiment. No production server integration.
//! Build twice: rustc --edition=2024 [--cfg enhanced] prototype.rs -o /tmp/worker-vN
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::Duration;

const RPC_VERSION: &str = "1";
const BUILD: &str = if cfg!(enhanced) { "v2" } else { "v1" };
const LIMIT: u64 = 1024;
const TIMEOUT: Duration = Duration::from_secs(3);

fn error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn read_line(reader: &mut impl Read) -> io::Result<String> {
    let mut bytes = Vec::new();
    for _ in 0..=LIMIT {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            return String::from_utf8(bytes).map_err(|_| error("invalid UTF-8 frame"));
        }
        bytes.push(byte[0]);
    }
    Err(error("oversized frame"))
}

fn worker() -> io::Result<()> {
    println!("READY {RPC_VERSION} {BUILD}");
    io::stdout().flush()?;
    // Serial worker is intentional: this prototype validates version lifetimes.
    // The parent exclusively owns both pipes; stdout is reserved for protocol frames.
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let command = match read_line(&mut input) {
            Ok(command) => command,
            Err(_) => return Ok(()),
        };
        println!("{}", execute(&command));
        io::stdout().flush()?;
    }
}

fn execute(command: &str) -> String {
    let parts: Vec<_> = command.split_whitespace().collect();
    match parts.as_slice() {
        ["HEALTH"] => format!("OK {RPC_VERSION} {BUILD}"),
        ["REPORT", delay, count] => {
            let parsed = delay.parse::<u64>().ok().zip(count.parse::<u64>().ok());
            let Some((delay, count)) =
                parsed.filter(|(delay, count)| *delay <= 1000 && *count <= 1_000_000)
            else {
                return "ERROR invalid_input".to_owned();
            };
            thread::sleep(Duration::from_millis(delay));
            // The second executable contains different compiled business behavior.
            let score = if cfg!(enhanced) { count * 10 } else { count };
            format!("RESULT {BUILD} {score}")
        }
        _ => "ERROR unknown_command".to_owned(),
    }
}

struct RpcRequest {
    command: String,
    reply: mpsc::SyncSender<io::Result<String>>,
}

struct Worker {
    child: Mutex<Child>,
    requests: Option<mpsc::SyncSender<RpcRequest>>,
    broker: Option<thread::JoinHandle<()>>,
    healthy: AtomicBool,
    build: String,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.requests.take();
        let child = self
            .child
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = child.kill();
        let _ = child.wait();
        if let Some(broker) = self.broker.take() {
            let _ = broker.join();
        }
        eprintln!("STOP {}", self.build);
    }
}

impl Worker {
    fn start(path: &PathBuf, expected_build: &str) -> io::Result<Arc<Self>> {
        let mut child = Command::new(path)
            .arg("worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut output = child.stdout.take().ok_or_else(|| error("missing stdout"))?;
        let mut input = child.stdin.take().ok_or_else(|| error("missing stdin"))?;
        let mut candidate = Self {
            child: Mutex::new(child),
            requests: None,
            broker: None,
            healthy: AtomicBool::new(true),
            build: expected_build.to_owned(),
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let startup_reader = thread::spawn(move || {
            let ready = read_line(&mut output);
            let _ = tx.send((ready, output));
        });
        let ready = rx.recv_timeout(TIMEOUT);
        if ready.is_err() {
            candidate.stop();
        }
        // The supplied demo workers do not fork or inherit stdout to subprocesses.
        let _ = startup_reader.join();
        let (ready, mut output) = ready.map_err(|_| error("readiness timeout"))?;
        let ready = ready?;
        let parts: Vec<_> = ready.split_whitespace().collect();
        let ["READY", protocol, build] = parts.as_slice() else {
            return Err(error("invalid readiness frame"));
        };
        if *protocol != RPC_VERSION || *build != expected_build {
            return Err(error("protocol or build mismatch"));
        }
        let (requests, pending) = mpsc::sync_channel::<RpcRequest>(32);
        candidate.requests = Some(requests);
        candidate.broker = Some(thread::spawn(move || {
            for request in pending {
                let result = writeln!(input, "{}", request.command)
                    .and_then(|()| input.flush())
                    .and_then(|()| read_line(&mut output));
                let failed = result.is_err();
                let _ = request.reply.send(result);
                if failed {
                    break;
                }
            }
        }));
        if candidate.rpc("HEALTH".to_owned())? != format!("OK {RPC_VERSION} {build}") {
            return Err(error("health probe failed"));
        }
        let expected_score = if *build == "v2" { 20 } else { 2 };
        if candidate.rpc("REPORT 0 2".to_owned())? != format!("RESULT {build} {expected_score}") {
            return Err(error("self test failed"));
        }
        Ok(Arc::new(candidate))
    }

    fn stop(&self) {
        self.healthy.store(false, Ordering::Release);
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }

    fn rpc(&self, command: String) -> io::Result<String> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(error("worker unhealthy"));
        }
        let (reply, rx) = mpsc::sync_channel(1);
        self.requests
            .as_ref()
            .ok_or_else(|| error("worker not ready"))?
            .try_send(RpcRequest { command, reply })
            .map_err(|_| error("worker queue unavailable"))?;
        match rx.recv_timeout(TIMEOUT) {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => {
                self.stop();
                Err(e)
            }
            Err(_) => {
                self.stop();
                Err(error("worker RPC timeout or disconnection"))
            }
        }
    }

    fn report(&self, delay: u64, count: u64) -> io::Result<String> {
        let response = self.rpc(format!("REPORT {delay} {count}"))?;
        let parts: Vec<_> = response.split_whitespace().collect();
        match parts.as_slice() {
            ["RESULT", build, score] if *build == self.build && score.parse::<u64>().is_ok() => {
                Ok(response)
            }
            _ => Err(error("invalid worker response")),
        }
    }
}

#[derive(Default)]
struct Route {
    revision: u64,
    active: Option<Arc<Worker>>,
}

struct Host {
    allowed: BTreeSet<PathBuf>,
    route: Mutex<Route>,
}

impl Host {
    fn activate(&self, expected: u64, path: &str, build: &str) -> io::Result<u64> {
        let path = std::fs::canonicalize(path)?;
        if !self.allowed.contains(&path) {
            return Err(error("artifact is not in the startup allowlist"));
        }
        {
            let route = self.route.lock().map_err(|_| error("route poisoned"))?;
            if route.revision != expected {
                return Err(error("revision conflict"));
            }
        }
        // All child startup and RPC work happens outside the route lock.
        let candidate = Worker::start(&path, build)?;
        let mut route = self.route.lock().map_err(|_| error("route poisoned"))?;
        if route.revision != expected {
            return Err(error("revision conflict after prepare"));
        }
        let revision = route
            .revision
            .checked_add(1)
            .ok_or_else(|| error("revision exhausted"))?;
        let previous = route.active.replace(candidate);
        route.revision = revision;
        drop(route);
        // Old requests still own an Arc. Last owner triggers child cleanup.
        drop(previous);
        Ok(revision)
    }

    fn acquire(&self) -> io::Result<(u64, Arc<Worker>)> {
        let route = self.route.lock().map_err(|_| error("route poisoned"))?;
        let worker = route
            .active
            .clone()
            .ok_or_else(|| error("no active worker"))?;
        Ok((route.revision, worker))
    }
}

fn host(paths: &[String]) -> io::Result<()> {
    let allowed = paths
        .iter()
        .map(std::fs::canonicalize)
        .collect::<io::Result<_>>()?;
    let host = Host {
        allowed,
        route: Mutex::new(Route::default()),
    };
    let mut calls: Vec<thread::JoinHandle<()>> = Vec::new();
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        // Bounded input, with one CLI command per line; paths must have no spaces.
        let line = match read_line(&mut input) {
            Ok(line) => line,
            Err(e) => {
                eprintln!("input closed: {e}");
                break;
            }
        };
        calls = calls
            .into_iter()
            .filter_map(|call| {
                if call.is_finished() {
                    let _ = call.join();
                    None
                } else {
                    Some(call)
                }
            })
            .collect();
        let parts: Vec<_> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["ACTIVATE", expected, path, build] => {
                let result = expected
                    .parse()
                    .map_err(|_| error("invalid revision"))
                    .and_then(|expected| host.activate(expected, path, build));
                match result {
                    Ok(revision) => println!("ACTIVE {revision} {build}"),
                    Err(e) => println!("REJECTED {e}"),
                }
            }
            ["CALL", id, delay, count] => {
                let parsed = id
                    .parse::<u64>()
                    .ok()
                    .zip(delay.parse::<u64>().ok())
                    .zip(count.parse::<u64>().ok());
                let Some(((id, delay), count)) =
                    parsed.filter(|((_, delay), count)| *delay <= 1000 && *count <= 1_000_000)
                else {
                    println!("REJECTED invalid call");
                    continue;
                };
                if calls.len() >= 32 {
                    println!("REJECTED too many calls");
                    continue;
                }
                match host.acquire() {
                    Ok((revision, worker)) => {
                        // Acquire before spawning: activation cannot move this call to v2.
                        println!("PINNED {id} {revision} {}", worker.build);
                        calls.push(thread::spawn(move || match worker.report(delay, count) {
                            Ok(result) => println!("DONE {id} {revision} {result}"),
                            Err(e) => println!("FAILED {id} {revision} {e}"),
                        }));
                    }
                    Err(e) => println!("REJECTED {e}"),
                }
            }
            ["QUIT"] => break,
            _ => println!("REJECTED unknown command"),
        }
        io::stdout().flush()?;
    }
    for call in calls {
        let _ = call.join();
    }
    // Host drops after calls join, so active and retired children are reaped.
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("worker") => worker(),
        Some("host") if args.len() > 1 => host(&args[1..]),
        _ => Err(error("usage: prototype worker | host ALLOWED_ARTIFACT...")),
    }
}
