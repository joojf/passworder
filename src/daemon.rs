use crate::vault::{UnlockedVault, VaultError};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

const PROTOCOL_VERSION: u32 = 1;
const APP_DIR: &str = "passworder";
const SOCKET_FILE: &str = "agent.sock";
const LOCK_FILE: &str = "agent.lock";
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const TEST_IDLE_TIMEOUT_ENV: &str = "PASSWORDER_TEST_IDLE_TIMEOUT_SECS";
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const POLL_INTERVAL_MS: libc::c_int = 1000;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Status,
    Lock,
    Unlock,
}

/// Base64 has no JSON escapes, so the parser can borrow the password from the wiped request
/// buffer. Decoding an escaped string would leave a copy in the parser's own allocation.
#[derive(Deserialize)]
struct Request<'a> {
    v: u32,
    op: Op,
    #[serde(borrow)]
    password_base64: Option<&'a str>,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    v: u32,
    op: Op,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_base64: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Locked,
    Unlocked,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Locked => "locked",
            State::Unlocked => "unlocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AuthFailed,
    VaultMissing,
    BadRequest,
    UnsupportedVersion,
    Internal,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    State(State),
    Error(ErrorCode),
}

/// Sends one request on its own connection. A connection left open during a prompt would stall
/// the daemon, which serves one client at a time.
pub fn send(op: Op, password: Option<&SecretString>) -> io::Result<Response> {
    let encoded = password.map(|p| Zeroizing::new(BASE64.encode(p.expose_secret())));
    let mut line = Zeroizing::new(serde_json::to_vec(&WireRequest {
        v: PROTOCOL_VERSION,
        op,
        password_base64: encoded.as_ref().map(|e| e.as_str()),
    })?);
    line.push(b'\n');

    let mut stream = UnixStream::connect(socket_dir()?.join(SOCKET_FILE))?;
    stream.write_all(&line)?;

    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(serde_json::from_str(&reply)?)
}

pub fn serve(vault_path: PathBuf) -> io::Result<()> {
    harden_process()?;

    let dir = create_socket_dir()?;
    let _instance_lock = lock_single_instance(&dir)?;

    let socket = dir.join(SOCKET_FILE);
    match fs::remove_file(&socket) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let listener = UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;
    eprintln!("Listening on {}", socket.display());

    let mut daemon = Daemon {
        vault_path,
        idle_timeout: idle_timeout(),
        unlocked: None,
    };
    loop {
        daemon.lock_if_idle();
        if !wait_for_client(&listener)? {
            continue;
        }
        // A client can disconnect between poll and accept, which must not stop the daemon.
        if let Ok((stream, _)) = listener.accept() {
            let _ = daemon.serve_client(stream);
        }
    }
}

/// Core dumps and debuggers could otherwise read the key from this process's memory.
fn harden_process() -> io::Result<()> {
    let no_core_dumps = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core_dumps) } != 0 {
        return Err(io::Error::last_os_error());
    }

    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn runtime_dir() -> io::Result<PathBuf> {
    let dir = PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR")
            .ok_or_else(|| io::Error::other("XDG_RUNTIME_DIR is not set"))?,
    );
    if !dir.is_absolute() {
        return Err(io::Error::other("XDG_RUNTIME_DIR is not an absolute path"));
    }
    ensure_private_dir(&dir)?;
    Ok(dir)
}

fn socket_dir() -> io::Result<PathBuf> {
    let dir = runtime_dir()?.join(APP_DIR);
    ensure_private_dir(&dir)?;
    Ok(dir)
}

fn create_socket_dir() -> io::Result<PathBuf> {
    let dir = runtime_dir()?.join(APP_DIR);
    match DirBuilder::new().mode(0o700).create(&dir) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error),
        _ => {}
    }
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Directory permissions are what keep other users away from the socket.
fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(dir)?;
    let owner = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{} must be a directory only your user can access",
            dir.display()
        )));
    }
    Ok(())
}

fn lock_single_instance(dir: &Path) -> io::Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(LOCK_FILE))?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(io::Error::other("the daemon is already running")),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

fn idle_timeout() -> Duration {
    // Debug builds only, because this changes how long the key stays in memory.
    if cfg!(debug_assertions)
        && let Some(seconds) = std::env::var_os(TEST_IDLE_TIMEOUT_ENV)
    {
        let seconds = seconds.to_str().and_then(|s| s.parse().ok());
        return Duration::from_secs(seconds.expect("test idle timeout in seconds"));
    }
    IDLE_TIMEOUT
}

/// Returns false when the interval passed with no client, so the caller can check the timeout.
fn wait_for_client(listener: &UnixListener) -> io::Result<bool> {
    let mut poll_fd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll_fd, 1, POLL_INTERVAL_MS) } >= 0 {
        return Ok(poll_fd.revents != 0);
    }
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::Interrupted => Ok(false),
        _ => Err(error),
    }
}

/// The wall clock counts time asleep, which the monotonic clock misses. The monotonic clock
/// ignores the wall clock being set back. Locking on whichever passes first covers both.
struct LockDeadline {
    wall_clock: SystemTime,
    monotonic: Instant,
}

impl LockDeadline {
    fn after(timeout: Duration) -> Self {
        Self {
            wall_clock: SystemTime::now() + timeout,
            monotonic: Instant::now() + timeout,
        }
    }

    fn has_passed(&self) -> bool {
        SystemTime::now() >= self.wall_clock || Instant::now() >= self.monotonic
    }
}

struct Unlocked {
    /// Dropping this wipes the key. Nothing reads it until a later operation uses secrets.
    _vault: UnlockedVault,
    locks_at: LockDeadline,
}

struct Daemon {
    vault_path: PathBuf,
    idle_timeout: Duration,
    unlocked: Option<Unlocked>,
}

impl Daemon {
    fn lock_if_idle(&mut self) {
        if self
            .unlocked
            .as_ref()
            .is_some_and(|u| u.locks_at.has_passed())
        {
            self.unlocked = None;
            eprintln!("Locked after the idle timeout");
        }
    }

    fn state(&self) -> Response {
        Response::State(if self.unlocked.is_some() {
            State::Unlocked
        } else {
            State::Locked
        })
    }

    fn serve_client(&mut self, mut stream: UnixStream) -> io::Result<()> {
        // Some platforms make accepted sockets inherit the listener's non-blocking mode.
        stream.set_nonblocking(false)?;

        let line = read_line(&mut stream);
        let request = line
            .as_ref()
            .and_then(|line| serde_json::from_slice(line).ok());
        // Reading can take up to the request deadline.
        self.lock_if_idle();
        let response = match request {
            Some(request) => self.handle(request),
            None => Response::Error(ErrorCode::BadRequest),
        };

        stream.write_all(&serde_json::to_vec(&response)?)
    }

    fn handle(&mut self, request: Request) -> Response {
        if request.v != PROTOCOL_VERSION {
            return Response::Error(ErrorCode::UnsupportedVersion);
        }
        match (request.op, request.password_base64) {
            (Op::Status, None) => self.state(),
            (Op::Lock, None) => {
                self.unlocked = None;
                self.state()
            }
            (Op::Unlock, Some(encoded)) => match decode_password(encoded) {
                Some(password) => self.unlock(&password),
                None => Response::Error(ErrorCode::BadRequest),
            },
            _ => Response::Error(ErrorCode::BadRequest),
        }
    }

    fn unlock(&mut self, password: &SecretString) -> Response {
        // Already unlocked: skip Argon2 and leave the deadline alone.
        if self.unlocked.is_some() {
            return self.state();
        }
        match UnlockedVault::open(&self.vault_path, password) {
            Ok(vault) => {
                self.unlocked = Some(Unlocked {
                    _vault: vault,
                    locks_at: LockDeadline::after(self.idle_timeout),
                });
                self.state()
            }
            Err(VaultError::AuthFailed) => Response::Error(ErrorCode::AuthFailed),
            Err(VaultError::NotInitialized) => Response::Error(ErrorCode::VaultMissing),
            Err(error) => {
                eprintln!("Error: unlock failed: {error}");
                Response::Error(ErrorCode::Internal)
            }
        }
    }
}

fn decode_password(encoded: &str) -> Option<SecretString> {
    let bytes = Zeroizing::new(BASE64.decode(encoded).ok()?);
    Some(SecretString::from(std::str::from_utf8(&bytes).ok()?))
}

/// Reads into one wiped buffer that never grows, because growing would leave copies of the
/// password behind. Socket timeouts limit each read, so a trickling client needs a deadline.
fn read_line(stream: &mut UnixStream) -> Option<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buffer = Zeroizing::new(vec![0u8; MAX_REQUEST_BYTES]);
    let mut filled = 0;

    while filled < MAX_REQUEST_BYTES {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(remaining)).ok()?;

        let count = stream.read(&mut buffer[filled..]).ok()?;
        if count == 0 {
            return None;
        }
        let received = &buffer[filled..filled + count];
        if let Some(newline) = received.iter().position(|byte| *byte == b'\n') {
            buffer.truncate(filled + newline);
            return Some(buffer);
        }
        filled += count;
    }
    None
}
