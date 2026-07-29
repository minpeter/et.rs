//! File logging, mirroring upstream `LogHandler` behaviour that the `--logdir`,
//! `--logtostdout`, `--silent`, and `--verbose` flags control.
//!
//! Log files are named exactly like upstream:
//! `<prefix>-<YYYY-MM-DD_HH-MM-SS>.<micros>[_<pid>].log`, created inside
//! `logdir` (which is created if missing), and rolled over (deleted and
//! restarted) once they exceed the configured maximum size.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Upstream default max log size for `etserver` (20 MiB).
pub const DEFAULT_MAX_LOG_SIZE: u64 = 20_971_520;

#[derive(Debug, Clone)]
pub struct LogOptions {
    /// Directory that receives log files.
    pub directory: PathBuf,
    /// File-name prefix (`etserver`, `etclient-<user>-<id>`, ...).
    pub prefix: String,
    /// Also mirror every line to stdout.
    pub to_stdout: bool,
    /// Disable logging entirely.
    pub silent: bool,
    /// Append `_<pid>` to the file name (upstream does this for `etserver`).
    pub append_pid: bool,
    /// Verbosity: `VLOG(n)` lines are kept when `n <= verbose`.
    pub verbose: u8,
    pub max_size: u64,
}

impl Default for LogOptions {
    fn default() -> Self {
        Self {
            directory: std::env::temp_dir(),
            prefix: "et".to_owned(),
            to_stdout: false,
            silent: true,
            append_pid: false,
            verbose: 0,
            max_size: DEFAULT_MAX_LOG_SIZE,
        }
    }
}

struct Logger {
    options: LogOptions,
    path: Option<PathBuf>,
    file: Option<fs::File>,
    written: u64,
}

static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

/// Initialise process-wide logging. Safe to call once per process; later calls
/// are ignored so role dispatch cannot reconfigure a live logger.
pub fn init(options: LogOptions) {
    let logger = Logger::open(options);
    let _ = LOGGER.set(Mutex::new(logger));
}

/// Log an informational line (upstream `LOG(INFO)`).
pub fn info(message: impl AsRef<str>) {
    write_line(0, message.as_ref());
}

/// Log a warning line (upstream `LOG(WARNING)`/`STERROR`).
pub fn warn(message: impl AsRef<str>) {
    write_line(0, &format!("WARNING {}", message.as_ref()));
}

/// Log a verbose line kept only when `level <= --verbose` (upstream `VLOG`).
pub fn verbose(level: u8, message: impl AsRef<str>) {
    write_line(level, message.as_ref());
}

/// Path of the active log file, if logging to a file.
pub fn log_path() -> Option<PathBuf> {
    LOGGER
        .get()
        .and_then(|logger| logger.lock().ok().and_then(|logger| logger.path.clone()))
}

/// Machine-local debug overrides shared by `et`, `etserver`, and `etterminal`.
///
/// | Variable     | Effect |
/// |--------------|--------|
/// | `ET_DEBUG=1` | Raise default verbosity to 2, force logging on, prefer a durable logdir |
/// | `ET_LOGDIR`  | Default log directory when `--logdir` / INI do not set one |
/// | `ET_VERBOSE` | Default verbosity when `--verbose` / INI leave it at 0 |
///
/// Non-zero CLI/INI verbosity and explicit log directories win over these.
/// Verbosity 0 means "use the environment/default verbosity".
pub fn env_debug_enabled() -> bool {
    matches!(
        std::env::var("ET_DEBUG").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES") | Ok("on") | Ok("ON")
    )
}

/// Resolve verbosity: CLI/INI value if non-zero, else `ET_VERBOSE`, else 2 when
/// `ET_DEBUG` is set, else 0.
pub fn effective_verbose(configured: u8) -> u8 {
    resolve_verbose(
        configured,
        env_debug_enabled(),
        std::env::var("ET_VERBOSE").ok(),
    )
}

/// Pure resolution used by [`effective_verbose`] and unit tests.
pub fn resolve_verbose(configured: u8, debug: bool, et_verbose: Option<String>) -> u8 {
    if configured > 0 {
        return configured;
    }
    if let Some(value) = et_verbose {
        if let Ok(level) = value.parse::<u8>() {
            return level;
        }
    }
    if debug {
        2
    } else {
        0
    }
}

/// Resolve log directory: configured path if present, else `ET_LOGDIR`, else
/// platform temp (or a durable home logdir when `ET_DEBUG` is set and no path
/// was configured).
pub fn effective_log_directory(configured: Option<PathBuf>) -> PathBuf {
    resolve_log_directory(
        configured,
        env_debug_enabled(),
        std::env::var_os("ET_LOGDIR").map(PathBuf::from),
        default_debug_log_directory(),
        std::env::temp_dir(),
    )
}

/// Pure resolution used by [`effective_log_directory`] and unit tests.
pub fn resolve_log_directory(
    configured: Option<PathBuf>,
    debug: bool,
    et_logdir: Option<PathBuf>,
    debug_default: PathBuf,
    temp_dir: PathBuf,
) -> PathBuf {
    if let Some(directory) = configured {
        return directory;
    }
    if let Some(directory) = et_logdir {
        return directory;
    }
    if debug {
        debug_default
    } else {
        temp_dir
    }
}

/// When `ET_DEBUG` is set, logging is never silent. Otherwise keep `configured`.
pub fn effective_silent(configured: bool) -> bool {
    resolve_silent(configured, env_debug_enabled())
}

/// Pure resolution used by [`effective_silent`] and unit tests.
pub fn resolve_silent(configured: bool, debug: bool) -> bool {
    if debug {
        false
    } else {
        configured
    }
}

/// Durable default under `$HOME/Library/Logs/et-rs` (macOS) or
/// `%LOCALAPPDATA%\et-rs` (Windows), or `$XDG_STATE_HOME/et-rs` /
/// `$HOME/.local/state/et-rs` elsewhere. Falls back to the process temp dir.
pub fn default_debug_log_directory() -> PathBuf {
    resolve_default_debug_log_directory(
        cfg!(target_os = "macos"),
        cfg!(target_os = "windows"),
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        std::env::temp_dir(),
    )
}

fn resolve_default_debug_log_directory(
    is_macos: bool,
    is_windows: bool,
    home: Option<PathBuf>,
    xdg_state_home: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    temp_dir: PathBuf,
) -> PathBuf {
    if is_macos {
        home.filter(|path| path.is_absolute())
            .map(|path| path.join("Library/Logs/et-rs"))
            .unwrap_or(temp_dir)
    } else if is_windows {
        local_app_data
            .filter(|path| path.is_absolute())
            .map(|path| path.join("et-rs"))
            .unwrap_or(temp_dir)
    } else {
        xdg_state_home
            .filter(|path| path.is_absolute())
            .map(|path| path.join("et-rs"))
            .or_else(|| {
                home.filter(|path| path.is_absolute())
                    .map(|path| path.join(".local/state/et-rs"))
            })
            .unwrap_or(temp_dir)
    }
}

fn write_line(level: u8, message: &str) {
    let Some(logger) = LOGGER.get() else {
        return;
    };
    let Ok(mut logger) = logger.lock() else {
        return;
    };
    logger.write(level, message);
}

impl Logger {
    fn open(options: LogOptions) -> Self {
        if options.silent {
            return Self {
                options,
                path: None,
                file: None,
                written: 0,
            };
        }
        let path = fs::create_dir_all(&options.directory)
            .ok()
            .map(|()| options.directory.join(file_name(&options)));
        let file = path.as_ref().and_then(|path| create(path).ok());
        Self {
            options,
            path,
            file,
            written: 0,
        }
    }

    fn write(&mut self, level: u8, message: &str) {
        if self.options.silent || level > self.options.verbose {
            return;
        }
        let line = format!("[{}] {message}\n", timestamp());
        if self.options.to_stdout {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            let _ = stdout.write_all(line.as_bytes());
            let _ = stdout.flush();
        }
        // Upstream's rollout handler deletes the file once it exceeds the
        // configured size and logging continues into a fresh file.
        if self.written + line.len() as u64 > self.options.max_size {
            if let Some(path) = self.path.clone() {
                self.file = None;
                let _ = fs::remove_file(&path);
                self.file = create(&path).ok();
                self.written = 0;
            }
        }
        if let Some(file) = self.file.as_mut() {
            if file.write_all(line.as_bytes()).is_ok() {
                self.written += line.len() as u64;
                let _ = file.flush();
            }
        }
    }
}

fn create(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    // Upstream opens log files 0600; Windows has no mode bits.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// `<prefix>-<YYYY-MM-DD_HH-MM-SS>.<micros>[_<pid>].log`
fn file_name(options: &LogOptions) -> String {
    let mut name = format!("{}-{}", options.prefix, file_timestamp());
    if options.append_pid {
        name.push_str(&format!("_{}", std::process::id()));
    }
    name.push_str(".log");
    name
}

fn file_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let (year, month, day, hour, minute, second) = civil_from_unix(now.as_secs());
    format!(
        "{year:04}-{month:02}-{day:02}_{hour:02}-{minute:02}-{second:02}.{:06}",
        now.subsec_micros()
    )
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let (year, month, day, hour, minute, second) = civil_from_unix(now.as_secs());
    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02},{:03}",
        now.subsec_millis()
    )
}

/// Days-from-civil conversion (Howard Hinnant's algorithm), UTC.
fn civil_from_unix(seconds: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (
        year,
        month,
        day,
        (remainder / 3600) as u32,
        ((remainder % 3600) / 60) as u32,
        (remainder % 60) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_matches_upstream_pattern() {
        let options = LogOptions {
            prefix: "etserver".to_owned(),
            append_pid: true,
            ..Default::default()
        };
        let name = file_name(&options);
        assert!(name.starts_with("etserver-"));
        assert!(name.ends_with(&format!("_{}.log", std::process::id())));
        // etserver-2026-07-26_16-45-00.123456_1234.log
        let middle = name
            .trim_start_matches("etserver-")
            .split('_')
            .next()
            .unwrap()
            .to_owned();
        let (date, rest) = middle.split_once('_').unwrap_or((&middle, ""));
        assert_eq!(date.len(), 10, "date part: {date}");
        assert!(rest.is_empty() || rest.contains('.'));
    }

    #[test]
    fn civil_conversion_matches_known_timestamps() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(1_000_000_000), (2001, 9, 9, 1, 46, 40));
        assert_eq!(civil_from_unix(1_700_000_000), (2023, 11, 14, 22, 13, 20));
    }

    #[test]
    fn silent_logging_writes_no_file() {
        let directory = std::env::temp_dir().join(format!("et-log-silent-{}", std::process::id()));
        let mut logger = Logger::open(LogOptions {
            directory: directory.clone(),
            silent: true,
            ..Default::default()
        });
        logger.write(0, "hello");
        assert!(logger.path.is_none());
        assert!(!directory.exists());
    }

    #[test]
    fn resolve_verbose_prefers_configured_then_env_then_debug_default() {
        assert_eq!(resolve_verbose(3, true, Some("1".into())), 3);
        assert_eq!(resolve_verbose(0, false, Some("4".into())), 4);
        assert_eq!(resolve_verbose(0, true, None), 2);
        assert_eq!(resolve_verbose(0, false, None), 0);
        assert_eq!(resolve_verbose(0, true, Some("nope".into())), 2);
    }

    #[test]
    fn zero_verbosity_uses_environment_semantics() {
        assert_eq!(resolve_verbose(0, true, None), 2);
        assert_eq!(resolve_verbose(0, true, Some("0".into())), 0);
    }

    #[test]
    fn resolve_log_directory_prefers_configured_then_env_then_debug_default() {
        let configured = PathBuf::from("/cli");
        let env = PathBuf::from("/env");
        let debug_default = PathBuf::from("/debug");
        let temp = PathBuf::from("/tmp");
        assert_eq!(
            resolve_log_directory(
                Some(configured.clone()),
                true,
                Some(env.clone()),
                debug_default.clone(),
                temp.clone()
            ),
            configured
        );
        assert_eq!(
            resolve_log_directory(
                None,
                false,
                Some(env.clone()),
                debug_default.clone(),
                temp.clone()
            ),
            env
        );
        assert_eq!(
            resolve_log_directory(None, true, None, debug_default.clone(), temp.clone()),
            debug_default
        );
        assert_eq!(
            resolve_log_directory(None, false, None, debug_default, temp.clone()),
            temp
        );
    }

    #[test]
    fn resolve_silent_forces_logging_under_debug() {
        assert!(!resolve_silent(true, true));
        assert!(resolve_silent(true, false));
        assert!(!resolve_silent(false, false));
    }

    #[test]
    fn platform_debug_directory_uses_only_absolute_durable_roots() {
        assert_eq!(
            resolve_default_debug_log_directory(
                true,
                false,
                Some(PathBuf::from("/home/test")),
                None,
                None,
                PathBuf::from("/tmp"),
            ),
            PathBuf::from("/home/test/Library/Logs/et-rs")
        );
        assert_eq!(
            resolve_default_debug_log_directory(
                false,
                false,
                Some(PathBuf::from("/home/test")),
                Some(PathBuf::from("/state")),
                None,
                PathBuf::from("/tmp"),
            ),
            PathBuf::from("/state/et-rs")
        );
        assert_eq!(
            resolve_default_debug_log_directory(
                false,
                false,
                Some(PathBuf::from("/home/test")),
                Some(PathBuf::from("relative")),
                None,
                PathBuf::from("/tmp"),
            ),
            PathBuf::from("/home/test/.local/state/et-rs")
        );
        assert_eq!(
            resolve_default_debug_log_directory(
                false,
                true,
                None,
                None,
                Some(PathBuf::from("/local")),
                PathBuf::from("/tmp"),
            ),
            PathBuf::from("/local/et-rs")
        );
    }

    #[cfg_attr(windows, ignore = "file mode bits are POSIX-only")]
    #[test]
    fn file_logging_respects_verbosity_and_rollover() {
        let directory = std::env::temp_dir().join(format!("et-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let mut logger = Logger::open(LogOptions {
            directory: directory.clone(),
            prefix: "ettest".to_owned(),
            silent: false,
            verbose: 1,
            max_size: 200,
            ..Default::default()
        });
        let path = logger.path.clone().unwrap();
        logger.write(0, "info line");
        logger.write(1, "verbose kept");
        logger.write(2, "verbose dropped");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("info line"));
        assert!(contents.contains("verbose kept"));
        assert!(!contents.contains("verbose dropped"));

        for index in 0..40 {
            logger.write(0, &format!("filler {index}"));
        }
        // Rollover keeps the file bounded by max_size.
        let size = fs::metadata(&path).unwrap().len();
        assert!(size <= 200, "log grew to {size}");
        fs::remove_dir_all(&directory).unwrap();
    }
}
