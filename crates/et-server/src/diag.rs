//! Optional process-wide diagnostic logging for the server runtime.
//!
//! `et-server` stays free of CLI/file-logging dependencies. The `etserver` binary
//! installs a sink that forwards into `et_cli::logging` after it initialises.
//! When no sink is installed (unit tests, embedded callers), log calls are no-ops.

use std::sync::OnceLock;

/// `level` matches upstream `VLOG` / `LOG(INFO)`: `0` is always kept by an
/// installed sink that honours info lines; higher values are verbose.
pub type DiagSink = fn(level: u8, message: &str);

static SINK: OnceLock<DiagSink> = OnceLock::new();

/// Install the process-wide diagnostic sink. Later calls are ignored so a live
/// server cannot reconfigure logging mid-flight.
pub fn init(sink: DiagSink) {
    let _ = SINK.set(sink);
}

/// Log an informational line (always forwarded when a sink is installed).
pub fn info(message: impl AsRef<str>) {
    write(0, message.as_ref());
}

/// Log a verbose line; the sink decides whether `level` is kept.
pub fn verbose(level: u8, message: impl AsRef<str>) {
    write(level, message.as_ref());
}

/// Escape and bound untrusted text before embedding it in a diagnostic line.
pub fn sanitize_external_field(value: &str) -> String {
    const MAX_LEN: usize = 256;
    const ELLIPSIS: &str = "...";

    let mut sanitized = String::with_capacity(value.len().min(MAX_LEN));
    let mut truncated = false;
    for character in value.chars() {
        let escaped: String = character.escape_default().collect();
        if sanitized.len() + escaped.len() > MAX_LEN - ELLIPSIS.len() {
            truncated = true;
            break;
        }
        sanitized.push_str(&escaped);
    }
    if truncated {
        sanitized.push_str(ELLIPSIS);
    }
    sanitized
}

fn write(level: u8, message: &str) {
    if let Some(sink) = SINK.get() {
        sink(level, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_fields_escape_control_characters_and_limit_length() {
        let malicious = format!("client\nforged\rentry\t{}", "x".repeat(300));
        let sanitized = sanitize_external_field(&malicious);
        assert_eq!(
            sanitized,
            format!("client\\nforged\\rentry\\t{}...", "x".repeat(230))
        );
        assert_eq!(sanitized.len(), 256);
    }
}
