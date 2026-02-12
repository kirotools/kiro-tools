#![allow(dead_code)]
use std::path::PathBuf;

use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::warn;

/// Debug logging mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugMode {
    /// Logging disabled
    Off,
    /// Log only on errors (4xx, 5xx)
    ErrorsOnly,
    /// Log all requests
    All,
}

impl Default for DebugMode {
    fn default() -> Self {
        Self::Off
    }
}

/// Debug logger for capturing request/response data.
pub struct DebugLogger {
    mode: DebugMode,
    debug_dir: PathBuf,
}

impl DebugLogger {
    pub fn new(mode: DebugMode, debug_dir: PathBuf) -> Self {
        Self { mode, debug_dir }
    }

    /// Check if logging should occur for this event.
    pub fn should_log(&self, is_error: bool) -> bool {
        match self.mode {
            DebugMode::Off => false,
            DebugMode::ErrorsOnly => is_error,
            DebugMode::All => true,
        }
    }

    /// Ensure the debug directory exists.
    async fn ensure_dir(&self) -> bool {
        if let Err(e) = fs::create_dir_all(&self.debug_dir).await {
            warn!(dir = %self.debug_dir.display(), error = %e, "Failed to create debug directory");
            return false;
        }
        true
    }

    /// Log raw request body to file. Creates debug_dir if needed.
    ///
    /// Writes to `{debug_dir}/{trace_id}_request.json`.
    /// Attempts to pretty-print if valid JSON, otherwise writes raw bytes.
    pub async fn log_request(&self, trace_id: &str, raw_body: &[u8]) {
        if !self.ensure_dir().await {
            return;
        }

        let path = self.debug_dir.join(format!("{trace_id}_request.json"));

        let content = match serde_json::from_slice::<serde_json::Value>(raw_body) {
            Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_else(|_| {
                String::from_utf8_lossy(raw_body).into_owned()
            }),
            Err(_) => String::from_utf8_lossy(raw_body).into_owned(),
        };

        if let Err(e) = fs::write(&path, content.as_bytes()).await {
            warn!(path = %path.display(), error = %e, "Failed to write request debug log");
        }
    }

    /// Append a response chunk to the log file.
    ///
    /// Appends to `{debug_dir}/{trace_id}_response.txt`.
    pub async fn log_response_chunk(&self, trace_id: &str, chunk: &[u8]) {
        if !self.ensure_dir().await {
            return;
        }

        let path = self.debug_dir.join(format!("{trace_id}_response.txt"));

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await;

        match file {
            Ok(mut f) => {
                if let Err(e) = f.write_all(chunk).await {
                    warn!(path = %path.display(), error = %e, "Failed to append response chunk");
                }
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to open response debug log");
            }
        }
    }

    /// Log error information.
    ///
    /// Writes to `{debug_dir}/{trace_id}_error.txt`.
    pub async fn log_error(&self, trace_id: &str, error: &str) {
        if !self.ensure_dir().await {
            return;
        }

        let path = self.debug_dir.join(format!("{trace_id}_error.txt"));
        let timestamp = chrono::Utc::now().to_rfc3339();
        let content = format!("[{timestamp}] {error}\n");

        if let Err(e) = fs::write(&path, content.as_bytes()).await {
            warn!(path = %path.display(), error = %e, "Failed to write error debug log");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_off() {
        assert_eq!(DebugMode::default(), DebugMode::Off);
    }

    #[test]
    fn should_log_off_never_logs() {
        let logger = DebugLogger::new(DebugMode::Off, PathBuf::from("/tmp"));
        assert!(!logger.should_log(false));
        assert!(!logger.should_log(true));
    }

    #[test]
    fn should_log_errors_only_on_error() {
        let logger = DebugLogger::new(DebugMode::ErrorsOnly, PathBuf::from("/tmp"));
        assert!(!logger.should_log(false));
        assert!(logger.should_log(true));
    }

    #[test]
    fn should_log_all_always_logs() {
        let logger = DebugLogger::new(DebugMode::All, PathBuf::from("/tmp"));
        assert!(logger.should_log(false));
        assert!(logger.should_log(true));
    }
}
