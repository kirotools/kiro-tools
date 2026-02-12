#![allow(dead_code)]
use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::Response,
};
use crate::proxy::debug_logger::{DebugLogger, DebugMode};

/// Endpoints whose raw request bodies are captured for debug logging.
const LOGGED_ENDPOINTS: &[&str] = &["/v1/messages"];

/// Max body size we're willing to buffer for debug logging (10 MB).
const MAX_DEBUG_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Axum middleware that captures raw request bodies before validation
/// and writes them to disk via [`DebugLogger`].
///
/// Controlled by environment variables:
/// - `KIRO_DEBUG_MODE`: `"all"` | `"errors"` | unset (off)
/// - `KIRO_DEBUG_DIR`: directory for debug files (default `/tmp/kiro-debug`)
pub async fn debug_logging_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // Skip non-API endpoints
    if !LOGGED_ENDPOINTS.iter().any(|ep| path == *ep) {
        return next.run(request).await;
    }

    // Check debug mode from env — Off means skip entirely
    let debug_mode = match std::env::var("KIRO_DEBUG_MODE").as_deref() {
        Ok("all") => DebugMode::All,
        Ok("errors") => DebugMode::ErrorsOnly,
        _ => return next.run(request).await,
    };

    let debug_dir = std::env::var("KIRO_DEBUG_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().join("kiro-debug").to_string_lossy().to_string());
    let logger = DebugLogger::new(debug_mode, std::path::PathBuf::from(debug_dir));

    // Generate a short trace ID for correlating request/response files
    let trace_id: String = rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect::<String>()
        .to_lowercase();

    // Extract body bytes
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_DEBUG_BODY_SIZE).await {
        Ok(bytes) => bytes,
        Err(_) => {
            // Body too large or read error — pass through with empty body
            let request = Request::from_parts(parts, Body::empty());
            return next.run(request).await;
        }
    };

    // Log raw request body (non-error context)
    if logger.should_log(false) {
        logger.log_request(&trace_id, &body_bytes).await;
    }

    // Reconstruct request with the captured body
    let request = Request::from_parts(parts, Body::from(body_bytes));

    // Continue to handler
    let response = next.run(request).await;

    // Log on error responses (4xx / 5xx)
    let is_error = response.status().is_client_error() || response.status().is_server_error();
    if is_error && logger.should_log(true) {
        logger
            .log_error(&trace_id, &format!("Response status: {}", response.status()))
            .await;
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logged_endpoints() {
        assert!(LOGGED_ENDPOINTS.contains(&"/v1/messages"));
        assert!(!LOGGED_ENDPOINTS.contains(&"/health"));
    }

    #[test]
    fn test_max_debug_body_size() {
        assert_eq!(MAX_DEBUG_BODY_SIZE, 10 * 1024 * 1024);
    }
}
