// Unified Anthropic-compatible error response formatting
// All error responses follow: {"type": "error", "error": {"type": "<type>", "message": "<msg>"}}

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Anthropic API compatible error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnthropicErrorType {
    InvalidRequestError,
    AuthenticationError,
    RateLimitError,
    ApiError,
    OverloadedError,
}

impl AnthropicErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequestError => "invalid_request_error",
            Self::AuthenticationError => "authentication_error",
            Self::RateLimitError => "rate_limit_error",
            Self::ApiError => "api_error",
            Self::OverloadedError => "overloaded_error",
        }
    }
}

/// Build an Anthropic-format error response with the given HTTP status, error type, and message.
pub fn error_response(
    status: StatusCode,
    error_type: AnthropicErrorType,
    message: &str,
) -> Response {
    let body = json!({
        "type": "error",
        "error": {
            "type": error_type.as_str(),
            "message": message
        }
    });
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_type_strings() {
        assert_eq!(
            AnthropicErrorType::InvalidRequestError.as_str(),
            "invalid_request_error"
        );
        assert_eq!(
            AnthropicErrorType::AuthenticationError.as_str(),
            "authentication_error"
        );
        assert_eq!(
            AnthropicErrorType::RateLimitError.as_str(),
            "rate_limit_error"
        );
        assert_eq!(AnthropicErrorType::ApiError.as_str(), "api_error");
        assert_eq!(
            AnthropicErrorType::OverloadedError.as_str(),
            "overloaded_error"
        );
    }

    use proptest::prelude::*;

    proptest! {
        /// Property 19: error_response produces valid Anthropic error JSON shape.
        #[test]
        fn prop_error_response_format(msg in "[a-zA-Z0-9 ]{1,100}") {
            let resp = error_response(
                StatusCode::BAD_REQUEST,
                AnthropicErrorType::InvalidRequestError,
                &msg,
            );
            let (parts, body) = resp.into_parts();
            prop_assert_eq!(parts.status, StatusCode::BAD_REQUEST);

            let body_bytes = axum::body::to_bytes(body, 1_000_000);
            let body_bytes = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(body_bytes)
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

            prop_assert_eq!(parsed["type"].as_str().unwrap(), "error");
            prop_assert_eq!(
                parsed["error"]["type"].as_str().unwrap(),
                "invalid_request_error"
            );
            prop_assert_eq!(parsed["error"]["message"].as_str().unwrap(), msg.as_str());
        }
    }
}
