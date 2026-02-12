#![allow(dead_code)]
/// Known error reason codes from the Kiro API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KiroErrorReason {
    ContentLengthExceedsThreshold,
    MonthlyRequestCount,
    MonthlyTokenCount,
    DailyRequestCount,
    ConcurrentRequestLimit,
    ModelNotAvailable,
    ServiceUnavailable,
    Unknown(String),
}

/// Structured information about a Kiro API error, including the user-friendly
/// message and metadata needed to build an Anthropic-shaped error response.
#[derive(Debug, Clone)]
pub struct KiroErrorInfo {
    pub reason: KiroErrorReason,
    pub user_message: String,
    pub anthropic_error_type: String,
    pub http_status: u16,
    pub original_message: String,
}

/// Maps a Kiro API reason code and raw message into a [`KiroErrorInfo`] with a
/// user-friendly message, appropriate HTTP status, and Anthropic error type.
pub fn map_kiro_error(reason_code: &str, raw_message: &str) -> KiroErrorInfo {
    match reason_code {
        "CONTENT_LENGTH_EXCEEDS_THRESHOLD" => KiroErrorInfo {
            reason: KiroErrorReason::ContentLengthExceedsThreshold,
            user_message: "Model context limit reached. Conversation size exceeds model capacity."
                .into(),
            anthropic_error_type: "api_error".into(),
            http_status: 400,
            original_message: raw_message.into(),
        },
        "MONTHLY_REQUEST_COUNT" => KiroErrorInfo {
            reason: KiroErrorReason::MonthlyRequestCount,
            user_message: "Monthly request limit exceeded. Account has reached its monthly quota."
                .into(),
            anthropic_error_type: "rate_limit_error".into(),
            http_status: 429,
            original_message: raw_message.into(),
        },
        "MONTHLY_TOKEN_COUNT" => KiroErrorInfo {
            reason: KiroErrorReason::MonthlyTokenCount,
            user_message:
                "Monthly token limit exceeded. Account has reached its monthly token quota.".into(),
            anthropic_error_type: "rate_limit_error".into(),
            http_status: 429,
            original_message: raw_message.into(),
        },
        "DAILY_REQUEST_COUNT" => KiroErrorInfo {
            reason: KiroErrorReason::DailyRequestCount,
            user_message: "Daily request limit exceeded. Please try again tomorrow.".into(),
            anthropic_error_type: "rate_limit_error".into(),
            http_status: 429,
            original_message: raw_message.into(),
        },
        "CONCURRENT_REQUEST_LIMIT" => KiroErrorInfo {
            reason: KiroErrorReason::ConcurrentRequestLimit,
            user_message:
                "Too many concurrent requests. Please wait for current requests to complete.".into(),
            anthropic_error_type: "rate_limit_error".into(),
            http_status: 429,
            original_message: raw_message.into(),
        },
        "MODEL_NOT_AVAILABLE" => KiroErrorInfo {
            reason: KiroErrorReason::ModelNotAvailable,
            user_message: "Requested model is not available. Please try a different model.".into(),
            anthropic_error_type: "invalid_request_error".into(),
            http_status: 400,
            original_message: raw_message.into(),
        },
        "SERVICE_UNAVAILABLE" => KiroErrorInfo {
            reason: KiroErrorReason::ServiceUnavailable,
            user_message: "Kiro service is temporarily unavailable. Please try again later.".into(),
            anthropic_error_type: "api_error".into(),
            http_status: 503,
            original_message: raw_message.into(),
        },
        _ => KiroErrorInfo {
            reason: KiroErrorReason::Unknown(reason_code.into()),
            user_message: format!("{raw_message} (reason: {reason_code})"),
            anthropic_error_type: "api_error".into(),
            http_status: 502,
            original_message: raw_message.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_length_exceeds_threshold() {
        let info = map_kiro_error("CONTENT_LENGTH_EXCEEDS_THRESHOLD", "Input is too long.");
        assert_eq!(info.reason, KiroErrorReason::ContentLengthExceedsThreshold);
        assert_eq!(
            info.user_message,
            "Model context limit reached. Conversation size exceeds model capacity."
        );
        assert_eq!(info.anthropic_error_type, "api_error");
        assert_eq!(info.http_status, 400);
        assert_eq!(info.original_message, "Input is too long.");
    }

    #[test]
    fn test_monthly_request_count() {
        let info = map_kiro_error("MONTHLY_REQUEST_COUNT", "Limit exceeded");
        assert_eq!(info.reason, KiroErrorReason::MonthlyRequestCount);
        assert_eq!(
            info.user_message,
            "Monthly request limit exceeded. Account has reached its monthly quota."
        );
        assert_eq!(info.anthropic_error_type, "rate_limit_error");
        assert_eq!(info.http_status, 429);
    }

    #[test]
    fn test_monthly_token_count() {
        let info = map_kiro_error("MONTHLY_TOKEN_COUNT", "Token limit");
        assert_eq!(info.reason, KiroErrorReason::MonthlyTokenCount);
        assert_eq!(
            info.user_message,
            "Monthly token limit exceeded. Account has reached its monthly token quota."
        );
        assert_eq!(info.anthropic_error_type, "rate_limit_error");
        assert_eq!(info.http_status, 429);
    }

    #[test]
    fn test_daily_request_count() {
        let info = map_kiro_error("DAILY_REQUEST_COUNT", "Daily limit");
        assert_eq!(info.reason, KiroErrorReason::DailyRequestCount);
        assert_eq!(
            info.user_message,
            "Daily request limit exceeded. Please try again tomorrow."
        );
        assert_eq!(info.anthropic_error_type, "rate_limit_error");
        assert_eq!(info.http_status, 429);
    }

    #[test]
    fn test_concurrent_request_limit() {
        let info = map_kiro_error("CONCURRENT_REQUEST_LIMIT", "Too many");
        assert_eq!(info.reason, KiroErrorReason::ConcurrentRequestLimit);
        assert_eq!(
            info.user_message,
            "Too many concurrent requests. Please wait for current requests to complete."
        );
        assert_eq!(info.anthropic_error_type, "rate_limit_error");
        assert_eq!(info.http_status, 429);
    }

    #[test]
    fn test_model_not_available() {
        let info = map_kiro_error("MODEL_NOT_AVAILABLE", "No such model");
        assert_eq!(info.reason, KiroErrorReason::ModelNotAvailable);
        assert_eq!(
            info.user_message,
            "Requested model is not available. Please try a different model."
        );
        assert_eq!(info.anthropic_error_type, "invalid_request_error");
        assert_eq!(info.http_status, 400);
    }

    #[test]
    fn test_service_unavailable() {
        let info = map_kiro_error("SERVICE_UNAVAILABLE", "Down for maintenance");
        assert_eq!(info.reason, KiroErrorReason::ServiceUnavailable);
        assert_eq!(
            info.user_message,
            "Kiro service is temporarily unavailable. Please try again later."
        );
        assert_eq!(info.anthropic_error_type, "api_error");
        assert_eq!(info.http_status, 503);
    }

    #[test]
    fn test_unknown_reason() {
        let info = map_kiro_error("SOMETHING_NEW", "Weird error happened");
        assert_eq!(
            info.reason,
            KiroErrorReason::Unknown("SOMETHING_NEW".into())
        );
        assert_eq!(
            info.user_message,
            "Weird error happened (reason: SOMETHING_NEW)"
        );
        assert_eq!(info.anthropic_error_type, "api_error");
        assert_eq!(info.http_status, 502);
        assert_eq!(info.original_message, "Weird error happened");
    }

    use proptest::prelude::*;

    const KNOWN_CODES: &[&str] = &[
        "CONTENT_LENGTH_EXCEEDS_THRESHOLD",
        "MONTHLY_REQUEST_COUNT",
        "MONTHLY_TOKEN_COUNT",
        "DAILY_REQUEST_COUNT",
        "CONCURRENT_REQUEST_LIMIT",
        "MODEL_NOT_AVAILABLE",
        "SERVICE_UNAVAILABLE",
    ];

    proptest! {
        /// Property 7: all known error codes produce non-empty user_message
        /// and valid anthropic_error_type.
        #[test]
        fn prop_kiro_error_code_mapping_completeness(
            idx in 0..7usize,
            raw_msg in "[a-zA-Z0-9 ]{1,50}",
        ) {
            let code = KNOWN_CODES[idx];
            let info = map_kiro_error(code, &raw_msg);
            prop_assert!(!info.user_message.is_empty());
            prop_assert!(!info.anthropic_error_type.is_empty());
            let valid_types = [
                "api_error",
                "rate_limit_error",
                "invalid_request_error",
                "authentication_error",
                "overloaded_error",
            ];
            prop_assert!(
                valid_types.contains(&info.anthropic_error_type.as_str()),
                "unexpected error type: {}",
                info.anthropic_error_type
            );
            prop_assert!(info.http_status >= 400 && info.http_status < 600);
        }

        #[test]
        fn prop_kiro_unknown_code_preserves_message(
            code in "[A-Z_]{1,20}",
            raw_msg in "[a-zA-Z0-9 ]{1,50}",
        ) {
            prop_assume!(!KNOWN_CODES.contains(&code.as_str()));
            let info = map_kiro_error(&code, &raw_msg);
            prop_assert!(info.user_message.contains(&raw_msg));
            prop_assert!(info.user_message.contains(&code));
        }
    }
}
