// Claude 协议处理器 (Kiro upstream only)

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};
use tracing::info;

use crate::proxy::debug_logger::{DebugLogger, DebugMode};
use crate::proxy::mappers::claude::models::ClaudeRequest;
use crate::proxy::server::AppState;
use crate::proxy::token_manager::ConcurrencySlot;
use axum::http::HeaderMap;

pub async fn handle_messages(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let trace_id: String = rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect::<String>().to_lowercase();

    let debug_mode = match std::env::var("KIRO_DEBUG_MODE").as_deref() {
        Ok("all") => DebugMode::All,
        Ok("errors") => DebugMode::ErrorsOnly,
        _ => DebugMode::Off,
    };
    let debug_logger = DebugLogger::new(
        debug_mode,
        std::path::PathBuf::from(
            std::env::var("KIRO_DEBUG_DIR").unwrap_or_else(|_| std::env::temp_dir().join("kiro-debug").to_string_lossy().to_string())
        ),
    );

    if debug_logger.should_log(false) {
        let raw = serde_json::to_vec(&body).unwrap_or_default();
        debug_logger.log_request(&trace_id, &raw).await;
    }

    let mut request: ClaudeRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => {
            if debug_logger.should_log(true) {
                debug_logger.log_error(&trace_id, &format!("Invalid request body: {}", e)).await;
            }
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "type": "error",
                    "error": {
                        "type": "invalid_request_error",
                        "message": format!("Invalid request body: {}", e)
                    }
                }))
            ).into_response();
        }
    };

    // Apply custom model alias mapping (e.g. "claude-opus-4.6" → "claude-opus-4.6-thinking")
    let original_model = request.model.clone();
    let mapped_model = {
        let mapping = state.custom_mapping.read().await;
        mapping.get(&request.model).cloned()
    };
    if let Some(ref target) = mapped_model {
        info!(
            "[{}] Model alias applied: {} → {}",
            trace_id, original_model, target
        );
        request.model = target.clone();
    }

    let normalized_model = crate::proxy::common::model_mapping::normalize_to_standard_id(&request.model)
        .unwrap_or_else(|| request.model.clone());

    info!(
        "[{}] Claude Request | Model: {}{} | Stream: {} | Messages: {} | Tools: {}",
        trace_id,
        request.model,
        if mapped_model.is_some() { format!(" (from {})", original_model) } else { String::new() },
        request.stream,
        request.messages.len(),
        request.tools.is_some()
    );

    let token_manager = state.token_manager;

    let (access_token, _project_id, email, account_id, _wait_ms) = match token_manager
        .get_token("claude", false, None, &normalized_model)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            if debug_logger.should_log(true) {
                debug_logger.log_error(&trace_id, &format!("No available accounts: {}", e)).await;
            }
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "type": "error",
                    "error": {
                        "type": "overloaded_error",
                        "message": format!("No available accounts: {}", e)
                    }
                }))
            ).into_response();
        }
    };

    // Check if we need to wait for a concurrency slot — if so, log a pending entry
    let needs_wait = !token_manager.has_available_slot(&account_id);
    let pending_log_id = if needs_wait {
        let log_id = uuid::Uuid::new_v4().to_string();
        let pending_log = crate::proxy::monitor::ProxyRequestLog {
            id: log_id.clone(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            method: "POST".to_string(),
            url: "/v1/messages".to_string(),
            status: 0,
            duration: 0,
            model: Some(request.model.clone()),
            mapped_model: None,
            account_email: Some(email.clone()),
            client_ip: None,
            error: None,
            request_body: None,
            response_body: None,
            input_tokens: None,
            output_tokens: None,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            protocol: Some("anthropic".to_string()),
            username: None,
        };
        state.monitor.log_pending_request(pending_log).await;
        info!("[{}] ⏳ Waiting for concurrency slot on account: {}", trace_id, email);
        Some(log_id)
    } else {
        None
    };

    let _concurrency_slot: ConcurrencySlot = match token_manager
        .acquire_slot_with_timeout(&account_id, std::time::Duration::from_secs(30))
        .await
    {
        Some(slot) => {
            // Slot acquired — remove pending log entry (monitor middleware will log the final result)
            if let Some(ref log_id) = pending_log_id {
                state.monitor.remove_pending_log(log_id).await;
                info!("[{}] ✓ Concurrency slot acquired after waiting", trace_id);
            }
            slot
        }
        None => {
            // Timeout — update pending log to show timeout error
            if let Some(ref log_id) = pending_log_id {
                let timeout_log = crate::proxy::monitor::ProxyRequestLog {
                    id: log_id.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis(),
                    method: "POST".to_string(),
                    url: "/v1/messages".to_string(),
                    status: 503,
                    duration: 30000,
                    model: Some(request.model.clone()),
                    mapped_model: None,
                    account_email: Some(email.clone()),
                    client_ip: None,
                    error: Some("Concurrency slot timeout (30s)".to_string()),
                    request_body: None,
                    response_body: None,
                    input_tokens: None,
                    output_tokens: None,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                    protocol: Some("anthropic".to_string()),
                    username: None,
                };
                state.monitor.update_log(timeout_log).await;
            }
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "type": "error",
                    "error": {
                        "type": "overloaded_error",
                        "message": "Account concurrency limit reached after waiting 30s."
                    }
                }))
            ).into_response();
        }
    };

    info!("✓ Using account: {} (Kiro)", email);

    if token_manager.is_kiro_account(&account_id) {
        let region = token_manager
            .get_account_region(&account_id)
            .unwrap_or_else(|| "us-east-1".to_string());

        let profile_arn = token_manager.get_account_profile_arn(&account_id);

        info!(
            "[{}] [Kiro] Routing to native upstream | Account: {} | Region: {}",
            trace_id, email, region
        );

        let request_timeout_secs = state.request_timeout.load(std::sync::atomic::Ordering::Relaxed);
        return super::kiro_upstream::handle_kiro_messages(
            &request,
            &access_token,
            &email,
            &account_id,
            &trace_id,
            &region,
            profile_arn.as_deref(),
            _concurrency_slot,
            &token_manager,
            mapped_model.as_ref().map(|_| original_model.as_str()),
            request_timeout_secs,
        )
        .await;
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "type": "error",
            "error": {
                "type": "overloaded_error",
                "message": "No Kiro accounts available. Only Kiro upstream is supported."
            }
        }))
    ).into_response()
}


pub async fn handle_list_models(State(state): State<AppState>) -> impl IntoResponse {
    use crate::proxy::common::model_mapping::get_all_dynamic_models;

    let model_ids = get_all_dynamic_models(&state.model_cache, &state.custom_mapping).await;

    let data: Vec<_> = model_ids.into_iter().map(|id| {
        json!({
            "id": id,
            "object": "model",
            "created": 1706745600,
            "owned_by": "kiro-tools"
        })
    }).collect();

    Json(json!({
        "object": "list",
        "data": data
    }))
}

pub async fn handle_count_tokens(
    State(_state): State<AppState>,
    _headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Response {
    Json(json!({
        "input_tokens": 0,
        "output_tokens": 0
    }))
    .into_response()
}
