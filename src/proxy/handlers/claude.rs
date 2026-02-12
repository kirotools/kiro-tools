// Claude 协议处理器 (Kiro upstream only)

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};
use tracing::info;

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

    let request: ClaudeRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => {
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

    let normalized_model = crate::proxy::common::model_mapping::normalize_to_standard_id(&request.model)
        .unwrap_or_else(|| request.model.clone());

    info!(
        "[{}] Claude Request | Model: {} | Stream: {} | Messages: {} | Tools: {}",
        trace_id,
        request.model,
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

    let _concurrency_slot: ConcurrencySlot = match token_manager
        .try_acquire_slot(&account_id)
    {
        Some(slot) => slot,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "type": "error",
                    "error": {
                        "type": "overloaded_error",
                        "message": "Account concurrency limit reached. Please retry."
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

        info!(
            "[{}] [Kiro] Routing to native upstream | Account: {} | Region: {}",
            trace_id, email, region
        );

        return super::kiro_upstream::handle_kiro_messages(
            &request,
            &access_token,
            &email,
            &account_id,
            &trace_id,
            &region,
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

    let model_ids = get_all_dynamic_models(&state.custom_mapping).await;

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
