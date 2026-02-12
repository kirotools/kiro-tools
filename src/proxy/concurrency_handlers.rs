use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use crate::models::AppConfig;
use crate::modules::config;
use crate::proxy::server::AppState;

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn admin_get_max_concurrency(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let max_concurrency = state.token_manager.get_max_concurrency();
    Ok(Json(json!({ "maxConcurrency": max_concurrency })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetMaxConcurrencyRequest {
    max_concurrency: usize,
}

pub async fn admin_set_max_concurrency(
    State(state): State<AppState>,
    Json(payload): Json<SetMaxConcurrencyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .token_manager
        .set_max_concurrency(payload.max_concurrency);

    // 持久化配置
    let mut app_config: AppConfig = config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    app_config.proxy.max_concurrency_per_account = payload.max_concurrency;
    config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(StatusCode::OK)
}
