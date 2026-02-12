use serde::{Deserialize, Serialize};
use crate::auth::KiroAuthManager;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

// ─── Public types (same fields as before — callers depend on these) ────────

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
}

impl UserInfo {
    /// Get best display name
    pub fn get_display_name(&self) -> Option<String> {
        // Prefer name
        if let Some(name) = &self.name {
            if !name.trim().is_empty() {
                return Some(name.clone());
            }
        }

        // If name is empty, combine given_name and family_name
        match (&self.given_name, &self.family_name) {
            (Some(given), Some(family)) => Some(format!("{} {}", given, family)),
            (Some(given), None) => Some(given.clone()),
            (None, Some(family)) => Some(family.clone()),
            (None, None) => None,
        }
    }
}

// ─── Global KiroAuthManager registry: account_id → KiroAuthManager ─────────

static AUTH_MANAGERS: OnceLock<Arc<Mutex<HashMap<String, Arc<KiroAuthManager>>>>> = OnceLock::new();

fn get_auth_managers() -> &'static Arc<Mutex<HashMap<String, Arc<KiroAuthManager>>>> {
    AUTH_MANAGERS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Register a KiroAuthManager for an account.
pub async fn register_auth_manager(account_id: &str, manager: Arc<KiroAuthManager>) {
    let mut managers = get_auth_managers().lock().await;
    managers.insert(account_id.to_string(), manager);
}

// ─── Core API (same signatures as before) ──────────────────────────────────

/// Refresh access_token using Kiro auth.
///
/// If an auth manager is registered for `account_id`, it is reused.
/// Otherwise a KiroAuthManager is created from `creds_file` (preferred, loads full
/// credential chain including Enterprise device registration) or bare `refresh_token`.
pub async fn refresh_access_token(
    refresh_token: Option<&str>,
    creds_file: Option<&str>,
    account_id: Option<&str>,
) -> Result<TokenResponse, String> {
    refresh_access_token_with_source(refresh_token, creds_file, None, account_id).await
}

/// Refresh access_token with explicit source selection.
///
/// Supports three authentication sources:
/// - `refresh_token`: Direct refresh token (Kiro Desktop auth)
/// - `creds_file`: Path to JSON credentials file
/// - `sqlite_db`: Path to kiro-cli SQLite database
pub async fn refresh_access_token_with_source(
    refresh_token: Option<&str>,
    creds_file: Option<&str>,
    sqlite_db: Option<&str>,
    account_id: Option<&str>,
) -> Result<TokenResponse, String> {
    // Try to find an existing auth manager for this account
    if let Some(aid) = account_id {
        let managers = get_auth_managers().lock().await;
        if let Some(manager) = managers.get(aid) {
            return token_from_manager(manager).await;
        }
    }

    // Build a new manager with explicit source priority: sqlite_db > creds_file > refresh_token
    let manager = KiroAuthManager::new(
        refresh_token.map(String::from),
        None,
        std::env::var("KIRO_REGION").ok(),
        creds_file.map(String::from).or_else(|| std::env::var("KIRO_CREDS_FILE").ok()),
        None,
        None,
        sqlite_db.map(String::from).or_else(|| std::env::var("KIRO_CLI_DB_FILE").ok()),
    );

    if let Some(aid) = account_id {
        crate::modules::logger::log_info(&format!(
            "Refreshing Kiro token for account: {}...",
            aid
        ));
    } else {
        crate::modules::logger::log_info(
            "Refreshing Kiro token for generic request (no account_id)...",
        );
    }

    let manager = Arc::new(manager);

    // Register for future reuse
    if let Some(aid) = account_id {
        register_auth_manager(aid, Arc::clone(&manager)).await;
    }

    token_from_manager(&manager).await
}

/// Helper: obtain a TokenResponse from a KiroAuthManager.
async fn token_from_manager(manager: &KiroAuthManager) -> Result<TokenResponse, String> {
    let access_token = manager
        .get_access_token()
        .await
        .map_err(|e| format!("Kiro token refresh failed: {}", e))?;

    let expires_at = manager.expires_at().await;
    let expires_in = expires_at
        .map(|e| (e - chrono::Utc::now()).num_seconds().max(0))
        .unwrap_or(3600);

    crate::modules::logger::log_info(&format!(
        "Token refreshed successfully! Expires in: {} seconds",
        expires_in
    ));

    Ok(TokenResponse {
        access_token,
        expires_in,
        token_type: "Bearer".to_string(),
        refresh_token: manager.current_refresh_token().await,
    })
}

/// Get user info from Kiro API.
///
/// Uses the /getUsageLimits endpoint which returns user email along with quota info.
/// This is the same endpoint used by Kiro IDE to fetch user information.
pub async fn get_user_info(
    access_token: &str,
    account_id: Option<&str>,
) -> Result<UserInfo, String> {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct KiroUsageLimitsResponse {
        #[serde(rename = "userInfo", default)]
        user_info: KiroUserInfo,
    }

    #[derive(Debug, Deserialize, Default)]
    struct KiroUserInfo {
        #[serde(default)]
        email: String,
    }

    let fingerprint = crate::auth::config::get_machine_fingerprint();
    let host = format!("codewhisperer.{}.amazonaws.com", "us-east-1");
    let url = format!(
        "https://{}/getUsageLimits?isEmailRequired=true&origin=AI_EDITOR&resourceType=AGENTIC_REQUEST",
        host
    );

    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 15).await
    } else {
        crate::utils::http::get_client()
    };

    let invocation_id = uuid::Uuid::new_v4().to_string();

    let response = client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header("x-amz-user-agent", format!("aws-sdk-js/1.0.0 KiroIDE-0.7.45-{}", fingerprint))
        .header(
            reqwest::header::USER_AGENT,
            format!(
                "aws-sdk-js/1.0.0 ua/2.1 os/linux lang/js api/codewhispererruntime#1.0.0 m/E KiroIDE-0.7.45-{}",
                fingerprint
            ),
        )
        .header("host", &host)
        .header("amz-sdk-invocation-id", &invocation_id)
        .header("amz-sdk-request", "attempt=1; max=1")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch user info: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Failed to fetch user info: HTTP {} - {}", status, text));
    }

    let usage_limits: KiroUsageLimitsResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse user info response: {}", e))?;

    let email = if !usage_limits.user_info.email.is_empty() {
        usage_limits.user_info.email
    } else {
        // Fallback to a generated email if API doesn't return one
        format!("kiro-user-{}", account_id.unwrap_or("unknown"))
    };

    Ok(UserInfo {
        email,
        name: None,
        given_name: None,
        family_name: None,
        picture: None,
    })
}

/// Generate OAuth authorization URL — NOT applicable for Kiro (stub).
pub fn get_auth_url(_redirect_uri: &str, _state: &str) -> String {
    // Kiro doesn't use OAuth redirect flow
    String::from("kiro://auth-not-applicable")
}

/// Exchange authorization code for token — NOT applicable for Kiro (stub).
pub async fn exchange_code(
    _code: &str,
    _redirect_uri: &str,
) -> Result<TokenResponse, String> {
    Err("OAuth code exchange is not supported for Kiro auth. Use credential file or kiro-cli login instead.".to_string())
}

/// Check and refresh Token if needed.
/// Returns the latest TokenData.
pub async fn ensure_fresh_token(
    current_token: &crate::models::TokenData,
    account_id: Option<&str>,
) -> Result<crate::models::TokenData, String> {
    let now = chrono::Local::now().timestamp();

    // If more than 5 minutes valid, return directly
    if current_token.expiry_timestamp > now + 300 {
        return Ok(current_token.clone());
    }

    // Need to refresh
    crate::modules::logger::log_info(&format!(
        "Token expiring soon for account {:?}, refreshing...",
        account_id
    ));
    let response = refresh_access_token(Some(&current_token.refresh_token), None, account_id).await?;

    // Use new refresh_token if returned, otherwise keep the old one
    let new_refresh_token = response.refresh_token
        .clone()
        .unwrap_or_else(|| current_token.refresh_token.clone());

    // Construct new TokenData
    Ok(crate::models::TokenData::new(
        response.access_token,
        new_refresh_token,
        response.expires_in,
        current_token.email.clone(),
        current_token.project_id.clone(),
        None,
    ))
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_auth_url_returns_stub() {
        let url = get_auth_url("http://localhost:8080/callback", "test-state");
        assert!(url.contains("kiro"));
    }

    #[test]
    fn test_user_info_display_name() {
        let info = UserInfo {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            given_name: None,
            family_name: None,
            picture: None,
        };
        assert_eq!(info.get_display_name(), Some("Test User".to_string()));
    }

    #[test]
    fn test_user_info_display_name_from_parts() {
        let info = UserInfo {
            email: "test@example.com".to_string(),
            name: None,
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            picture: None,
        };
        assert_eq!(info.get_display_name(), Some("John Doe".to_string()));
    }

    #[test]
    fn test_user_info_display_name_none() {
        let info = UserInfo {
            email: "test@example.com".to_string(),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
        };
        assert_eq!(info.get_display_name(), None);
    }

    #[tokio::test]
    async fn test_exchange_code_returns_error() {
        let result = exchange_code("code", "http://localhost").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not supported"));
    }

    #[tokio::test]
    async fn test_get_user_info_returns_error_with_invalid_token() {
        let result = get_user_info("invalid-token", Some("test-account")).await;
        // 使用无效 token 调用真实 API 应该返回错误
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Failed to fetch user info"), "Unexpected error: {}", err);
    }
}
