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
    // Try to find an existing auth manager for this account
    if let Some(aid) = account_id {
        let managers = get_auth_managers().lock().await;
        if let Some(manager) = managers.get(aid) {
            return token_from_manager(manager).await;
        }
    }

    // Build a new manager: prefer creds_file (loads clientIdHash → device registration),
    // fall back to bare refresh_token (Kiro Desktop auth only).
    let manager = KiroAuthManager::new(
        refresh_token.map(String::from),
        None,
        std::env::var("KIRO_REGION").ok(),
        creds_file.map(String::from).or_else(|| std::env::var("KIRO_CREDS_FILE").ok()),
        None,
        None,
        std::env::var("KIRO_CLI_DB_FILE").ok(),
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

/// Get user info.
///
/// Kiro does not have a traditional userinfo endpoint.
/// Returns a placeholder derived from `account_id`.
pub async fn get_user_info(
    _access_token: &str,
    account_id: Option<&str>,
) -> Result<UserInfo, String> {
    let label = account_id.unwrap_or("kiro-user").to_string();
    Ok(UserInfo {
        email: label,
        name: Some("Kiro User".to_string()),
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

    // Construct new TokenData
    Ok(crate::models::TokenData::new(
        response.access_token,
        current_token.refresh_token.clone(), // refresh_token may not be returned on refresh
        response.expires_in,
        current_token.email.clone(),
        current_token.project_id.clone(), // Keep original project_id
        None, // session_id will be generated in token_manager
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
    async fn test_get_user_info_returns_placeholder() {
        let info = get_user_info("token", Some("test-account")).await.unwrap();
        assert_eq!(info.email, "test-account");
    }
}
