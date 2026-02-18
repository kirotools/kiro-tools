use crate::models::{Account, TokenData};
use crate::modules;
use chrono::Utc;
use serde_json::Value;

fn is_http_unauthorized_error(err: &str) -> bool {
    err.contains("HTTP 401")
}

fn extract_refresh_token_from_json(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(token) = map
                .get("refresh_token")
                .or_else(|| map.get("refreshToken"))
                .and_then(|v| v.as_str())
            {
                let token = token.trim();
                if token.len() > 20 {
                    return Some(token.to_string());
                }
            }

            if let Some(accounts) = map.get("accounts").and_then(|v| v.as_array()) {
                for item in accounts {
                    if let Some(token) = extract_refresh_token_from_json(item) {
                        return Some(token);
                    }
                }
            }

            None
        }
        Value::Array(arr) => {
            // Tuple style: [email, refresh_token]
            if arr.len() >= 2 {
                if let (Some(_email), Some(token)) = (arr[0].as_str(), arr[1].as_str()) {
                    let token = token.trim();
                    if token.len() > 20 {
                        return Some(token.to_string());
                    }
                }
            }

            for item in arr {
                if let Some(token) = extract_refresh_token_from_json(item) {
                    return Some(token);
                }
            }

            None
        }
        Value::String(s) => {
            let token = s.trim();
            if token.len() > 20 {
                Some(token.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn normalize_refresh_token_input(refresh_token: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = refresh_token else {
        return Ok(None);
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.starts_with('{') || trimmed.starts_with('[') || (trimmed.starts_with('"') && trimmed.ends_with('"')) {
        if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
            if let Some(token) = extract_refresh_token_from_json(&json) {
                return Ok(Some(token));
            }

            return Err("Invalid refresh_token JSON input: no refresh_token/refreshToken found".to_string());
        }
    }

    // Fallback: treat as plain token string
    if trimmed.len() > 20 {
        return Ok(Some(trimmed.to_string()));
    }

    Err("Invalid refresh_token input: token is too short".to_string())
}

/// 账号服务层 - 彻底解除对 Tauri 运行时的依赖
pub struct AccountService {
    pub integration: crate::modules::integration::SystemManager,
}

impl AccountService {
    pub fn new(integration: crate::modules::integration::SystemManager) -> Self {
        Self { integration }
    }

    /// 添加账号逻辑
    ///
    /// One of `refresh_token`, `creds_file`, or `sqlite_db` must be provided.
    /// - `refresh_token`: Direct refresh token string (Kiro Desktop auth)
    /// - `creds_file`: Path to JSON credentials file (Kiro IDE or kiro-cli)
    /// - `sqlite_db`: Path to kiro-cli SQLite database
    ///
    /// `auth_source_hint` allows frontend/caller to specify the source type ("token", "creds_file", "aws_sso").
    /// If not specified, it is inferred from which parameter is provided.
    pub async fn add_account(
        &self,
        refresh_token: Option<&str>,
        creds_file: Option<&str>,
        sqlite_db: Option<&str>,
        auth_source_hint: Option<&str>,
    ) -> Result<Account, String> {
        let normalized_refresh_token = normalize_refresh_token_input(refresh_token)?;

        if normalized_refresh_token.is_none() && creds_file.is_none() && sqlite_db.is_none() {
            return Err("Either refreshToken, credsFile, or sqliteDb must be provided".to_string());
        }

        // Determine auth_source: explicit hint > inferred from parameters
        let auth_source = auth_source_hint.map(String::from).or_else(|| {
            if sqlite_db.is_some() {
                Some("sqlite_db".to_string())
            } else if creds_file.is_some() {
                // Detect aws_sso vs creds_file by checking file content for clientId/clientSecret
                if let Some(path) = creds_file {
                    let expanded = shellexpand::tilde(path).to_string();
                    if let Ok(content) = std::fs::read_to_string(&expanded) {
                        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                            if data.get("clientId").is_some() || data.get("client_id").is_some() {
                                return Some("aws_sso".to_string());
                            }
                        }
                    }
                }
                Some("creds_file".to_string())
            } else {
                Some("token".to_string())
            }
        });

        // [FIX #1583] 生成临时 UUID 作为账号上下文，避免传递 None 导致代理选择异常
        let temp_account_id = uuid::Uuid::new_v4().to_string();

        // 1. 获取 Token (使用临时 ID 确保代理选择有明确上下文)
        let token_res = modules::oauth::refresh_access_token_with_source(
            normalized_refresh_token.as_deref(),
            creds_file,
            sqlite_db,
            Some(&temp_account_id),
        )
        .await?;

        // Detect auth_type from the KiroAuthManager
        let auth_type_str = {
            let managers = modules::oauth::get_auth_managers().lock().await;
            managers.get(&temp_account_id).map(|mgr| {
                // Use try_lock to avoid async in sync context
                mgr.auth_type_sync()
                    .map(|at| format!("{:?}", at))
                    .unwrap_or_default()
            })
        };

        let user_info = match modules::oauth::get_user_info(&token_res.access_token, Some(&temp_account_id)).await {
            Ok(info) => info,
            Err(e) if is_http_unauthorized_error(&e) => {
                let retry_token_res = modules::oauth::refresh_access_token_with_source(
                    normalized_refresh_token.as_deref(),
                    creds_file,
                    sqlite_db,
                    Some(&temp_account_id),
                )
                .await?;
                modules::oauth::get_user_info(&retry_token_res.access_token, Some(&temp_account_id)).await?
            }
            Err(e) => return Err(e),
        };

        // 3. Kiro accounts use a fixed project ID
        let project_id = Some("kiro-native".to_string());

        let persist_refresh_token = token_res.refresh_token.clone()
            .or_else(|| normalized_refresh_token.clone())
            .unwrap_or_default();

        let token = TokenData::new(
            token_res.access_token.clone(),
            persist_refresh_token,
            token_res.expires_in,
            Some(user_info.email.clone()),
            project_id,
            None,
        );

        // 5. 持久化
        let mut account =
            modules::upsert_account_with_source(
                user_info.email.clone(), 
                user_info.get_display_name(), 
                token,
                creds_file.map(str::to_string),
                sqlite_db.map(str::to_string),
                auth_source,
                auth_type_str,
            )?;

        // [FIX] Re-register AUTH_MANAGER under the real account ID (remove temp UUID entry).
        // This ensures future token refreshes reuse the existing manager instead of creating new ones.
        modules::oauth::move_auth_manager(&temp_account_id, &account.id).await;

        // 6. [NEW] 自动获取配额信息（用于刷新时间排序）
        let email_for_log = account.email.clone();
        let access_token = token_res.access_token.clone();
        match modules::quota::fetch_quota(&access_token, &email_for_log, Some(&account.id)).await {
            Ok((quota_data, new_project_id)) => {
                account.quota = Some(quota_data);
                if let Some(pid) = new_project_id {
                    account.token.project_id = Some(pid);
                }
                // 保存更新后的账号信息
                if let Err(e) = modules::account::save_account(&account) {
                    modules::logger::log_warn(&format!(
                        "[Service] Failed to save quota for {}: {}",
                        email_for_log, e
                    ));
                } else {
                    modules::logger::log_info(&format!(
                        "[Service] Fetched quota for new account: {}",
                        email_for_log
                    ));
                }
            }
            Err(e) => {
                modules::logger::log_warn(&format!(
                    "[Service] Failed to fetch quota for {}: {}",
                    email_for_log, e
                ));
            }
        }

        modules::logger::log_info(&format!(
            "[Service] Added/Updated account: {}",
            account.email
        ));
        Ok(account)
    }

    /// 删除账号逻辑
    pub fn delete_account(&self, account_id: &str) -> Result<(), String> {
        modules::delete_account(account_id)?;
        self.integration.update_tray();
        Ok(())
    }

    /// 切换账号逻辑
    pub async fn switch_account(&self, account_id: &str) -> Result<(), String> {
        modules::account::switch_account(account_id, &self.integration).await
    }

    /// 列表获取
    pub fn list_accounts(&self) -> Result<Vec<Account>, String> {
        modules::list_accounts()
    }

    /// 获取当前 ID
    pub fn get_current_id(&self) -> Result<Option<String>, String> {
        modules::get_current_account_id()
    }

    /// Force-update credentials for a disabled account.
    ///
    /// Replaces the local `_creds.json` with fresh content from a new source,
    /// performs a test refresh to verify the credentials work, then re-enables
    /// the account — matching kiro-account-manager's behavior of always being
    /// able to recover an account by providing fresh credentials.
    pub async fn update_credentials(
        &self,
        account_id: &str,
        creds_file: Option<&str>,
        sqlite_db: Option<&str>,
    ) -> Result<Account, String> {
        // 1. Force replace _creds.json and clear disabled state
        let account = modules::account::force_update_credentials(account_id, creds_file, sqlite_db)?;

        // 2. Drop any stale in-memory auth manager so a fresh one is created
        // from the new credentials
        modules::oauth::remove_auth_manager(account_id).await;

        // 3. Test-refresh to verify the credentials actually work
        let token_res = modules::oauth::refresh_access_token_with_source(
            None,
            account.creds_file.as_deref(),
            None,
            Some(account_id),
        )
        .await
        .map_err(|e| format!("Credentials test refresh failed: {}", e))?;

        // 4. Save the verified tokens back to the account
        let mut account = modules::account::load_account(account_id)?;
        account.token.access_token = token_res.access_token.clone();
        account.token.expires_in = token_res.expires_in;
        account.token.expiry_timestamp = Utc::now().timestamp() + token_res.expires_in;
        if let Some(ref new_rt) = token_res.refresh_token {
            account.token.refresh_token = new_rt.clone();
        }
        account.encrypted = false;
        modules::account::save_account(&account)?;

        // 5. Fetch fresh quota info
        match modules::quota::fetch_quota(&token_res.access_token, &account.email, Some(account_id)).await {
            Ok((quota_data, new_project_id)) => {
                let mut account = modules::account::load_account(account_id)?;
                account.quota = Some(quota_data);
                if let Some(pid) = new_project_id {
                    account.token.project_id = Some(pid);
                }
                let _ = modules::account::save_account(&account);
            }
            Err(e) => {
                modules::logger::log_warn(&format!(
                    "[Service] Failed to fetch quota after credential update for {}: {}",
                    account.email, e
                ));
            }
        }

        modules::logger::log_info(&format!(
            "[Service] Credentials updated and verified for: {} ({})",
            account.email, account_id
        ));

        modules::account::load_account(account_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_refresh_token_from_json, is_http_unauthorized_error, normalize_refresh_token_input};
    use serde_json::json;

    #[test]
    fn detects_401_error_text() {
        let err = "Failed to fetch user info: HTTP 401 - unauthorized";
        assert!(is_http_unauthorized_error(err));
    }

    #[test]
    fn ignores_non_401_error_text() {
        let err = "Failed to fetch user info: HTTP 403 - forbidden";
        assert!(!is_http_unauthorized_error(err));
    }

    #[test]
    fn parses_plain_refresh_token() {
        let token = "1//abcdefghijklmnopqrstuvwxyz123456";
        let parsed = normalize_refresh_token_input(Some(token)).unwrap();
        assert_eq!(parsed.as_deref(), Some(token));
    }

    #[test]
    fn parses_wrapped_accounts_json() {
        let input = r#"{"accounts":[{"email":"a@b.com","refresh_token":"1//token_12345678901234567890"}]}"#;
        let parsed = normalize_refresh_token_input(Some(input)).unwrap();
        assert_eq!(parsed.as_deref(), Some("1//token_12345678901234567890"));
    }

    #[test]
    fn parses_tuple_array_json() {
        let input = r#"[["a@b.com","1//tuple_token_12345678901234567890"]]"#;
        let parsed = normalize_refresh_token_input(Some(input)).unwrap();
        assert_eq!(parsed.as_deref(), Some("1//tuple_token_12345678901234567890"));
    }

    #[test]
    fn extracts_camel_case_token() {
        let v = json!({"refreshToken":"1//camel_case_token_12345678901234567890"});
        let extracted = extract_refresh_token_from_json(&v);
        assert_eq!(extracted.as_deref(), Some("1//camel_case_token_12345678901234567890"));
    }
}
