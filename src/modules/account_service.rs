use crate::models::{Account, TokenData};
use crate::modules;

fn is_http_unauthorized_error(err: &str) -> bool {
    err.contains("HTTP 401")
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
    pub async fn add_account(
        &self,
        refresh_token: Option<&str>,
        creds_file: Option<&str>,
        sqlite_db: Option<&str>,
    ) -> Result<Account, String> {
        if refresh_token.is_none() && creds_file.is_none() && sqlite_db.is_none() {
            return Err("Either refreshToken, credsFile, or sqliteDb must be provided".to_string());
        }

        // [FIX #1583] 生成临时 UUID 作为账号上下文，避免传递 None 导致代理选择异常
        let temp_account_id = uuid::Uuid::new_v4().to_string();

        // 1. 获取 Token (使用临时 ID 确保代理选择有明确上下文)
        let token_res = modules::oauth::refresh_access_token_with_source(
            refresh_token,
            creds_file,
            sqlite_db,
            Some(&temp_account_id),
        )
        .await?;

        let user_info = match modules::oauth::get_user_info(&token_res.access_token, Some(&temp_account_id)).await {
            Ok(info) => info,
            Err(e) if is_http_unauthorized_error(&e) => {
                let retry_token_res = modules::oauth::refresh_access_token_with_source(
                    refresh_token,
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
            .or_else(|| refresh_token.map(String::from))
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
}

#[cfg(test)]
mod tests {
    use super::is_http_unauthorized_error;

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
}
