use super::{quota::QuotaData, token::TokenData};
use serde::{Deserialize, Serialize};

/// 账号数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub token: TokenData,
    pub quota: Option<QuotaData>,
    /// Disabled accounts are ignored by the proxy token pool (e.g. revoked refresh_token -> invalid_grant).
    #[serde(default)]
    pub disabled: bool,
    /// Optional human-readable reason for disabling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// Unix timestamp when the account was disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<i64>,
    /// User manually disabled proxy feature (does not affect app usage).
    #[serde(default)]
    pub proxy_disabled: bool,
    /// Optional human-readable reason for proxy disabling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_disabled_reason: Option<String>,
    /// Unix timestamp when the proxy was disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_disabled_at: Option<i64>,
    /// [NEW] 403 验证阻止状态 (VALIDATION_REQUIRED)
    #[serde(default)]
    pub validation_blocked: bool,
    /// [NEW] 验证阻止截止时间戳
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_until: Option<i64>,
    /// [NEW] 验证阻止原因
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_reason: Option<String>,
    pub created_at: i64,
    pub last_used: i64,
    /// 绑定的代理 ID (None = 使用全局代理池)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    /// 代理绑定时间
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_bound_at: Option<i64>,
    /// 用户自定义标签
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    #[serde(default)]
    pub encrypted: bool,
    /// Path to the original credentials file (e.g., ~/.aws/sso/cache/kiro-auth-token.json)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creds_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sqlite_db: Option<String>,
    /// Whether to sync refreshed tokens back to the source credentials file
    #[serde(default)]
    pub sync_back: bool,
    /// Authentication source: "token", "creds_file", "aws_sso"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_source: Option<String>,
    /// Detected auth type from KiroAuthManager: "KiroDesktop" or "AwsSsoOidc"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// Original credential source path before import-to-local (e.g. ~/.aws/sso/cache/kiro-auth-token.json).
    /// Used as a recovery fallback on invalid_grant: if our local token chain breaks,
    /// we can re-read from the original source (Kiro IDE may have updated it independently).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_creds_source: Option<String>,
}

impl Account {
    pub fn new(id: String, email: String, token: TokenData) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id,
            email,
            name: None,
            token,
            quota: None,
            disabled: false,
            disabled_reason: None,
            disabled_at: None,
            proxy_disabled: false,
            proxy_disabled_reason: None,
            proxy_disabled_at: None,
            validation_blocked: false,
            validation_blocked_until: None,
            validation_blocked_reason: None,
            created_at: now,
            last_used: now,
            proxy_id: None,
            proxy_bound_at: None,
            custom_label: None,
            encrypted: false,
            creds_file: None,
            sqlite_db: None,
            sync_back: false,
            auth_source: None,
            auth_type: None,
            original_creds_source: None,
        }
    }

    pub fn update_last_used(&mut self) {
        self.last_used = chrono::Utc::now().timestamp();
    }

    pub fn update_quota(&mut self, quota: QuotaData) {
        self.quota = Some(quota);
    }

    pub fn encrypt_tokens(&mut self) -> Result<(), String> {
        if self.encrypted {
            return Ok(());
        }

        self.token.access_token = crate::utils::crypto::encrypt_string(&self.token.access_token)
            .map_err(|e| format!("Failed to encrypt access_token: {}", e))?;
        self.token.refresh_token = crate::utils::crypto::encrypt_string(&self.token.refresh_token)
            .map_err(|e| format!("Failed to encrypt refresh_token: {}", e))?;
        self.encrypted = true;
        Ok(())
    }

    pub fn decrypt_tokens(&mut self) -> Result<(), String> {
        if !self.encrypted {
            return Ok(());
        }

        self.token.access_token = crate::utils::crypto::decrypt_string(&self.token.access_token)
            .map_err(|e| format!("Failed to decrypt access_token: {}", e))?;
        self.token.refresh_token = crate::utils::crypto::decrypt_string(&self.token.refresh_token)
            .map_err(|e| format!("Failed to decrypt refresh_token: {}", e))?;
        self.encrypted = false;
        Ok(())
    }
}

/// 账号索引数据（accounts.json）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountIndex {
    pub version: String,
    pub accounts: Vec<AccountSummary>,
    pub current_account_id: Option<String>,
}

/// 账号摘要信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub proxy_disabled: bool,
    pub created_at: i64,
    pub last_used: i64,
}

impl AccountIndex {
    pub fn new() -> Self {
        Self {
            version: "2.0".to_string(),
            accounts: Vec::new(),
            current_account_id: None,
        }
    }
}

impl Default for AccountIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// 导出账号项（用于备份/迁移）
///
/// 支持三种来源的账号导出：
/// - token: 仅包含 email + refresh_token
/// - creds_file: 包含 email + refresh_token + 嵌入的凭证文件内容
/// - aws_sso: 包含 email + refresh_token + 嵌入的 AWS SSO 凭证内容
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportItem {
    pub email: String,
    pub refresh_token: String,
    /// 认证来源: "token" | "creds_file" | "aws_sso"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_source: Option<String>,
    /// 检测到的认证类型: "KiroDesktop" | "AwsSsoOidc"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// 嵌入的凭证文件内容（用于 creds_file/aws_sso 来源的完整还原）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creds_data: Option<serde_json::Value>,
}

/// 导出账号响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportResponse {
    pub accounts: Vec<AccountExportItem>,
}
