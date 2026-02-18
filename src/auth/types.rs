use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Authentication mechanism type.
///
/// - `KiroDesktop`: Kiro IDE credentials using desktop auth endpoint
/// - `AwsSsoOidc`: AWS SSO OIDC credentials from kiro-cli or Enterprise Kiro IDE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthType {
    /// Kiro Desktop Auth - uses https://prod.{region}.auth.desktop.kiro.dev/refreshToken
    KiroDesktop,
    /// AWS SSO OIDC - uses https://oidc.{region}.amazonaws.com/token
    AwsSsoOidc,
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthType::KiroDesktop => write!(f, "Kiro Desktop"),
            AuthType::AwsSsoOidc => write!(f, "AWS SSO OIDC"),
        }
    }
}

/// Credentials loaded from a JSON file (Kiro IDE format, camelCase).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct FileCredentials {
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "profileArn")]
    pub profile_arn: Option<String>,
    pub region: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    #[serde(rename = "clientIdHash")]
    pub client_id_hash: Option<String>,
    #[serde(rename = "authMethod")]
    pub auth_method: Option<String>,
    pub provider: Option<String>,
}

/// Credentials loaded from kiro-cli SQLite database (snake_case).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct SqliteTokenData {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub profile_arn: Option<String>,
    pub region: Option<String>,
    pub expires_at: Option<String>,
    pub scopes: Option<Vec<String>>,
}

/// Device registration data from SQLite or Enterprise file.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct DeviceRegistration {
    #[serde(alias = "clientId", alias = "client_id")]
    pub client_id: Option<String>,
    #[serde(alias = "clientSecret", alias = "client_secret")]
    pub client_secret: Option<String>,
    pub region: Option<String>,
}

/// Enterprise device registration file (camelCase, from ~/.aws/sso/cache/{hash}.json).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct EnterpriseDeviceRegistration {
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    /// Unix timestamp when the client_secret expires (0 = unknown / not set).
    #[serde(rename = "clientSecretExpiresAt", default)]
    pub client_secret_expires_at: i64,
}

/// Response from Kiro Desktop Auth refresh endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct KiroDesktopRefreshResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<i64>,
    #[serde(rename = "profileArn")]
    pub profile_arn: Option<String>,
}

/// Response from AWS SSO OIDC CreateToken endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct AwsSsoOidcRefreshResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<i64>,
}

/// Errors specific to the auth module.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Refresh token is not set")]
    MissingRefreshToken,

    #[error("Client ID is not set (required for AWS SSO OIDC)")]
    MissingClientId,

    #[error("Client secret is not set (required for AWS SSO OIDC)")]
    MissingClientSecret,

    #[error("Response does not contain accessToken")]
    MissingAccessToken,

    #[error("Failed to obtain access token")]
    TokenUnavailable,

    #[error("Token expired and refresh failed. Please run 'kiro-cli login' to refresh your credentials.")]
    TokenExpiredRefreshFailed,

    #[error("HTTP error: {status} - {body}")]
    HttpStatus { status: u16, body: String },

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Date parse error: {0}")]
    DateParse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_type_display() {
        assert_eq!(AuthType::KiroDesktop.to_string(), "Kiro Desktop");
        assert_eq!(AuthType::AwsSsoOidc.to_string(), "AWS SSO OIDC");
    }

    #[test]
    fn test_auth_type_equality() {
        assert_eq!(AuthType::KiroDesktop, AuthType::KiroDesktop);
        assert_eq!(AuthType::AwsSsoOidc, AuthType::AwsSsoOidc);
        assert_ne!(AuthType::KiroDesktop, AuthType::AwsSsoOidc);
    }

    #[test]
    fn test_file_credentials_deserialize() {
        let json = r#"{
            "refreshToken": "rt_123",
            "accessToken": "at_456",
            "profileArn": "arn:aws:test",
            "region": "us-east-1",
            "expiresAt": "2026-02-10T19:54:16Z",
            "clientIdHash": "abc123",
            "authMethod": "IdC",
            "provider": "Enterprise"
        }"#;
        let creds: FileCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.refresh_token.as_deref(), Some("rt_123"));
        assert_eq!(creds.access_token.as_deref(), Some("at_456"));
        assert_eq!(creds.profile_arn.as_deref(), Some("arn:aws:test"));
        assert_eq!(creds.region.as_deref(), Some("us-east-1"));
        assert_eq!(creds.client_id_hash.as_deref(), Some("abc123"));
        assert_eq!(creds.auth_method.as_deref(), Some("IdC"));
        assert_eq!(creds.provider.as_deref(), Some("Enterprise"));
    }

    #[test]
    fn test_file_credentials_missing_fields() {
        let json = r#"{"refreshToken": "rt_only"}"#;
        let creds: FileCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.refresh_token.as_deref(), Some("rt_only"));
        assert!(creds.access_token.is_none());
        assert!(creds.client_id.is_none());
        assert!(creds.client_id_hash.is_none());
    }

    #[test]
    fn test_sqlite_token_data_deserialize() {
        let json = r#"{
            "access_token": "at_sqlite",
            "refresh_token": "rt_sqlite",
            "region": "ap-southeast-1",
            "expires_at": "2026-02-10T19:54:16Z",
            "scopes": ["codewhisperer:completions"]
        }"#;
        let data: SqliteTokenData = serde_json::from_str(json).unwrap();
        assert_eq!(data.access_token.as_deref(), Some("at_sqlite"));
        assert_eq!(data.refresh_token.as_deref(), Some("rt_sqlite"));
        assert_eq!(data.scopes.as_ref().map(|s| s.len()), Some(1));
    }

    #[test]
    fn test_enterprise_device_registration_deserialize() {
        let json = r#"{"clientId": "cid_123", "clientSecret": "cs_456"}"#;
        let reg: EnterpriseDeviceRegistration = serde_json::from_str(json).unwrap();
        assert_eq!(reg.client_id.as_deref(), Some("cid_123"));
        assert_eq!(reg.client_secret.as_deref(), Some("cs_456"));
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::MissingRefreshToken;
        assert_eq!(err.to_string(), "Refresh token is not set");

        let err = AuthError::HttpStatus {
            status: 400,
            body: "bad request".to_string(),
        };
        assert!(err.to_string().contains("400"));
    }
}
