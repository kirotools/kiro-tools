use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: String,
    #[zeroize(skip)]
    pub expires_in: i64,
    #[zeroize(skip)]
    pub expiry_timestamp: i64,
    #[zeroize(skip)]
    pub token_type: String,
    #[zeroize(skip)]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub session_id: Option<String>,
}

impl TokenData {
    pub fn new(
        access_token: String,
        refresh_token: String,
        expires_in: i64,
        email: Option<String>,
        project_id: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        let expiry_timestamp = chrono::Utc::now().timestamp() + expires_in;
        Self {
            access_token,
            refresh_token,
            expires_in,
            expiry_timestamp,
            token_type: "Bearer".to_string(),
            email,
            project_id,
            session_id,
        }
    }
}
