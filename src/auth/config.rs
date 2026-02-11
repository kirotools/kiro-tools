/// Time before token expiration when refresh is needed (in seconds).
/// Default 10 minutes - refresh token in advance to avoid errors.
pub const TOKEN_REFRESH_THRESHOLD: i64 = 600;

/// Supported SQLite token keys (searched in priority order).
pub const SQLITE_TOKEN_KEYS: &[&str] = &[
    "kirocli:social:token",     // Social login (SSO providers)
    "kirocli:odic:token",       // AWS SSO OIDC (kiro-cli corporate)
    "codewhisperer:odic:token", // Legacy AWS SSO OIDC
];

/// Device registration keys for AWS SSO OIDC (searched in priority order).
pub const SQLITE_REGISTRATION_KEYS: &[&str] = &[
    "kirocli:odic:device-registration",
    "codewhisperer:odic:device-registration",
];

/// Returns the Kiro Desktop Auth token refresh URL for the given region.
///
/// Example: `get_kiro_refresh_url("us-east-1")` →
/// `"https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"`
pub fn get_kiro_refresh_url(region: &str) -> String {
    format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region)
}

/// Returns the Kiro API host for the given region.
///
/// Example: `get_kiro_api_host("us-east-1")` →
/// `"https://codewhisperer.us-east-1.amazonaws.com"`
pub fn get_kiro_api_host(region: &str) -> String {
    format!("https://codewhisperer.{}.amazonaws.com", region)
}

/// Returns the Q API host for the given region.
///
/// Example: `get_kiro_q_host("us-east-1")` →
/// `"https://q.us-east-1.amazonaws.com"`
pub fn get_kiro_q_host(region: &str) -> String {
    format!("https://q.{}.amazonaws.com", region)
}

/// Returns the AWS SSO OIDC token URL for the given region.
///
/// Example: `get_aws_sso_oidc_url("us-east-1")` →
/// `"https://oidc.us-east-1.amazonaws.com/token"`
pub fn get_aws_sso_oidc_url(region: &str) -> String {
    format!("https://oidc.{}.amazonaws.com/token", region)
}

/// Generates a unique machine fingerprint.
///
/// Uses the `machine-uid` crate to get a hardware-based identifier,
/// then hashes it with SHA-256 for privacy.
/// Falls back to a default hash if machine UID is unavailable.
pub fn get_machine_fingerprint() -> String {
    use sha2::{Digest, Sha256};

    match machine_uid::get() {
        Ok(uid) => {
            let mut hasher = Sha256::new();
            hasher.update(uid.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        Err(_) => {
            let mut hasher = Sha256::new();
            hasher.update(b"default-kiro-tools");
            format!("{:x}", hasher.finalize())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_kiro_refresh_url() {
        assert_eq!(
            get_kiro_refresh_url("us-east-1"),
            "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"
        );
        assert_eq!(
            get_kiro_refresh_url("eu-central-1"),
            "https://prod.eu-central-1.auth.desktop.kiro.dev/refreshToken"
        );
    }

    #[test]
    fn test_get_kiro_api_host() {
        assert_eq!(
            get_kiro_api_host("us-east-1"),
            "https://codewhisperer.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_get_kiro_q_host() {
        assert_eq!(
            get_kiro_q_host("us-east-1"),
            "https://q.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_get_aws_sso_oidc_url() {
        assert_eq!(
            get_aws_sso_oidc_url("us-east-1"),
            "https://oidc.us-east-1.amazonaws.com/token"
        );
        assert_eq!(
            get_aws_sso_oidc_url("ap-southeast-1"),
            "https://oidc.ap-southeast-1.amazonaws.com/token"
        );
    }

    #[test]
    fn test_token_refresh_threshold() {
        assert_eq!(TOKEN_REFRESH_THRESHOLD, 600);
    }

    #[test]
    fn test_sqlite_token_keys_order() {
        assert_eq!(SQLITE_TOKEN_KEYS[0], "kirocli:social:token");
        assert_eq!(SQLITE_TOKEN_KEYS[1], "kirocli:odic:token");
        assert_eq!(SQLITE_TOKEN_KEYS[2], "codewhisperer:odic:token");
    }

    #[test]
    fn test_sqlite_registration_keys_order() {
        assert_eq!(
            SQLITE_REGISTRATION_KEYS[0],
            "kirocli:odic:device-registration"
        );
        assert_eq!(
            SQLITE_REGISTRATION_KEYS[1],
            "codewhisperer:odic:device-registration"
        );
    }

    #[test]
    fn test_get_machine_fingerprint_is_stable() {
        let fp1 = get_machine_fingerprint();
        let fp2 = get_machine_fingerprint();
        assert_eq!(fp1, fp2);
        // SHA-256 hex is 64 chars
        assert_eq!(fp1.len(), 64);
    }
}
