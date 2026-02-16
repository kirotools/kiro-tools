use crate::modules::account::{get_accounts_dir, load_account, save_account};
use std::fs;

pub fn migrate_accounts_to_encrypted() -> Result<usize, String> {
    let accounts_dir = get_accounts_dir()?;

    if !accounts_dir.exists() {
        return Ok(0);
    }

    let entries = fs::read_dir(&accounts_dir)
        .map_err(|e| format!("Failed to read accounts directory: {}", e))?;

    let mut migrated_count = 0;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let account_id = match path.file_stem().and_then(|s| s.to_str()) {
            Some(id) => id,
            None => continue,
        };

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let is_encrypted =
            content.contains(r#""encrypted": true"#) || content.contains(r#""encrypted":true"#);

        if !is_encrypted {
            match load_account(account_id) {
                Ok(account) => {
                    crate::modules::logger::log_info(&format!(
                        "Migrating account {} to encrypted storage",
                        account.email
                    ));

                    if let Err(e) = save_account(&account) {
                        crate::modules::logger::log_error(&format!(
                            "Failed to migrate account {}: {}",
                            account.email, e
                        ));
                    } else {
                        migrated_count += 1;
                        crate::modules::logger::log_info(&format!(
                            "Successfully migrated account {}",
                            account.email
                        ));
                    }
                }
                Err(e) => {
                    crate::modules::logger::log_warn(&format!(
                        "Failed to load account {} for migration: {}",
                        account_id, e
                    ));
                }
            }
        }
    }

    if migrated_count > 0 {
        crate::modules::logger::log_info(&format!(
            "Migration complete: {} account(s) migrated to encrypted storage",
            migrated_count
        ));
    }

    Ok(migrated_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Account, TokenData};
    use tempfile::TempDir;

    #[test]
    fn test_migrate_plaintext_accounts() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let accounts_dir = get_accounts_dir().unwrap();
        fs::create_dir_all(&accounts_dir).unwrap();

        let plaintext_account = r#"{
            "id": "migrate-test",
            "email": "migrate@example.com",
            "name": null,
            "token": {
                "access_token": "plaintext_access",
                "refresh_token": "plaintext_refresh",
                "expires_in": 3600,
                "expiry_timestamp": 1234567890,
                "token_type": "Bearer",
                "email": "migrate@example.com",
                "project_id": null,
                "session_id": null
            },
            "quota": null,
            "disabled": false,
            "proxy_disabled": false,
            "validation_blocked": false,
            "created_at": 1234567890,
            "last_used": 1234567890,
            "encrypted": false
        }"#;

        let account_path = accounts_dir.join("migrate-test.json");
        fs::write(&account_path, plaintext_account).unwrap();

        let migrated = migrate_accounts_to_encrypted().unwrap();
        assert_eq!(migrated, 1);

        let content = fs::read_to_string(&account_path).unwrap();
        assert!(!content.contains("plaintext_access"));
        assert!(!content.contains("plaintext_refresh"));
        assert!(
            content.contains(r#""encrypted": true"#) || content.contains(r#""encrypted":true"#)
        );
        assert!(
            !content.contains("plaintext_refresh"),
            "File still contains plaintext_refresh"
        );
        assert!(
            content.contains(r#""encrypted": true"#) || content.contains(r#""encrypted":true"#),
            "File does not have encrypted: true"
        );

        let loaded = load_account("migrate-test").unwrap();
        assert_eq!(loaded.token.access_token, "plaintext_access");
        assert_eq!(loaded.token.refresh_token, "plaintext_refresh");

        std::env::remove_var("KIRO_DATA_DIR");
    }

    #[test]
    fn test_migrate_already_encrypted_accounts() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let account = Account::new(
            "already-encrypted".to_string(),
            "encrypted@example.com".to_string(),
            TokenData::new(
                "access".to_string(),
                "refresh".to_string(),
                3600,
                Some("encrypted@example.com".to_string()),
                None,
                None,
            ),
        );

        save_account(&account).unwrap();

        let migrated = migrate_accounts_to_encrypted().unwrap();
        assert_eq!(migrated, 0);

        std::env::remove_var("KIRO_DATA_DIR");
    }

    #[test]
    fn test_migrate_mixed_accounts() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let accounts_dir = get_accounts_dir().unwrap();
        fs::create_dir_all(&accounts_dir).unwrap();

        let plaintext = r#"{
            "id": "plain-1",
            "email": "plain@example.com",
            "name": null,
            "token": {
                "access_token": "plain_access",
                "refresh_token": "plain_refresh",
                "expires_in": 3600,
                "expiry_timestamp": 1234567890,
                "token_type": "Bearer",
                "email": "plain@example.com"
            },
            "quota": null,
            "disabled": false,
            "proxy_disabled": false,
            "validation_blocked": false,
            "created_at": 1234567890,
            "last_used": 1234567890,
            "encrypted": false
        }"#;

        fs::write(accounts_dir.join("plain-1.json"), plaintext).unwrap();

        let encrypted = Account::new(
            "encrypted-1".to_string(),
            "encrypted@example.com".to_string(),
            TokenData::new(
                "enc_access".to_string(),
                "enc_refresh".to_string(),
                3600,
                Some("encrypted@example.com".to_string()),
                None,
                None,
            ),
        );
        save_account(&encrypted).unwrap();

        let migrated = migrate_accounts_to_encrypted().unwrap();
        assert_eq!(migrated, 1);

        std::env::remove_var("KIRO_DATA_DIR");
    }

    #[test]
    fn test_end_to_end_account_lifecycle_with_encryption() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let accounts_dir = get_accounts_dir().unwrap();
        fs::create_dir_all(&accounts_dir).unwrap();

        let original_access = "secret_access_token_12345";
        let original_refresh = "secret_refresh_token_67890";

        let account = Account::new(
            "e2e-test".to_string(),
            "e2e@example.com".to_string(),
            TokenData::new(
                original_access.to_string(),
                original_refresh.to_string(),
                3600,
                Some("e2e@example.com".to_string()),
                None,
                None,
            ),
        );

        save_account(&account).unwrap();

        let account_path = accounts_dir.join("e2e-test.json");
        let file_content = fs::read_to_string(&account_path).unwrap();

        assert!(
            !file_content.contains(original_access),
            "Access token leaked in plaintext"
        );
        assert!(
            !file_content.contains(original_refresh),
            "Refresh token leaked in plaintext"
        );
        assert!(
            file_content.contains("\"encrypted\""),
            "Missing encrypted field"
        );

        let loaded = load_account("e2e-test").unwrap();
        assert_eq!(loaded.token.access_token, original_access);
        assert_eq!(loaded.token.refresh_token, original_refresh);
        assert!(
            !loaded.encrypted,
            "Loaded account should be decrypted in memory"
        );

        std::env::remove_var("KIRO_DATA_DIR");
    }

    #[test]
    fn test_multiple_accounts_encryption_isolation() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let accounts_dir = get_accounts_dir().unwrap();
        fs::create_dir_all(&accounts_dir).unwrap();

        let accounts_data = vec![
            ("acc1", "user1@example.com", "access1", "refresh1"),
            ("acc2", "user2@example.com", "access2", "refresh2"),
            ("acc3", "user3@example.com", "access3", "refresh3"),
        ];

        for (id, email, access, refresh) in &accounts_data {
            let account = Account::new(
                id.to_string(),
                email.to_string(),
                TokenData::new(
                    access.to_string(),
                    refresh.to_string(),
                    3600,
                    Some(email.to_string()),
                    None,
                    None,
                ),
            );
            save_account(&account).unwrap();
        }

        for (id, email, access, refresh) in &accounts_data {
            let account_path = accounts_dir.join(format!("{}.json", id));
            let file_content = fs::read_to_string(&account_path).unwrap();

            assert!(
                !file_content.contains(access),
                "Account {} access token leaked",
                id
            );
            assert!(
                !file_content.contains(refresh),
                "Account {} refresh token leaked",
                id
            );

            for (other_id, _, other_access, other_refresh) in &accounts_data {
                if other_id != id {
                    assert!(
                        !file_content.contains(other_access),
                        "Account {} contains token from {}",
                        id,
                        other_id
                    );
                    assert!(
                        !file_content.contains(other_refresh),
                        "Account {} contains token from {}",
                        id,
                        other_id
                    );
                }
            }

            let loaded = load_account(id).unwrap();
            assert_eq!(loaded.token.access_token, *access);
            assert_eq!(loaded.token.refresh_token, *refresh);
            assert_eq!(loaded.email, *email);
        }

        std::env::remove_var("KIRO_DATA_DIR");
    }

    #[test]
    fn test_migration_preserves_all_account_fields() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let accounts_dir = get_accounts_dir().unwrap();
        fs::create_dir_all(&accounts_dir).unwrap();

        let plaintext_account = r#"{
  "id": "full-test",
  "email": "full@example.com",
  "name": "Full Name",
  "token": {
    "access_token": "full_access",
    "refresh_token": "full_refresh",
    "expires_in": 7200,
    "expiry_timestamp": 9999999999,
    "token_type": "Bearer",
    "email": "full@example.com",
    "project_id": "proj-123",
    "session_id": "sess-456"
  },
  "quota": {
    "models": [
      {
        "name": "claude-sonnet-4",
        "percentage": 80,
        "reset_time": "2026-02-14T00:00:00Z",
        "usage_limit": 2000.0,
        "current_usage": 400.0
      }
    ],
    "last_updated": 1234567890,
    "is_forbidden": false,
    "subscription_tier": "PRO"
  },
  "disabled": true,
  "disabled_reason": "Test disable",
  "disabled_at": 1234567800,
  "proxy_disabled": true,
  "proxy_disabled_reason": "Test proxy disable",
  "proxy_disabled_at": 1234567801,
  "validation_blocked": true,
  "validation_blocked_until": 1234567900,
  "validation_blocked_reason": "Test validation",
  "created_at": 1234567700,
  "last_used": 1234567850,
  "proxy_id": "proxy-789",
  "proxy_bound_at": 1234567750,
  "custom_label": "Test Label",
  "encrypted": false
}"#;

        let account_path = accounts_dir.join("full-test.json");
        fs::write(&account_path, plaintext_account).unwrap();

        let migrated = migrate_accounts_to_encrypted().unwrap();
        assert_eq!(migrated, 1);

        let loaded = load_account("full-test").unwrap();
        assert_eq!(loaded.id, "full-test");
        assert_eq!(loaded.email, "full@example.com");
        assert_eq!(loaded.name.as_deref(), Some("Full Name"));
        assert_eq!(loaded.token.access_token, "full_access");
        assert_eq!(loaded.token.refresh_token, "full_refresh");
        assert_eq!(loaded.token.expires_in, 7200);
        assert_eq!(loaded.token.expiry_timestamp, 9999999999);
        assert_eq!(loaded.token.project_id.as_deref(), Some("proj-123"));
        assert_eq!(loaded.token.session_id.as_deref(), Some("sess-456"));
        assert!(loaded.quota.is_some());
        assert!(loaded.disabled);
        assert_eq!(loaded.disabled_reason.as_deref(), Some("Test disable"));
        assert_eq!(loaded.disabled_at, Some(1234567800));
        assert!(loaded.proxy_disabled);
        assert_eq!(
            loaded.proxy_disabled_reason.as_deref(),
            Some("Test proxy disable")
        );
        assert_eq!(loaded.proxy_disabled_at, Some(1234567801));
        assert!(loaded.validation_blocked);
        assert_eq!(loaded.validation_blocked_until, Some(1234567900));
        assert_eq!(
            loaded.validation_blocked_reason.as_deref(),
            Some("Test validation")
        );
        assert_eq!(loaded.created_at, 1234567700);
        assert_eq!(loaded.last_used, 1234567850);
        assert_eq!(loaded.proxy_id.as_deref(), Some("proxy-789"));
        assert_eq!(loaded.proxy_bound_at, Some(1234567750));
        assert_eq!(loaded.custom_label.as_deref(), Some("Test Label"));

        std::env::remove_var("KIRO_DATA_DIR");
    }

    #[test]
    fn test_corrupted_encrypted_data_handling() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let accounts_dir = get_accounts_dir().unwrap();
        fs::create_dir_all(&accounts_dir).unwrap();

        let corrupted_account = r#"{
            "id": "corrupted-test",
            "email": "corrupted@example.com",
            "name": null,
            "token": {
                "access_token": "not_valid_base64_!@#$%",
                "refresh_token": "also_invalid_base64_!@#$%",
                "expires_in": 3600,
                "expiry_timestamp": 1234567890,
                "token_type": "Bearer",
                "email": "corrupted@example.com"
            },
            "quota": null,
            "disabled": false,
            "proxy_disabled": false,
            "validation_blocked": false,
            "created_at": 1234567890,
            "last_used": 1234567890,
            "encrypted": true
        }"#;

        let account_path = accounts_dir.join("corrupted-test.json");
        fs::write(&account_path, corrupted_account).unwrap();

        let result = load_account("corrupted-test");
        assert!(result.is_ok(), "Should recover corrupted encrypted flag safely");

        std::env::remove_var("KIRO_DATA_DIR");
    }

    #[test]
    fn test_no_plaintext_leakage_in_memory() {
        let _guard = crate::test_utils::GLOBAL_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("KIRO_DATA_DIR", temp_dir.path());

        let accounts_dir = get_accounts_dir().unwrap();
        fs::create_dir_all(&accounts_dir).unwrap();

        let sensitive_token = "super_secret_token_should_not_leak";

        {
            let account = Account::new(
                "memory-test".to_string(),
                "memory@example.com".to_string(),
                TokenData::new(
                    sensitive_token.to_string(),
                    "refresh_token".to_string(),
                    3600,
                    Some("memory@example.com".to_string()),
                    None,
                    None,
                ),
            );

            save_account(&account).unwrap();
        }

        let account_path = accounts_dir.join("memory-test.json");
        let file_content = fs::read_to_string(&account_path).unwrap();
        assert!(
            !file_content.contains(sensitive_token),
            "Token leaked to disk"
        );

        std::env::remove_var("KIRO_DATA_DIR");
    }
}
