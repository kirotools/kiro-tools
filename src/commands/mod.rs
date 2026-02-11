#![allow(dead_code)]
use crate::models::{Account, AppConfig};
use crate::modules;

pub mod proxy;
pub mod cloudflared;
pub mod user_token;

pub async fn list_accounts() -> Result<Vec<Account>, String> {
    modules::list_accounts()
}

pub async fn get_current_account() -> Result<Option<Account>, String> {
    let account_id = modules::get_current_account_id()?;
    if let Some(id) = account_id {
        modules::load_account(&id).map(Some)
    } else {
        Ok(None)
    }
}

pub async fn load_config() -> Result<AppConfig, String> {
    modules::load_app_config()
}

pub async fn save_config(config: AppConfig) -> Result<(), String> {
    modules::save_app_config(&config)
}

pub use modules::account::RefreshStats;

pub async fn refresh_all_quotas_internal(
    proxy_state: &crate::commands::proxy::ProxyServiceState,
) -> Result<RefreshStats, String> {
    let stats = modules::account::refresh_all_quotas_logic().await?;

    let instance_lock = proxy_state.instance.read().await;
    if let Some(instance) = instance_lock.as_ref() {
        let _ = instance.token_manager.reload_all_accounts().await;
    }

    Ok(stats)
}

pub async fn clear_log_cache() -> Result<(), String> {
    modules::logger::clear_logs()
}

pub async fn clear_kiro_cache() -> Result<modules::cache::ClearResult, String> {
    modules::cache::clear_kiro_cache(None)
}

pub async fn get_kiro_cache_paths() -> Result<Vec<String>, String> {
    Ok(modules::cache::get_existing_cache_paths()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect())
}

pub async fn open_data_folder() -> Result<(), String> {
    let path = modules::account::get_data_dir()?;

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
    }

    Ok(())
}
