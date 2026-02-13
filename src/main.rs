pub mod auth;
mod models;
mod modules;
mod commands;
mod utils;
mod proxy;
pub mod error;
pub mod constants;

#[cfg(test)]
mod test_utils;

use modules::logger;
use tracing::{info, error};
use std::sync::Arc;

#[cfg(target_os = "macos")]
fn increase_nofile_limit() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            info!("Current open file limit: soft={}, hard={}", rl.rlim_cur, rl.rlim_max);
            let target = 4096.min(rl.rlim_max);
            if rl.rlim_cur < target {
                rl.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) == 0 {
                    info!("Successfully increased hard file limit to {}", target);
                } else {
                    tracing::warn!("Failed to increase file descriptor limit");
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    #[cfg(target_os = "macos")]
    increase_nofile_limit();

    logger::init_logger();

    if let Err(e) = modules::token_stats::init_db() {
        error!("Failed to initialize token stats database: {}", e);
    }
    if let Err(e) = modules::security_db::init_db() {
        error!("Failed to initialize security database: {}", e);
    }
    if let Err(e) = modules::user_token_db::init_db() {
        error!("Failed to initialize user token database: {}", e);
    }

    match modules::migration::migrate_accounts_to_encrypted() {
        Ok(count) if count > 0 => {
            info!("Migrated {} account(s) to encrypted storage", count);
        }
        Ok(_) => {}
        Err(e) => {
            error!("Failed to migrate accounts to encrypted storage: {}", e);
        }
    }

    info!("Starting kiro-tools server...");

    let proxy_state = commands::proxy::ProxyServiceState::new();
    let cf_state = Arc::new(commands::cloudflared::CloudflaredState::new());

    match modules::config::load_app_config() {
        Ok(mut config) => {
            let mut modified = false;

            let bind_local_only = std::env::var("KIRO_BIND_LOCAL_ONLY")
                .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false);
            if bind_local_only {
                config.proxy.allow_lan_access = false;
                modified = true;
            } else {
                config.proxy.allow_lan_access = true;
            }

            if matches!(config.proxy.auth_mode, crate::proxy::ProxyAuthMode::Off | crate::proxy::ProxyAuthMode::Auto) {
                info!("Forcing auth_mode to AllExceptHealth for security");
                config.proxy.auth_mode = crate::proxy::ProxyAuthMode::AllExceptHealth;
                modified = true;
            }

            let env_key = std::env::var("KIRO_API_KEY")
                .or_else(|_| std::env::var("API_KEY"))
                .ok();
            if let Some(key) = env_key {
                if !key.trim().is_empty() {
                    info!("Using API Key from environment variable");
                    config.proxy.api_key = key;
                    modified = true;
                }
            }

            let env_web_password = std::env::var("KIRO_WEB_PASSWORD")
                .or_else(|_| std::env::var("WEB_PASSWORD"))
                .ok();
            if let Some(pwd) = env_web_password {
                if !pwd.trim().is_empty() {
                    info!("Using Web UI Password from environment variable");
                    config.proxy.admin_password = Some(pwd);
                    modified = true;
                }
            }

            let env_auth_mode = std::env::var("KIRO_AUTH_MODE")
                .or_else(|_| std::env::var("AUTH_MODE"))
                .ok();
            if let Some(mode_str) = env_auth_mode {
                let mode = match mode_str.to_lowercase().as_str() {
                    "off" => Some(crate::proxy::ProxyAuthMode::Off),
                    "strict" => Some(crate::proxy::ProxyAuthMode::Strict),
                    "all_except_health" => Some(crate::proxy::ProxyAuthMode::AllExceptHealth),
                    "auto" => Some(crate::proxy::ProxyAuthMode::Auto),
                    _ => {
                        tracing::warn!("Invalid AUTH_MODE: {}, ignoring", mode_str);
                        None
                    }
                };
                if let Some(m) = mode {
                    info!("Using Auth Mode from environment variable: {:?}", m);
                    config.proxy.auth_mode = m;
                    modified = true;
                }
            }

            info!("--------------------------------------------------");
            info!("Proxy service starting...");
            info!("Port: {}", config.proxy.port);
            info!("API Key: {}", config.proxy.api_key);
            if let Some(ref pwd) = config.proxy.admin_password {
                info!("Web UI Password: {}", pwd);
            } else {
                info!("Web UI Password: (Same as API Key)");
            }
            info!("--------------------------------------------------");

            if modified {
                if let Err(e) = modules::config::save_app_config(&config) {
                    error!("Failed to persist environment overrides: {}", e);
                } else {
                    info!("Environment overrides persisted to gui_config.json");
                }
            }

            if let Err(e) = commands::proxy::internal_start_proxy_service(
                config.proxy,
                &proxy_state,
                crate::modules::integration::SystemManager::Headless,
                cf_state.clone(),
            ).await {
                error!("Failed to start proxy service: {}", e);
                std::process::exit(1);
            }

            info!("Proxy service is running.");
        }
        Err(e) => {
            error!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    }

    tokio::signal::ctrl_c().await.ok();
    info!("Shutting down");
}
