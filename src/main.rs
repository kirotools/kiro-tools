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

    // [FIX] 检查是否是修复命令
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--repair-accounts" {
        match commands::account_repair::repair_account_index() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                error!("账号修复失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // [FIX] 在启动时固定数据目录，防止后续调用时环境变量变化
    let data_dir = modules::account::get_data_dir()
        .expect("Failed to get data directory");
    
    // 设置固定的数据目录环境变量
    std::env::set_var("KIRO_DATA_DIR_FIXED", data_dir.to_str().unwrap());
    
    info!("✓ Data directory fixed at: {:?}", data_dir);
    
    // [FIX] 检查数据目录是否可写
    check_data_directory_writable(&data_dir);

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

            let env_port = std::env::var("KIRO_PORT")
                .or_else(|_| std::env::var("PORT"))
                .ok()
                .and_then(|p| p.parse::<u16>().ok());
            if let Some(port) = env_port {
                info!("Using Port from environment variable: {}", port);
                config.proxy.port = port;
                modified = true;
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

/// [FIX] 检查数据目录是否可写
fn check_data_directory_writable(data_dir: &std::path::PathBuf) {
    let test_file = data_dir.join(".write_test");
    if let Err(e) = std::fs::write(&test_file, "test") {
        error!("⚠️  CRITICAL: Data directory is not writable: {}", e);
        error!("⚠️  Accounts may be LOST on restart!");
        error!("⚠️  Directory: {:?}", data_dir);
        error!("⚠️  Please check permissions and disk space.");
        std::process::exit(1);
    }
    let _ = std::fs::remove_file(&test_file);
    
    // 检查环境变量是否设置
    if std::env::var("KIRO_DATA_DIR").is_ok() {
        tracing::warn!("⚠️  KIRO_DATA_DIR environment variable is set");
        tracing::warn!("⚠️  Make sure it's consistent across restarts!");
    }
}
