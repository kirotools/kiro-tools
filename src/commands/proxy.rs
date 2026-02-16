#![allow(dead_code)]
use crate::proxy::monitor::{ProxyMonitor, ProxyStats};
use crate::proxy::{ProxyConfig, TokenManager};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
    pub base_url: String,
    pub active_accounts: usize,
}

#[derive(Clone)]
pub struct ProxyServiceState {
    pub instance: Arc<RwLock<Option<ProxyServiceInstance>>>,
    pub monitor: Arc<RwLock<Option<Arc<ProxyMonitor>>>>,
    pub admin_server: Arc<RwLock<Option<AdminServerInstance>>>,
    pub starting: Arc<AtomicBool>,
}

pub struct AdminServerInstance {
    pub axum_server: crate::proxy::AxumServer,
    #[allow(dead_code)]
    pub server_handle: tokio::task::JoinHandle<()>,
}

pub struct ProxyServiceInstance {
    pub config: ProxyConfig,
    pub token_manager: Arc<TokenManager>,
    pub axum_server: crate::proxy::AxumServer,
    #[allow(dead_code)]
    pub server_handle: tokio::task::JoinHandle<()>,
}

impl ProxyServiceState {
    pub fn new() -> Self {
        Self {
            instance: Arc::new(RwLock::new(None)),
            monitor: Arc::new(RwLock::new(None)),
            admin_server: Arc::new(RwLock::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
        }
    }
}

struct StartingGuard(Arc<AtomicBool>);
impl Drop for StartingGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

pub async fn internal_start_proxy_service(
    config: ProxyConfig,
    state: &ProxyServiceState,
    integration: crate::modules::integration::SystemManager,
    cloudflared_state: Arc<crate::commands::cloudflared::CloudflaredState>,
) -> Result<ProxyStatus, String> {
    {
        let instance_lock = state.instance.read().await;
        if instance_lock.is_some() {
            return Err("Service already running".to_string());
        }
    }

    if state
        .starting
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Service is starting, please wait...".to_string());
    }

    let _starting_guard = StartingGuard(state.starting.clone());

    {
        let mut monitor_lock = state.monitor.write().await;
        if monitor_lock.is_none() {
            *monitor_lock = Some(Arc::new(ProxyMonitor::new(1000, None)));
        }
        if let Some(monitor) = monitor_lock.as_ref() {
            monitor.set_enabled(config.enable_logging);
        }
    }

    let _monitor = state.monitor.read().await.as_ref().unwrap().clone();

    ensure_admin_server(
        config.clone(),
        state,
        integration.clone(),
        cloudflared_state.clone(),
    )
    .await?;

    let token_manager = {
        let admin_lock = state.admin_server.read().await;
        admin_lock
            .as_ref()
            .unwrap()
            .axum_server
            .token_manager
            .clone()
    };

    token_manager.start_auto_cleanup().await;
    token_manager
        .update_sticky_config(config.scheduling.clone())
        .await;

    let app_config = crate::modules::config::load_app_config()
        .unwrap_or_else(|_| crate::models::AppConfig::new());
    token_manager
        .update_circuit_breaker_config(app_config.circuit_breaker)
        .await;

    if let Some(ref account_id) = config.preferred_account_id {
        token_manager
            .set_preferred_account(Some(account_id.clone()))
            .await;
        tracing::info!("Fixed account mode restored: {}", account_id);
    }

    let active_accounts = token_manager.load_accounts().await.unwrap_or(0);

    if active_accounts > 0 {
        let primary_id = token_manager
            .get_preferred_account()
            .await
            .or_else(|| token_manager.get_first_account_id());

        if let Some(aid) = primary_id {
            let refresh_fut = token_manager.force_refresh_account_token(&aid);
            match tokio::time::timeout(std::time::Duration::from_secs(20), refresh_fut).await {
                Ok(Ok(_)) => {
                    tracing::info!("Startup token refresh ok: {}", aid);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Startup token refresh failed ({}): {}", aid, e);
                }
                Err(_) => {
                    tracing::warn!("Startup token refresh timed out: {}", aid);
                }
            }
        }
    }

    // Auto-import from KIRO_CREDS_FILE env var if no accounts exist (matching gateway behavior)
    let active_accounts = if active_accounts == 0 {
        if let Ok(creds_file) = std::env::var("KIRO_CREDS_FILE") {
            let expanded = if creds_file.starts_with('~') {
                if let Some(home) = dirs::home_dir() {
                    creds_file.replacen('~', &home.to_string_lossy(), 1)
                } else {
                    creds_file.clone()
                }
            } else {
                creds_file.clone()
            };
            if std::path::Path::new(&expanded).exists() {
                tracing::info!("No accounts found, auto-importing from KIRO_CREDS_FILE: {}", expanded);

                let svc = crate::modules::account_service::AccountService::new(integration.clone());
                match svc.add_account(None, Some(&expanded), None).await {
                    Ok(account) => {
                        tracing::info!("Auto-imported account from KIRO_CREDS_FILE: {}", account.email);
                        token_manager.load_accounts().await.unwrap_or(0)
                    }
                    Err(e) => {
                        tracing::error!("Failed to auto-import from KIRO_CREDS_FILE: {}", e);
                        0
                    }
                }
            } else {
                tracing::warn!("KIRO_CREDS_FILE set but file not found: {}", expanded);
                0
            }
        } else {
            0
        }
    } else {
        active_accounts
    };

    // Populate model cache from Kiro API (matching gateway startup behavior)
    {
        let admin_lock = state.admin_server.read().await;
        let model_cache = admin_lock.as_ref().unwrap().axum_server.model_cache.clone();
        let tm = token_manager.clone();
        tokio::spawn(async move {
            if let Ok((access_token, _project_id, _email, _account_id, _wait)) =
                tm.get_token("claude", false, None, "claude-sonnet-4.5").await
            {
                let region = tm.get_first_account_region().unwrap_or_else(|| "us-east-1".to_string());
                let profile_arn = tm.get_first_account_profile_arn();
                let arn_ref = profile_arn.as_deref();
                match crate::proxy::common::model_mapping::fetch_models_from_kiro(
                    &access_token, &region, arn_ref,
                ).await {
                    Ok(models) => {
                        let models_clone = models.clone();
                        let _ = model_cache.get_models(move || async move { Ok(models_clone) }).await;
                        tracing::info!("Model cache populated: {} models from Kiro API", models.len());
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch models from Kiro API: {}, using fallback", e);
                    }
                }
            }
        });
    }

    if active_accounts == 0 {
        let legacy_enabled = config.legacy_provider.enabled
            && !matches!(config.legacy_provider.dispatch_mode, crate::proxy::LegacyDispatchMode::Off);
        if !legacy_enabled {
            tracing::warn!("No available accounts, proxy logic will pause.");
            return Ok(ProxyStatus {
                running: false,
                port: config.port,
                base_url: format!("http://127.0.0.1:{}", config.port),
                active_accounts: 0,
            });
        }
    }

    let mut instance_lock = state.instance.write().await;
    let admin_lock = state.admin_server.read().await;
    let axum_server = admin_lock.as_ref().unwrap().axum_server.clone();

    let instance = ProxyServiceInstance {
        config: config.clone(),
        token_manager: token_manager.clone(),
        axum_server: axum_server.clone(),
        server_handle: tokio::spawn(async {}),
    };

    axum_server.set_running(true).await;

    *instance_lock = Some(instance);

    Ok(ProxyStatus {
        running: true,
        port: config.port,
        base_url: format!("http://127.0.0.1:{}", config.port),
        active_accounts,
    })
}

pub async fn ensure_admin_server(
    config: ProxyConfig,
    state: &ProxyServiceState,
    integration: crate::modules::integration::SystemManager,
    cloudflared_state: Arc<crate::commands::cloudflared::CloudflaredState>,
) -> Result<(), String> {
    let mut admin_lock = state.admin_server.write().await;
    if admin_lock.is_some() {
        return Ok(());
    }

    let monitor = {
        let mut monitor_lock = state.monitor.write().await;
        if monitor_lock.is_none() {
            *monitor_lock = Some(Arc::new(ProxyMonitor::new(1000, None)));
        }
        monitor_lock.as_ref().unwrap().clone()
    };

    let app_data_dir = crate::modules::account::get_data_dir()?;
    let token_manager = Arc::new(TokenManager::new(app_data_dir));
    token_manager.set_max_concurrency(config.max_concurrency_per_account);
    let _ = token_manager.load_accounts().await;

    let (axum_server, server_handle) = match crate::proxy::AxumServer::start(
        config.get_bind_address().to_string(),
        config.port,
        token_manager,
        config.custom_mapping.clone(),
        config.request_timeout,
        config.upstream_proxy.clone(),
        config.user_agent_override.clone(),
        crate::proxy::ProxySecurityConfig::from_proxy_config(&config),
        monitor,
        integration.clone(),
        cloudflared_state,
        config.proxy_pool.clone(),
        config.fake_reasoning.clone(),
    )
    .await
    {
        Ok((server, handle)) => (server, handle),
        Err(e) => return Err(format!("Failed to start admin server: {}", e)),
    };

    *admin_lock = Some(AdminServerInstance {
        axum_server,
        server_handle,
    });

    crate::proxy::update_global_system_prompt_config(config.global_system_prompt.clone());

    Ok(())
}

pub async fn stop_proxy_service(state: &ProxyServiceState) -> Result<(), String> {
    let mut instance_lock = state.instance.write().await;

    if instance_lock.is_none() {
        return Err("Service not running".to_string());
    }

    if let Some(instance) = instance_lock.take() {
        instance.token_manager.abort_background_tasks().await;
        instance.axum_server.set_running(false).await;
    }

    Ok(())
}

pub async fn get_proxy_status(state: &ProxyServiceState) -> Result<ProxyStatus, String> {
    if state.starting.load(Ordering::SeqCst) {
        return Ok(ProxyStatus {
            running: false,
            port: 0,
            base_url: "starting".to_string(),
            active_accounts: 0,
        });
    }

    let lock_res = state.instance.try_read();

    match lock_res {
        Ok(instance_lock) => match instance_lock.as_ref() {
            Some(instance) => Ok(ProxyStatus {
                running: true,
                port: instance.config.port,
                base_url: format!("http://127.0.0.1:{}", instance.config.port),
                active_accounts: instance.token_manager.len(),
            }),
            None => Ok(ProxyStatus {
                running: false,
                port: 0,
                base_url: String::new(),
                active_accounts: 0,
            }),
        },
        Err(_) => Ok(ProxyStatus {
            running: false,
            port: 0,
            base_url: "busy".to_string(),
            active_accounts: 0,
        }),
    }
}

pub async fn get_proxy_stats(state: &ProxyServiceState) -> Result<ProxyStats, String> {
    let monitor_lock = state.monitor.read().await;
    if let Some(monitor) = monitor_lock.as_ref() {
        Ok(monitor.get_stats().await)
    } else {
        Ok(ProxyStats::default())
    }
}

pub async fn reload_proxy_accounts(state: &ProxyServiceState) -> Result<usize, String> {
    let instance_lock = state.instance.read().await;

    if let Some(instance) = instance_lock.as_ref() {
        instance.token_manager.clear_all_sessions();
        let count = instance
            .token_manager
            .load_accounts()
            .await
            .map_err(|e| format!("Failed to reload accounts: {}", e))?;
        Ok(count)
    } else {
        Err("Service not running".to_string())
    }
}

pub fn generate_api_key() -> String {
    format!("sk-{}", uuid::Uuid::new_v4().simple())
}

fn join_base_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    format!("{}{}", base, path)
}

fn extract_model_ids(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();

    fn push_from_item(out: &mut Vec<String>, item: &serde_json::Value) {
        match item {
            serde_json::Value::String(s) => out.push(s.to_string()),
            serde_json::Value::Object(map) => {
                if let Some(id) = map.get("id").and_then(|v| v.as_str()) {
                    out.push(id.to_string());
                } else if let Some(name) = map.get("name").and_then(|v| v.as_str()) {
                    out.push(name.to_string());
                }
            }
            _ => {}
        }
    }

    match value {
        serde_json::Value::Array(arr) => {
            for item in arr {
                push_from_item(&mut out, item);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(data) = map.get("data") {
                if let serde_json::Value::Array(arr) = data {
                    for item in arr {
                        push_from_item(&mut out, item);
                    }
                }
            }
            if let Some(models) = map.get("models") {
                match models {
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            push_from_item(&mut out, item);
                        }
                    }
                    other => push_from_item(&mut out, other),
                }
            }
        }
        _ => {}
    }

    out
}

pub async fn fetch_legacy_provider_models(
    config: crate::proxy::LegacyProviderConfig,
    upstream_proxy: crate::proxy::config::UpstreamProxyConfig,
    request_timeout: u64,
) -> Result<Vec<String>, String> {
    if config.base_url.trim().is_empty() {
        return Err("Legacy provider base_url is empty".to_string());
    }
    if config.api_key.trim().is_empty() {
        return Err("Legacy provider api_key is not set".to_string());
    }

    let url = join_base_url(&config.base_url, "/v1/models");

    let mut builder =
        reqwest::Client::builder().timeout(Duration::from_secs(request_timeout.max(5)));
    if !upstream_proxy.custom_proxy_url.is_empty() {
        let proxy = reqwest::Proxy::all(&upstream_proxy.custom_proxy_url)
            .map_err(|e| format!("Invalid upstream proxy url: {}", e))?;
        builder = builder.proxy(proxy);
    }
    let client = builder
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("x-api-key", config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Upstream request failed: {}", e))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        let preview = if text.len() > 4000 {
            &text[..4000]
        } else {
            &text
        };
        return Err(format!("Upstream returned {}: {}", status, preview));
    }

    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("Invalid JSON response: {}", e))?;
    let mut models = extract_model_ids(&json);
    models.retain(|s| !s.trim().is_empty());
    models.sort();
    models.dedup();
    Ok(models)
}
