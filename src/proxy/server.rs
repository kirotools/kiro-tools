use crate::models::AppConfig;
use crate::modules::{account, config, logger, proxy_db, security_db, token_stats};
use crate::proxy::TokenManager;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::oneshot;
use tokio::sync::RwLock;
use tracing::{debug, error};

// [FIX] 全局待重新加载账号队列
// 当 update_account_quota 更新 protected_models 后，将账号 ID 加入此队列
// TokenManager 在 get_token 时会检查并处理这些账号
static PENDING_RELOAD_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();

// [NEW] 全局待删除账号队列 (Issue #1477)
// 当账号被删除后，将账号 ID 加入此队列，TokenManager 在 get_token 时会检查并清理内存缓存
static PENDING_DELETE_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();

fn get_pending_reload_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_RELOAD_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

fn get_pending_delete_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_DELETE_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

/// 触发账号重新加载信号（供 update_account_quota 调用）
pub fn trigger_account_reload(account_id: &str) {
    if let Ok(mut pending) = get_pending_reload_accounts().write() {
        pending.insert(account_id.to_string());
        tracing::debug!(
            "[Quota] Queued account {} for TokenManager reload",
            account_id
        );
    }
}

/// 触发账号删除信号 (Issue #1477)
pub fn trigger_account_delete(account_id: &str) {
    if let Ok(mut pending) = get_pending_delete_accounts().write() {
        pending.insert(account_id.to_string());
        tracing::debug!(
            "[Proxy] Queued account {} for cache removal",
            account_id
        );
    }
}

/// 获取并清空待重新加载的账号列表（供 TokenManager 调用）
pub fn take_pending_reload_accounts() -> Vec<String> {
    if let Ok(mut pending) = get_pending_reload_accounts().write() {
        let accounts: Vec<String> = pending.drain().collect();
        if !accounts.is_empty() {
            tracing::debug!(
                "[Quota] Taking {} pending accounts for reload",
                accounts.len()
            );
        }
        accounts
    } else {
        Vec::new()
    }
}

/// 获取并清空待删除的账号列表 (Issue #1477)
pub fn take_pending_delete_accounts() -> Vec<String> {
    if let Ok(mut pending) = get_pending_delete_accounts().write() {
        let accounts: Vec<String> = pending.drain().collect();
        if !accounts.is_empty() {
            tracing::debug!(
                "[Proxy] Taking {} pending accounts for cache removal",
                accounts.len()
            );
        }
        accounts
    } else {
        Vec::new()
    }
}

/// Axum 应用状态
#[derive(Clone)]
pub struct AppState {
    pub token_manager: Arc<TokenManager>,
    pub custom_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    pub model_cache: Arc<crate::proxy::upstream::model_cache::ModelCache>,
    #[allow(dead_code)]
    pub request_timeout: u64, // API 请求超时(秒)
    #[allow(dead_code)]
    pub thought_signature_map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>, // 思维链签名映射 (ID -> Signature)
    #[allow(dead_code)]
    pub upstream_proxy: Arc<tokio::sync::RwLock<crate::proxy::config::UpstreamProxyConfig>>,
    pub monitor: Arc<crate::proxy::monitor::ProxyMonitor>,
    pub switching: Arc<RwLock<bool>>, // [NEW] 账号切换状态，用于防止并发切换
    pub integration: crate::modules::integration::SystemManager, // [NEW] 系统集成层实现
    pub account_service: Arc<crate::modules::account_service::AccountService>, // [NEW] 账号管理服务层
    pub security: Arc<RwLock<crate::proxy::ProxySecurityConfig>>,              // [NEW] 安全配置状态
    pub cloudflared_state: Arc<crate::commands::cloudflared::CloudflaredState>, // [NEW] Cloudflared 插件状态
    pub is_running: Arc<RwLock<bool>>, // [NEW] 运行状态标识
    pub port: u16,                     // [NEW] 本地监听端口 (v4.0.8 修复)
    pub proxy_pool_state: Arc<tokio::sync::RwLock<crate::proxy::config::ProxyPoolConfig>>, // [FIX Web Mode]
    pub proxy_pool_manager: Arc<crate::proxy::proxy_pool::ProxyPoolManager>, // [FIX Web Mode]
}

// 为 AppState 实现 FromRef，以便中间件提取 security 状态
impl axum::extract::FromRef<AppState> for Arc<RwLock<crate::proxy::ProxySecurityConfig>> {
    fn from_ref(state: &AppState) -> Self {
        state.security.clone()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct AccountResponse {
    id: String,
    email: String,
    name: Option<String>,
    is_current: bool,
    disabled: bool,
    disabled_reason: Option<String>,
    disabled_at: Option<i64>,
    proxy_disabled: bool,
    proxy_disabled_reason: Option<String>,
    proxy_disabled_at: Option<i64>,
    /// [NEW] 403 验证阻止状态
    validation_blocked: bool,
    validation_blocked_until: Option<i64>,
    validation_blocked_reason: Option<String>,
    quota: Option<QuotaResponse>,
    last_used: i64,
    concurrency: Option<ConcurrencyResponse>,
}

#[derive(Serialize)]
struct ConcurrencyResponse {
    max: usize,
    current: usize,
    available: usize,
}

#[derive(Serialize)]
struct QuotaResponse {
    models: Vec<ModelQuota>,
    last_updated: i64,
    subscription_tier: Option<String>,
    is_forbidden: bool,
}

#[derive(Serialize)]
struct ModelQuota {
    name: String,
    percentage: i32,
    reset_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage_limit: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_usage: Option<f64>,
}

#[derive(Serialize)]
struct AccountListResponse {
    accounts: Vec<AccountResponse>,
    current_account_id: Option<String>,
}

fn to_account_response(
    account: &crate::models::account::Account,
    current_id: &Option<String>,
    token_manager: &TokenManager,
) -> AccountResponse {
    let concurrency_info = token_manager.get_account_concurrency_info(&account.id);
    
    AccountResponse {
        id: account.id.clone(),
        email: account.email.clone(),
        name: account.name.clone(),
        is_current: current_id.as_ref() == Some(&account.id),
        disabled: account.disabled,
        disabled_reason: account.disabled_reason.clone(),
        disabled_at: account.disabled_at,
        proxy_disabled: account.proxy_disabled,
        proxy_disabled_reason: account.proxy_disabled_reason.clone(),
        proxy_disabled_at: account.proxy_disabled_at,
        quota: account.quota.as_ref().map(|q| QuotaResponse {
            models: q
                .models
                .iter()
                .map(|m| ModelQuota {
                    name: m.name.clone(),
                    percentage: m.percentage,
                    reset_time: m.reset_time.clone(),
                    usage_limit: m.usage_limit,
                    current_usage: m.current_usage,
                })
                .collect(),
            last_updated: q.last_updated,
            subscription_tier: q.subscription_tier.clone(),
            is_forbidden: q.is_forbidden,
        }),
        last_used: account.last_used,
        validation_blocked: account.validation_blocked,
        validation_blocked_until: account.validation_blocked_until,
        validation_blocked_reason: account.validation_blocked_reason.clone(),
        concurrency: Some(ConcurrencyResponse {
            max: concurrency_info.max_concurrency,
            current: concurrency_info.current_concurrency,
            available: concurrency_info.available_slots,
        }),
    }
}

/// Axum 服务器实例
#[derive(Clone)]
#[allow(dead_code)]
pub struct AxumServer {
    shutdown_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<()>>>>,
    custom_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    proxy_state: Arc<tokio::sync::RwLock<crate::proxy::config::UpstreamProxyConfig>>,
    security_state: Arc<RwLock<crate::proxy::ProxySecurityConfig>>,
    #[allow(dead_code)] // 预留给 cloudflared 运行状态查询与后续控制
    pub cloudflared_state: Arc<crate::commands::cloudflared::CloudflaredState>,
    pub is_running: Arc<RwLock<bool>>,
    pub token_manager: Arc<TokenManager>,
    pub model_cache: Arc<crate::proxy::upstream::model_cache::ModelCache>,
    pub proxy_pool_state: Arc<tokio::sync::RwLock<crate::proxy::config::ProxyPoolConfig>>,
    pub proxy_pool_manager: Arc<crate::proxy::proxy_pool::ProxyPoolManager>,
}

#[allow(dead_code)]
impl AxumServer {
    pub async fn update_mapping(&self, config: &crate::proxy::config::ProxyConfig) {
        {
            let mut m = self.custom_mapping.write().await;
            *m = config.custom_mapping.clone();
        }
        tracing::debug!("模型映射 (Custom) 已全量热更新");
    }

    /// 更新代理配置
    pub async fn update_proxy(&self, new_config: crate::proxy::config::UpstreamProxyConfig) {
        let mut proxy = self.proxy_state.write().await;
        *proxy = new_config;
        tracing::info!("上游代理配置已热更新");
    }

    /// 更新代理池配置
    pub async fn update_proxy_pool(&self, new_config: crate::proxy::config::ProxyPoolConfig) {
        let mut pool = self.proxy_pool_state.write().await;
        *pool = new_config;
        tracing::info!("代理池配置已热更新");
    }

    pub async fn update_security(&self, config: &crate::proxy::config::ProxyConfig) {
        let mut sec = self.security_state.write().await;
        *sec = crate::proxy::ProxySecurityConfig::from_proxy_config(config);
        tracing::info!("反代服务安全配置已热更新");
    }

    pub async fn set_running(&self, running: bool) {
        let mut r = self.is_running.write().await;
        *r = running;
        tracing::info!("反代服务运行状态更新为: {}", running);
    }

    /// 启动 Axum 服务器
    pub async fn start(
        host: String,
        port: u16,
        token_manager: Arc<TokenManager>,
        custom_mapping: std::collections::HashMap<String, String>,
        _request_timeout: u64,
        upstream_proxy: crate::proxy::config::UpstreamProxyConfig,
        _user_agent_override: Option<String>,
        security_config: crate::proxy::ProxySecurityConfig,
        monitor: Arc<crate::proxy::monitor::ProxyMonitor>,

        integration: crate::modules::integration::SystemManager,
        cloudflared_state: Arc<crate::commands::cloudflared::CloudflaredState>,
        proxy_pool_config: crate::proxy::config::ProxyPoolConfig, // [NEW]
    ) -> Result<(Self, tokio::task::JoinHandle<()>), String> {
        let custom_mapping_state = Arc::new(tokio::sync::RwLock::new(custom_mapping));
        let proxy_state = Arc::new(tokio::sync::RwLock::new(upstream_proxy.clone()));
        let proxy_pool_state = Arc::new(tokio::sync::RwLock::new(proxy_pool_config));
        let proxy_pool_manager = crate::proxy::proxy_pool::init_global_proxy_pool(proxy_pool_state.clone());
    
    // Start health check loop
    proxy_pool_manager.clone().start_health_check_loop();
        let security_state = Arc::new(RwLock::new(security_config));
        let is_running_state = Arc::new(RwLock::new(true));
        let model_cache = Arc::new(crate::proxy::upstream::model_cache::ModelCache::new(
            std::time::Duration::from_secs(300),
        ));

        let state = AppState {
            token_manager: token_manager.clone(),
            custom_mapping: custom_mapping_state.clone(),
            model_cache: model_cache.clone(),
            request_timeout: 300, // 5分钟超时
            thought_signature_map: Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            upstream_proxy: proxy_state.clone(),
            monitor: monitor.clone(),
            switching: Arc::new(RwLock::new(false)),
            integration: integration.clone(),
            account_service: Arc::new(crate::modules::account_service::AccountService::new(
                integration.clone(),
            )),
            security: security_state.clone(),
            cloudflared_state: cloudflared_state.clone(),
            is_running: is_running_state.clone(),
            port,
            proxy_pool_state: proxy_pool_state.clone(),
            proxy_pool_manager: proxy_pool_manager.clone(),
        };

        // 构建路由 - 使用新架构的 handlers！
        use crate::proxy::handlers;
        use crate::proxy::middleware::{
            auth_middleware, cors_layer, ip_filter_middleware,
            monitor_middleware, service_status_middleware,
        };

        // 1. 构建主 AI 代理路由 (遵循 auth_mode 配置)
        let proxy_routes = Router::new()
            .route("/health", get(health_check_handler))
            .route("/healthz", get(health_check_handler))
            // Anthropic Protocol (Kiro)
            .route("/v1/messages", post(handlers::claude::handle_messages))
            .route(
                "/v1/messages/count_tokens",
                post(handlers::claude::handle_count_tokens),
            )
            .route(
                "/v1/models",
                get(handlers::claude::handle_list_models),
            )
            .route("/v1/api/event_logging/batch", post(silent_ok_handler))
            .route("/v1/api/event_logging", post(silent_ok_handler))
            // 应用 AI 服务特定的层
            // 注意：Axum layer 执行顺序是从下往上（洋葱模型）
            // 请求: ip_filter -> auth -> monitor -> handler
            // 响应: handler -> monitor -> auth -> ip_filter
            // monitor 需要在 auth 之后执行才能获取 UserTokenIdentity
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                monitor_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                ip_filter_middleware,
            ));

        // 2. 构建管理 API (强制鉴权)
        let admin_routes = Router::new()
            .route("/health", get(health_check_handler))
            .route(
                "/accounts",
                get(admin_list_accounts).post(admin_add_account),
            )
            .route("/accounts/current", get(admin_get_current_account))
            .route("/accounts/switch", post(admin_switch_account))
            .route("/accounts/refresh", post(admin_refresh_all_quotas))
            .route("/accounts/:accountId", delete(admin_delete_account))
            .route("/stats/summary", get(admin_get_token_stats_summary))
            .route("/stats/hourly", get(admin_get_token_stats_hourly))
            .route("/stats/daily", get(admin_get_token_stats_daily))
            .route("/stats/weekly", get(admin_get_token_stats_weekly))
            .route("/stats/accounts", get(admin_get_token_stats_by_account))
            .route("/stats/models", get(admin_get_token_stats_by_model))
            .route("/config", get(admin_get_config).post(admin_save_config))
            .route("/proxy/opencode/status", post(admin_get_opencode_sync_status))
            .route("/proxy/opencode/sync", post(admin_execute_opencode_sync))
            .route("/proxy/opencode/restore", post(admin_execute_opencode_restore))
            .route("/proxy/opencode/config", post(admin_get_opencode_config_content))
            .route("/proxy/kiro/quota", post(admin_get_kiro_quota))
            .route("/proxy/status", get(admin_get_proxy_status))
            .route("/proxy/pool/config", get(admin_get_proxy_pool_config))
            .route("/proxy/pool/bindings", get(admin_get_all_account_bindings))
            .route("/proxy/pool/bind", post(admin_bind_account_proxy))
            .route("/proxy/pool/unbind", post(admin_unbind_account_proxy))
            .route("/proxy/pool/binding/:accountId", get(admin_get_account_proxy_binding))
            .route("/proxy/health-check/trigger", post(admin_trigger_proxy_health_check))
            .route("/proxy/start", post(admin_start_proxy_service))
            .route("/proxy/stop", post(admin_stop_proxy_service))
            .route("/proxy/mapping", post(admin_update_model_mapping))
            .route("/proxy/models", get(admin_list_proxy_models))
            .route("/proxy/api-key/generate", post(admin_generate_api_key))
            .route(
                "/proxy/session-bindings/clear",
                post(admin_clear_proxy_session_bindings),
            )
            .route("/proxy/rate-limits", delete(admin_clear_all_rate_limits))
            .route(
                "/proxy/rate-limits/:accountId",
                delete(admin_clear_rate_limit),
            )
            .route(
                "/proxy/preferred-account",
                get(admin_get_preferred_account).post(admin_set_preferred_account),
            )
            .route(
                "/proxy/monitor/toggle",
                post(admin_set_proxy_monitor_enabled),
            )
            .route(
                "/proxy/cloudflared/status",
                get(admin_cloudflared_get_status),
            )
            .route(
                "/proxy/cloudflared/install",
                post(admin_cloudflared_install),
            )
            .route("/proxy/cloudflared/start", post(admin_cloudflared_start))
            .route("/proxy/cloudflared/stop", post(admin_cloudflared_stop))
            .route("/system/open-folder", post(admin_open_folder))
            .route("/proxy/stats", get(admin_get_proxy_stats))
            .route("/logs", get(admin_get_proxy_logs_filtered))
            .route("/logs/count", get(admin_get_proxy_logs_count_filtered))
            .route("/logs/clear", post(admin_clear_proxy_logs))
            .route("/logs/:logId", get(admin_get_proxy_log_detail))
            // Debug Console (Log Bridge)
            .route("/debug/enable", post(admin_enable_debug_console))
            .route("/debug/disable", post(admin_disable_debug_console))
            .route("/debug/enabled", get(admin_is_debug_console_enabled))
            .route("/debug/logs", get(admin_get_debug_console_logs))
            .route("/debug/logs/clear", post(admin_clear_debug_console_logs))
            .route("/stats/token/clear", post(admin_clear_token_stats))
            .route("/stats/token/hourly", get(admin_get_token_stats_hourly))
            .route("/stats/token/daily", get(admin_get_token_stats_daily))
            .route("/stats/token/weekly", get(admin_get_token_stats_weekly))
            .route(
                "/stats/token/by-account",
                get(admin_get_token_stats_by_account),
            )
            .route("/stats/token/summary", get(admin_get_token_stats_summary))
            .route("/stats/token/by-model", get(admin_get_token_stats_by_model))
            .route(
                "/stats/token/model-trend/hourly",
                get(admin_get_token_stats_model_trend_hourly),
            )
            .route(
                "/stats/token/model-trend/daily",
                get(admin_get_token_stats_model_trend_daily),
            )
            .route(
                "/stats/token/account-trend/hourly",
                get(admin_get_token_stats_account_trend_hourly),
            )
            .route(
                "/stats/token/account-trend/daily",
                get(admin_get_token_stats_account_trend_daily),
            )
            // User Tokens
            .route("/user-tokens", get(admin_list_user_tokens).post(admin_create_user_token))
            .route("/user-tokens/summary", get(admin_get_user_token_summary))
            .route("/user-tokens/:id/renew", post(admin_renew_user_token))
            .route("/user-tokens/:id", delete(admin_delete_user_token).patch(admin_update_user_token))
            // Security / IP Management
            .route("/security/logs", get(admin_get_ip_access_logs))
            .route("/security/logs/clear", post(admin_clear_ip_access_logs))
            .route("/security/stats", get(admin_get_ip_stats))
            .route("/security/token-stats", get(admin_get_ip_token_stats))
            .route("/security/blacklist", get(admin_get_ip_blacklist).post(admin_add_ip_to_blacklist).delete(admin_remove_ip_from_blacklist))
            .route("/security/blacklist/clear", post(admin_clear_ip_blacklist))
            .route("/security/blacklist/check", get(admin_check_ip_in_blacklist))
            .route("/security/whitelist", get(admin_get_ip_whitelist).post(admin_add_ip_to_whitelist).delete(admin_remove_ip_from_whitelist))
            .route("/security/whitelist/clear", post(admin_clear_ip_whitelist))
            .route("/security/whitelist/check", get(admin_check_ip_in_whitelist))
            .route("/security/config", get(admin_get_security_config).post(admin_update_security_config))
            // Additional Account Routes
            .route("/accounts/bulk-delete", post(admin_delete_accounts))
            .route("/accounts/reorder", post(admin_reorder_accounts))
            .route("/accounts/export", post(admin_export_accounts))
            .route("/accounts/:accountId/toggle-proxy", post(admin_toggle_proxy_status))
            .route("/accounts/:accountId/quota", get(admin_fetch_account_quota))
            // System
            .route("/system/data-dir", get(admin_get_data_dir_path))
            .route("/system/updates/settings", get(admin_get_update_settings))
            .route("/system/updates/save", post(admin_save_update_settings))
            .route("/system/updates/check-status", get(admin_should_check_updates))
            .route("/system/updates/check", post(admin_check_for_updates))
            .route("/system/updates/touch", post(admin_update_last_check_time))
            .route("/system/http-api/settings", get(admin_get_http_api_settings).post(admin_save_http_api_settings))
            .route("/system/cache/clear", post(admin_clear_kiro_cache))
            .route("/system/cache/paths", get(admin_get_kiro_cache_paths))
            .route("/system/logs/clear-cache", post(admin_clear_log_cache))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::proxy::middleware::auth::admin_auth_middleware,
            ));

        // 3. 整合并应用全局层
        // 从环境变量读取 body 大小限制，默认 50MB
        let max_body_size: usize = std::env::var("KIRO_MAX_BODY_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024); // 默认 100MB
        tracing::info!("请求体大小限制: {} MB", max_body_size / 1024 / 1024);

        let app = Router::new()
            .nest("/api", admin_routes)
            .merge(proxy_routes)
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                service_status_middleware,
            ))
            .layer(cors_layer())
            .layer(DefaultBodyLimit::max(max_body_size)) // 放宽 body 大小限制
            .with_state(state.clone());

        // 静态文件托管 (用于 Headless/Docker 模式)
        let dist_path = std::env::var("KIRO_DIST_PATH").unwrap_or_else(|_| "dist".to_string());
        let app = if std::path::Path::new(&dist_path).exists() {
            tracing::info!("正在托管静态资源: {}", dist_path);
            app.fallback_service(tower_http::services::ServeDir::new(&dist_path).fallback(
                tower_http::services::ServeFile::new(format!("{}/index.html", dist_path)),
            ))
        } else {
            app
        };

        // 绑定地址
        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("地址 {} 绑定失败: {}", addr, e))?;

        tracing::info!("反代服务器启动在 http://{}", addr);

        // 创建关闭通道
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let server_instance = Self {
            shutdown_tx: Arc::new(tokio::sync::Mutex::new(Some(shutdown_tx))),
            custom_mapping: custom_mapping_state.clone(),
            proxy_state,
            security_state,
            cloudflared_state,
            is_running: is_running_state,
            token_manager: token_manager.clone(),
            model_cache,
            proxy_pool_state,
            proxy_pool_manager,
        };

        // 在新任务中启动服务器
        let handle = tokio::spawn(async move {
            use hyper::server::conn::http1;
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;

            loop {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((stream, remote_addr)) => {
                                let io = TokioIo::new(stream);
                                
                                // 注入 ConnectInfo (用于获取真实 IP)
                                use tower::ServiceExt;
                                use hyper::body::Incoming;
                                let app_with_info = app.clone().map_request(move |mut req: axum::http::Request<Incoming>| {
                                    req.extensions_mut().insert(axum::extract::ConnectInfo(remote_addr));
                                    req
                                });

                                let service = TowerToHyperService::new(app_with_info);

                                tokio::task::spawn(async move {
                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .with_upgrades() // 支持 WebSocket (如果以后需要)
                                        .await
                                    {
                                        debug!("连接处理结束或出错: {:?}", err);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("接收连接失败: {:?}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        tracing::info!("反代服务器停止监听");
                        break;
                    }
                }
            }
        });

        Ok((server_instance, handle))
    }

    /// 停止服务器
    pub fn stop(&self) {
        let tx_mutex = self.shutdown_tx.clone();
        tokio::spawn(async move {
            let mut lock = tx_mutex.lock().await;
            if let Some(tx) = lock.take() {
                let _ = tx.send(());
                tracing::info!("Axum server 停止信号已发送");
            }
        });
    }
}

// ===== API 处理器 (旧代码已移除，由 src/proxy/handlers/* 接管) =====

/// 健康检查处理器
async fn health_check_handler() -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
    .into_response()
}

/// 静默成功处理器 (用于拦截遥测日志等)
async fn silent_ok_handler() -> Response {
    StatusCode::OK.into_response()
}

// ============================================================================
// [PHASE 1] 整合后的 Admin Handlers
// ============================================================================

// [整合清理] 旧模型定义与映射器已上移

async fn admin_list_accounts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let accounts = state.account_service.list_accounts().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let current_id = state.account_service.get_current_id().ok().flatten();

    let account_responses: Vec<AccountResponse> = accounts
        .into_iter()
        .map(|acc| {
            to_account_response(&acc, &current_id, &state.token_manager)
        })
        .collect();

    Ok(Json(AccountListResponse {
        current_account_id: current_id,
        accounts: account_responses,
    }))
}

/// Export accounts with refresh tokens (for backup/migration)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportAccountsRequest {
    account_ids: Vec<String>,
}

async fn admin_export_accounts(
    State(_state): State<AppState>,
    Json(payload): Json<ExportAccountsRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let response = account::export_accounts_by_ids(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(response))
}

async fn admin_get_current_account(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let response = if let Some(id) = current_id {
        let acc = account::load_account(&id).ok();
        acc.map(|acc| {
            to_account_response(&acc, &Some(id), &state.token_manager)
        })
    } else {
        None
    };

    Ok(Json(response))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddAccountRequest {
    refresh_token: Option<String>,
    creds_file: Option<String>,
    sqlite_db: Option<String>,
}

async fn admin_add_account(
    State(state): State<AppState>,
    Json(payload): Json<AddAccountRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = state
        .account_service
        .add_account(
            payload.refresh_token.as_deref(),
            payload.creds_file.as_deref(),
            payload.sqlite_db.as_deref(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    // [FIX #1166] 账号变动后立即重新加载 TokenManager
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after adding: {}",
            e
        ));
    }

    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id, &state.token_manager)))
}

async fn admin_delete_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .account_service
        .delete_account(&account_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    // [FIX #1166] 账号变动后立即重新加载 TokenManager
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after deletion: {}",
            e
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwitchRequest {
    account_id: String,
}

async fn admin_switch_account(
    State(state): State<AppState>,
    Json(payload): Json<SwitchRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    {
        let switching = state.switching.read().await;
        if *switching {
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Another switch operation is already in progress".to_string(),
                }),
            ));
        }
    }

    {
        let mut switching = state.switching.write().await;
        *switching = true;
    }

    let account_id = payload.account_id.clone();
    logger::log_info(&format!("[API] Starting account switch: {}", account_id));

    let result = state.account_service.switch_account(&account_id).await;

    {
        let mut switching = state.switching.write().await;
        *switching = false;
    }

    match result {
        Ok(()) => {
            logger::log_info(&format!("[API] Account switch successful: {}", account_id));

            // [FIX #1166] 账号切换后立即同步内存状态
            state.token_manager.clear_all_sessions();
            if let Err(e) = state.token_manager.load_accounts().await {
                logger::log_error(&format!(
                    "[API] Failed to reload accounts after switch: {}",
                    e
                ));
            }

            Ok(StatusCode::OK)
        }
        Err(e) => {
            logger::log_error(&format!("[API] Account switch failed: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            ))
        }
    }
}

async fn admin_refresh_all_quotas() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)>
{
    logger::log_info("[API] Starting refresh of all account quotas");
    let stats = account::refresh_all_quotas_logic().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(stats))
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // 预留日志接口结构体
struct LogsRequest {
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    filter: String,
    #[serde(default)]
    errors_only: bool,
}

#[allow(dead_code)] // 预留日志接口
async fn admin_get_logs(
    Query(params): Query<LogsRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let limit = if params.limit == 0 { 50 } else { params.limit };
    let total =
        proxy_db::get_logs_count_filtered(&params.filter, params.errors_only).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    let logs =
        proxy_db::get_logs_filtered(&params.filter, params.errors_only, limit, params.offset)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: e }),
                )
            })?;

    Ok(Json(serde_json::json!({
        "total": total,
        "logs": logs,
    })))
}

async fn admin_get_config() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let cfg = config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(cfg))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveConfigWrapper {
    config: AppConfig,
}

async fn admin_save_config(
    State(state): State<AppState>,
    Json(payload): Json<SaveConfigWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let new_config = payload.config;
    // 1. 持久化
    config::save_app_config(&new_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // 2. 热更新内存状态
    // 这里我们直接复用内部组件的 update 方法
    // 注意：AppState 本身持有各个组件的 Arc<RwLock> 或直接持有引用

    // 我们需要一个方式获取到当前的 AxumServer 实例来进行热更新，
    // 或者直接操作 AppState 里的各状态。
    // 在本重构中，各个状态已经在 AppState 中了。

    // 更新模型映射
    {
        let mut mapping = state.custom_mapping.write().await;
        *mapping = new_config.clone().proxy.custom_mapping;
    }

    // 更新上游代理
    {
        let mut proxy = state.upstream_proxy.write().await;
        *proxy = new_config.clone().proxy.upstream_proxy;
    }

    // 更新安全策略
    {
        let mut security = state.security.write().await;
        *security = crate::proxy::ProxySecurityConfig::from_proxy_config(&new_config.proxy);
    }

    {
        let mut pool = state.proxy_pool_state.write().await;
        *pool = new_config.clone().proxy.proxy_pool;
    }

    state.token_manager.set_max_concurrency(new_config.proxy.max_concurrency_per_account);

    Ok(StatusCode::OK)
}

// [FIX Web Mode] Get proxy pool config
async fn admin_get_proxy_pool_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = state.proxy_pool_state.read().await;
    Ok(Json(config.clone()))
}

// [FIX Web Mode] Get all account proxy bindings
async fn admin_get_all_account_bindings(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let bindings = state.proxy_pool_manager.get_all_bindings_snapshot();
    Ok(Json(bindings))
}

// [FIX Web Mode] Bind account to proxy
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindAccountProxyRequest {
    account_id: String,
    proxy_id: String,
}

async fn admin_bind_account_proxy(
    State(state): State<AppState>,
    Json(payload): Json<BindAccountProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.proxy_pool_manager
        .bind_account_to_proxy(payload.account_id, payload.proxy_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(StatusCode::OK)
}

// [FIX Web Mode] Unbind account from proxy
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnbindAccountProxyRequest {
    account_id: String,
}

async fn admin_unbind_account_proxy(
    State(state): State<AppState>,
    Json(payload): Json<UnbindAccountProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.proxy_pool_manager.unbind_account_proxy(payload.account_id).await;
    Ok(StatusCode::OK)
}

// [FIX Web Mode] Get account proxy binding
async fn admin_get_account_proxy_binding(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let binding = state.proxy_pool_manager.get_account_binding(&account_id);
    Ok(Json(binding))
}

// [FIX Web Mode] Trigger proxy pool health check
async fn admin_trigger_proxy_health_check(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.proxy_pool_manager.health_check().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // 返回更新后的代理池配置（包含健康状态）
    let config = state.proxy_pool_state.read().await;
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Health check completed",
        "proxies": config.proxies,
    })))
}

async fn admin_list_proxy_models(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let models = crate::proxy::common::model_mapping::get_all_models_with_metadata(&state.model_cache, &state.custom_mapping).await;
    Json(serde_json::json!({ "models": models }))
}

async fn admin_get_proxy_status(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // 在 Headless/Axum 模式下，AxumServer 既然在运行，通常就是 running
    let active_accounts = state.token_manager.len();

    let is_running = { *state.is_running.read().await };
    Ok(Json(serde_json::json!({
        "running": is_running,
        "port": state.port,
        "base_url": format!("http://127.0.0.1:{}", state.port),
        "active_accounts": active_accounts,
    })))
}

async fn admin_start_proxy_service(State(state): State<AppState>) -> impl IntoResponse {
    // 1. 持久化配置 (修复 #1166)
    if let Ok(mut config) = crate::modules::config::load_app_config() {
        config.proxy.auto_start = true;
        let _ = crate::modules::config::save_app_config(&config);
    }

    // 2. 确保账号已加载 (如果是第一次启动)
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!("[API] 启用服务并加载账号失败: {}", e));
    }

    let mut running = state.is_running.write().await;
    *running = true;
    logger::log_info("[API] 反代服务功能已启用 (持久化已同步)");
    StatusCode::OK
}

async fn admin_stop_proxy_service(State(state): State<AppState>) -> impl IntoResponse {
    // 1. 持久化配置 (修复 #1166)
    if let Ok(mut config) = crate::modules::config::load_app_config() {
        config.proxy.auto_start = false;
        let _ = crate::modules::config::save_app_config(&config);
    }

    let mut running = state.is_running.write().await;
    *running = false;
    logger::log_info("[API] 反代服务功能已禁用 (Axum 模式 / 持久化已同步)");
    StatusCode::OK
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateMappingWrapper {
    config: crate::proxy::config::ProxyConfig,
}

async fn admin_update_model_mapping(
    State(state): State<AppState>,
    Json(payload): Json<UpdateMappingWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = payload.config;

    // 1. 更新内存状态 (热更新)
    {
        let mut mapping = state.custom_mapping.write().await;
        *mapping = config.custom_mapping.clone();
    }

    // 2. 持久化到硬盘 (修复 #1149)
    // 加载当前配置，更新 mapping，然后保存
    let mut app_config = crate::modules::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    app_config.proxy.custom_mapping = config.custom_mapping;

    crate::modules::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    logger::log_info("[API] 模型映射已通过 API 热更新并保存");
    Ok(StatusCode::OK)
}

async fn admin_generate_api_key() -> impl IntoResponse {
    let new_key = format!("sk-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    Json(new_key)
}

async fn admin_clear_proxy_session_bindings(State(state): State<AppState>) -> impl IntoResponse {
    state.token_manager.clear_all_sessions();
    logger::log_info("[API] 已清除所有会话绑定");
    StatusCode::OK
}

async fn admin_clear_all_rate_limits(State(state): State<AppState>) -> impl IntoResponse {
    state.token_manager.clear_all_rate_limits();
    logger::log_info("[API] 已清除所有限流记录");
    StatusCode::OK
}

async fn admin_clear_rate_limit(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let cleared = state.token_manager.clear_rate_limit(&account_id);
    if cleared {
        logger::log_info(&format!("[API] 已清除账号 {} 的限流记录", account_id));
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn admin_get_preferred_account(State(state): State<AppState>) -> impl IntoResponse {
    let pref = state.token_manager.get_preferred_account().await;
    Json(pref)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetPreferredAccountRequest {
    account_id: Option<String>,
}

async fn admin_set_preferred_account(
    State(state): State<AppState>,
    Json(payload): Json<SetPreferredAccountRequest>,
) -> impl IntoResponse {
    state
        .token_manager
        .set_preferred_account(payload.account_id)
        .await;
    StatusCode::OK
}

async fn admin_set_proxy_monitor_enabled(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let enabled = payload
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // [FIX #1269] 只有在状态真正改变时才记录日志并设置，避免重复触发导致的"重启"错觉
    if state.monitor.is_enabled() != enabled {
        state.monitor.set_enabled(enabled);
        logger::log_info(&format!("[API] 监控状态已设置为: {}", enabled));
    }

    StatusCode::OK
}

async fn admin_get_proxy_logs_count_filtered(
    Query(params): Query<LogsRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(move || {
        proxy_db::get_logs_count_filtered(&params.filter, params.errors_only)
    })
    .await;

    match res {
        Ok(Ok(count)) => Ok(Json(count)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_clear_proxy_logs() -> impl IntoResponse {
    let _ = tokio::task::spawn_blocking(|| {
        if let Err(e) = proxy_db::clear_logs() {
            logger::log_error(&format!("[API] 清除反代日志失败: {}", e));
        }
    })
    .await;
    logger::log_info("[API] 已清除所有反代日志");
    StatusCode::OK
}

async fn admin_get_proxy_log_detail(
    Path(log_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res =
        tokio::task::spawn_blocking(move || crate::modules::proxy_db::get_log_detail(&log_id))
            .await;

    match res {
        Ok(Ok(log)) => Ok(Json(log)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct LogsFilterQuery {
    #[serde(default)]
    filter: String,
    #[serde(default)]
    errors_only: bool,
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn admin_get_proxy_logs_filtered(
    Query(params): Query<LogsFilterQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(move || {
        crate::modules::proxy_db::get_logs_filtered(
            &params.filter,
            params.errors_only,
            params.limit,
            params.offset,
        )
    })
    .await;

    match res {
        Ok(Ok(logs)) => Ok(Json(logs)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_proxy_stats(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = state.monitor.get_stats().await;
    Ok(Json(stats))
}

async fn admin_get_data_dir_path() -> impl IntoResponse {
    match crate::modules::account::get_data_dir() {
        Ok(p) => Json(p.to_string_lossy().to_string()),
        Err(e) => Json(format!("Error: {}", e)),
    }
}

// --- User Token Handlers ---

async fn admin_list_user_tokens() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let tokens = crate::commands::user_token::list_user_tokens().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(tokens))
}

async fn admin_get_user_token_summary() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let summary = crate::commands::user_token::get_user_token_summary().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(summary))
}

async fn admin_create_user_token(
    Json(payload): Json<crate::commands::user_token::CreateTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let token = crate::commands::user_token::create_user_token(payload).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(token))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenewTokenRequest {
    expires_type: String,
}

async fn admin_renew_user_token(
    Path(id): Path<String>,
    Json(payload): Json<RenewTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::renew_user_token(id, payload.expires_type).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

async fn admin_delete_user_token(
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::delete_user_token(id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_update_user_token(
    Path(id): Path<String>,
    Json(payload): Json<crate::commands::user_token::UpdateTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::update_user_token(id, payload).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

async fn admin_should_check_updates() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)>
{
    let settings = crate::modules::update_checker::load_update_settings().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let should = crate::modules::update_checker::should_check_for_updates(&settings);
    Ok(Json(should))
}

async fn admin_clear_kiro_cache(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = crate::commands::clear_kiro_cache().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(res))
}

async fn admin_get_kiro_cache_paths(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = crate::commands::get_kiro_cache_paths()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(res))
}

async fn admin_clear_log_cache() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::clear_log_cache().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

// Token Stats Handlers
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct StatsPeriodQuery {
    hours: Option<i64>,
    days: Option<i64>,
    weeks: Option<i64>,
}

async fn admin_get_token_stats_hourly(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(24);
    let res = tokio::task::spawn_blocking(move || token_stats::get_hourly_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_daily(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let days = p.days.unwrap_or(7);
    let res = tokio::task::spawn_blocking(move || token_stats::get_daily_stats(days)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_weekly(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let weeks = p.weeks.unwrap_or(4);
    let res = tokio::task::spawn_blocking(move || token_stats::get_weekly_stats(weeks)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_by_account(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(168);
    let res = tokio::task::spawn_blocking(move || token_stats::get_account_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_summary(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(168);
    let res = tokio::task::spawn_blocking(move || token_stats::get_summary_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_by_model(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(168);
    let res = tokio::task::spawn_blocking(move || token_stats::get_model_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_model_trend_hourly(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_model_trend_hourly(24) // Default 24 hours
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_model_trend_daily(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_model_trend_daily(7) // Default 7 days
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_account_trend_hourly(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_account_trend_hourly(24) // Default 24 hours
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_account_trend_daily(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_account_trend_daily(7) // Default 7 days
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_clear_token_stats() -> impl IntoResponse {
    let res = tokio::task::spawn_blocking(|| {
        // Clear databases (brute force)
        if let Ok(path) = token_stats::get_db_path() {
            let _ = std::fs::remove_file(path);
        }
        let _ = token_stats::init_db();
    })
    .await;

    match res {
        Ok(_) => {
            logger::log_info("[API] 已清除所有 Token 统计数据");
            StatusCode::OK
        }
        Err(e) => {
            logger::log_error(&format!("[API] 清除 Token 统计数据失败: {}", e));
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn admin_get_update_settings() -> impl IntoResponse {
    // 從真實模組加載設置
    match crate::modules::update_checker::load_update_settings() {
        Ok(s) => Json(serde_json::to_value(s).unwrap_or_default()),
        Err(_) => Json(serde_json::json!({
            "auto_check": true,
            "last_check_time": 0,
            "check_interval_hours": 24
        })),
    }
}

async fn admin_check_for_updates() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let info = crate::modules::update_checker::check_for_updates()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(info))
}

async fn admin_update_last_check_time(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::update_checker::update_last_check_time().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

async fn admin_save_update_settings(Json(settings): Json<serde_json::Value>) -> impl IntoResponse {
    if let Ok(s) =
        serde_json::from_value::<crate::modules::update_checker::UpdateSettings>(settings)
    {
        let _ = crate::modules::update_checker::save_update_settings(&s);
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    }
}

async fn admin_get_http_api_settings() -> impl IntoResponse {
    Json(serde_json::json!({ "enabled": true, "port": 8045 }))
}

// [整合清理] 冗餘導入已移除

#[derive(Deserialize)]
struct BulkDeleteRequest {
    #[serde(rename = "accountIds")]
    account_ids: Vec<String>,
}

async fn admin_delete_accounts(
    Json(payload): Json<BulkDeleteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::account::delete_accounts(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReorderRequest {
    account_ids: Vec<String>,
}

async fn admin_reorder_accounts(
    State(state): State<AppState>,
    Json(payload): Json<ReorderRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::account::reorder_accounts(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // [FIX #1166] 排序变动后立即重新加载 TokenManager
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after reorder: {}",
            e
        ));
    }

    Ok(StatusCode::OK)
}

async fn admin_fetch_account_quota(
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut account = crate::modules::load_account(&account_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let quota = crate::modules::account::fetch_quota_with_retry(&mut account)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    crate::modules::update_account_quota(&account_id, quota.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(quota))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToggleProxyRequest {
    enable: bool,
    reason: Option<String>,
}

async fn admin_toggle_proxy_status(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(payload): Json<ToggleProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::account::toggle_proxy_status(
        &account_id,
        payload.enable,
        payload.reason.as_deref(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // 同步到运行中的反代服务
    let _ = state.token_manager.reload_account(&account_id).await;

    Ok(StatusCode::OK)
}



async fn admin_get_kiro_quota() -> impl IntoResponse {
    let accounts = crate::modules::account::list_accounts().unwrap_or_default();
    let mut results = Vec::new();
    for account in &accounts {
        if account.disabled {
            continue;
        }
        let token_result = crate::modules::quota::get_valid_token_for_account(account).await;
        match token_result {
            Ok((access_token, _)) => {
                match crate::modules::quota::fetch_quota(&access_token, &account.email, Some(&account.id)).await {
                    Ok((quota, _)) => results.push(serde_json::json!({
                        "account_id": account.id,
                        "email": account.email,
                        "quota": quota,
                    })),
                    Err(e) => results.push(serde_json::json!({
                        "account_id": account.id,
                        "email": account.email,
                        "error": e.to_string(),
                    })),
                }
            }
            Err(e) => results.push(serde_json::json!({
                "account_id": account.id,
                "email": account.email,
                "error": e,
            })),
        }
    }
    Json(serde_json::json!({ "accounts": results }))
}

async fn admin_save_http_api_settings(
    Json(payload): Json<crate::modules::http_api::HttpApiSettings>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::http_api::save_settings(&payload).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

// Cloudflared Handlers
async fn admin_cloudflared_get_status(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .cloudflared_state
        .ensure_manager()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    let lock = state.cloudflared_state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        let (installed, version) = manager.check_installed().await;
        let mut status = manager.get_status().await;
        status.installed = installed;
        status.version = version;
        if !installed {
            status.running = false;
            status.url = None;
        }
        Ok(Json(status))
    } else {
        Ok(Json(
            crate::modules::cloudflared::CloudflaredStatus::default(),
        ))
    }
}

async fn admin_cloudflared_install(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .cloudflared_state
        .ensure_manager()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    let lock = state.cloudflared_state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        let status = manager.install().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
        Ok(Json(status))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Manager not initialized".to_string(),
            }),
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudflaredStartRequest {
    config: crate::modules::cloudflared::CloudflaredConfig,
}

async fn admin_cloudflared_start(
    State(state): State<AppState>,
    Json(payload): Json<CloudflaredStartRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .cloudflared_state
        .ensure_manager()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    let lock = state.cloudflared_state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        let status = manager.start(payload.config).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
        Ok(Json(status))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Manager not initialized".to_string(),
            }),
        ))
    }
}

async fn admin_cloudflared_stop(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .cloudflared_state
        .ensure_manager()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    let lock = state.cloudflared_state.manager.read().await;
    if let Some(manager) = lock.as_ref() {
        let status = manager.stop().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
        Ok(Json(status))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Manager not initialized".to_string(),
            }),
        ))
    }
}

// --- Supplementary Account Handlers ---

async fn admin_open_folder() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Note: In Web mode, this may not actually open a local folder unless the backend handles it.
    // For headless mode, the backend should use opener to open it on the server (the desktop).
    crate::commands::open_data_folder().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

// ============================================================================
// Security / IP Management Handlers
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpAccessLogQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_page_size")]
    page_size: usize,
    search: Option<String>,
    #[serde(default)]
    blocked_only: bool,
}

fn default_page() -> usize { 1 }
fn default_page_size() -> usize { 50 }

#[derive(Serialize)]
struct IpAccessLogResponse {
    logs: Vec<crate::modules::security_db::IpAccessLog>,
    total: usize,
}

async fn admin_get_ip_access_logs(
    Query(q): Query<IpAccessLogQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let offset = (q.page.max(1) - 1) * q.page_size;
    let logs = security_db::get_ip_access_logs(
        q.page_size,
        offset,
        q.search.as_deref(),
        q.blocked_only,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    let total = logs.len(); // Simple total
    
    Ok(Json(IpAccessLogResponse { logs, total }))
}

async fn admin_clear_ip_access_logs() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::clear_ip_access_logs()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(StatusCode::OK)
}

#[derive(Serialize)]
struct IpStatsResponse {
    total_requests: usize,
    unique_ips: usize,
    blocked_requests: usize,
    top_ips: Vec<crate::modules::security_db::IpRanking>,
}

async fn admin_get_ip_stats() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = security_db::get_ip_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    let top_ips = security_db::get_top_ips(10, 24)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    let response = IpStatsResponse {
        total_requests: stats.total_requests as usize,
        unique_ips: stats.unique_ips as usize,
        blocked_requests: stats.blocked_count as usize,
        top_ips,
    };
    Ok(Json(response))
}

#[derive(Deserialize)]
struct IpTokenStatsQuery {
    limit: Option<usize>,
    hours: Option<i64>,
}

async fn admin_get_ip_token_stats(
    Query(q): Query<IpTokenStatsQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = proxy_db::get_token_usage_by_ip(
        q.limit.unwrap_or(100),
        q.hours.unwrap_or(720)
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(stats))
}

async fn admin_get_ip_blacklist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let list = security_db::get_blacklist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(list))
}

#[derive(Deserialize)]
struct AddBlacklistRequest {
    ip_pattern: String,
    reason: Option<String>,
    expires_at: Option<i64>,
}

async fn admin_add_ip_to_blacklist(
    Json(req): Json<AddBlacklistRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::add_to_blacklist(
        &req.ip_pattern,
        req.reason.as_deref(),
        req.expires_at,
        "manual",
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct RemoveIpRequest {
    ip_pattern: String,
}

async fn admin_remove_ip_from_blacklist(
    Query(q): Query<RemoveIpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_blacklist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    
    if let Some(entry) = entries.iter().find(|e| e.ip_pattern == q.ip_pattern) {
        security_db::remove_from_blacklist(&entry.id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    } else {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("IP pattern {} not found", q.ip_pattern) })));
    }
    
    Ok(StatusCode::OK)
}

async fn admin_clear_ip_blacklist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_blacklist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    for entry in entries {
        security_db::remove_from_blacklist(&entry.id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckIpQuery {
    ip: String,
}

async fn admin_check_ip_in_blacklist(
    Query(q): Query<CheckIpQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = security_db::is_ip_in_blacklist(&q.ip)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(serde_json::json!({ "result": result })))
}

async fn admin_get_ip_whitelist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let list = security_db::get_whitelist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(list))
}

#[derive(Deserialize)]
struct AddWhitelistRequest {
    ip_pattern: String,
    description: Option<String>,
}

async fn admin_add_ip_to_whitelist(
    Json(req): Json<AddWhitelistRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::add_to_whitelist(
        &req.ip_pattern,
        req.description.as_deref(),
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(StatusCode::CREATED)
}

async fn admin_remove_ip_from_whitelist(
    Query(q): Query<RemoveIpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_whitelist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    
    if let Some(entry) = entries.iter().find(|e| e.ip_pattern == q.ip_pattern) {
        security_db::remove_from_whitelist(&entry.id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    } else {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("IP pattern {} not found", q.ip_pattern) })));
    }
    Ok(StatusCode::OK)
}

async fn admin_clear_ip_whitelist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_whitelist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    for entry in entries {
        security_db::remove_from_whitelist(&entry.ip_pattern)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    }
    Ok(StatusCode::OK)
}

async fn admin_check_ip_in_whitelist(
    Query(q): Query<CheckIpQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = security_db::is_ip_in_whitelist(&q.ip)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(serde_json::json!({ "result": result })))
}

async fn admin_get_security_config(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let app_config = crate::modules::config::load_app_config()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
    
    Ok(Json(app_config.proxy.security_monitor))
}

#[derive(Deserialize)]
struct UpdateSecurityConfigWrapper {
    config: crate::proxy::config::SecurityMonitorConfig,
}

async fn admin_update_security_config(
    State(state): State<AppState>,
    Json(payload): Json<UpdateSecurityConfigWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = payload.config;
    let mut app_config = crate::modules::config::load_app_config()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
        
    app_config.proxy.security_monitor = config.clone();
    
    crate::modules::config::save_app_config(&app_config)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

    {
        let mut sec = state.security.write().await;
        *sec = crate::proxy::ProxySecurityConfig::from_proxy_config(&app_config.proxy);
        tracing::info!("[Security] Runtime security config hot-reloaded via Web API");
    }

    Ok(StatusCode::OK)
}

// --- Debug Console Handlers ---

async fn admin_enable_debug_console() -> impl IntoResponse {
    crate::modules::log_bridge::enable_log_bridge();
    StatusCode::OK
}

async fn admin_disable_debug_console() -> impl IntoResponse {
    crate::modules::log_bridge::disable_log_bridge();
    StatusCode::OK
}

async fn admin_is_debug_console_enabled() -> impl IntoResponse {
    Json(crate::modules::log_bridge::is_log_bridge_enabled())
}

async fn admin_get_debug_console_logs() -> impl IntoResponse {
    let logs = crate::modules::log_bridge::get_buffered_logs();
    Json(logs)
}

async fn admin_clear_debug_console_logs() -> impl IntoResponse {
    crate::modules::log_bridge::clear_log_buffer();
    StatusCode::OK
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpencodeSyncStatusRequest {
    proxy_url: String,
}

async fn admin_get_opencode_sync_status(
    Json(payload): Json<OpencodeSyncStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::get_opencode_sync_status(payload.proxy_url)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpencodeSyncRequest {
    proxy_url: String,
    api_key: String,
    #[serde(default)]
    sync_accounts: bool,
    pub models: Option<Vec<String>>,
}

async fn admin_execute_opencode_sync(
    Json(payload): Json<OpencodeSyncRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::execute_opencode_sync(
        payload.proxy_url,
        payload.api_key,
        Some(payload.sync_accounts),
        payload.models,
    )
    .await
    .map(|_| StatusCode::OK)
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })
}

async fn admin_execute_opencode_restore(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::execute_opencode_restore()
        .await
        .map(|_| StatusCode::OK)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetOpencodeConfigRequest {
    file_name: Option<String>,
}

async fn admin_get_opencode_config_content(
    Json(payload): Json<GetOpencodeConfigRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let file_name = payload.file_name;
    tokio::task::spawn_blocking(move || crate::proxy::opencode_sync::read_opencode_config_content(file_name))
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e.to_string() }),
        ))?
        .map(Json)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        ))
}
