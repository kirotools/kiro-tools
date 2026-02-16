use serde::{Serialize, Deserialize};
use std::collections::VecDeque;
use tokio::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::proxy::redaction::redact_sensitive_text;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequestLog {
    pub id: String,
    pub timestamp: i64,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub duration: u64,
    pub model: Option<String>,
    pub mapped_model: Option<String>,
    pub account_email: Option<String>,
    pub client_ip: Option<String>,
    pub error: Option<String>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cache_creation_input_tokens: Option<u32>,
    pub cache_read_input_tokens: Option<u32>,
    pub protocol: Option<String>,
    pub username: Option<String>,
}

impl ProxyRequestLog {
    pub fn redacted(&self) -> Self {
        let mut cloned = self.clone();
        if let Some(request_body) = &cloned.request_body {
            cloned.request_body = Some(redact_sensitive_text(request_body));
        }
        if let Some(response_body) = &cloned.response_body {
            cloned.response_body = Some(redact_sensitive_text(response_body));
        }
        if let Some(error) = &cloned.error {
            cloned.error = Some(redact_sensitive_text(error));
        }
        cloned
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub success_count: u64,
    pub error_count: u64,
}

pub struct ProxyMonitor {
    pub logs: RwLock<VecDeque<ProxyRequestLog>>,
    pub stats: RwLock<ProxyStats>,
    pub max_logs: usize,
    pub enabled: AtomicBool,
}

impl ProxyMonitor {
    pub fn new(max_logs: usize, _app_handle: Option<()>) -> Self {
        // Initialize DB
        if let Err(e) = crate::modules::proxy_db::init_db() {
            tracing::error!("Failed to initialize proxy DB: {}", e);
        }

        match crate::modules::proxy_db::clear_stale_pending_logs() {
            Ok(updated) => {
                if updated > 0 {
                    tracing::info!("Startup cleanup: cleared {} stale pending log(s)", updated);
                }
            }
            Err(e) => {
                tracing::error!("Failed to clear stale pending logs: {}", e);
            }
        }

        // Auto cleanup old logs (keep last 30 days)
        tokio::spawn(async {
            match crate::modules::proxy_db::cleanup_old_logs(30) {
                Ok(deleted) => {
                    if deleted > 0 {
                        tracing::info!("Auto cleanup: removed {} old logs (>30 days)", deleted);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to cleanup old logs: {}", e);
                }
            }
        });

        Self {
            logs: RwLock::new(VecDeque::with_capacity(max_logs)),
            stats: RwLock::new(ProxyStats::default()),
            max_logs,
            enabled: AtomicBool::new(false),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub async fn log_request(&self, log: ProxyRequestLog) {
        if !self.is_enabled() {
            return;
        }
        tracing::info!("[Monitor] Logging request: {} {}", log.method, log.url);
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
            if log.status >= 200 && log.status < 400 {
                stats.success_count += 1;
            } else {
                stats.error_count += 1;
            }
        }

        // Add log to memory
        {
            let mut logs = self.logs.write().await;
            if logs.len() >= self.max_logs {
                logs.pop_back();
            }
            logs.push_front(log.clone());
        }

        // Save to DB
        let log_to_save = log.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::modules::proxy_db::save_log(&log_to_save) {
                tracing::error!("Failed to save proxy log to DB: {}", e);
            }

            // Sync to Security DB (IpAccessLogs) so it appears in Security Monitor
            if let Some(ip) = &log_to_save.client_ip {
                let security_log = crate::modules::security_db::IpAccessLog {
                    id: uuid::Uuid::new_v4().to_string(),
                    client_ip: ip.clone(),
                    timestamp: log_to_save.timestamp / 1000, // ms to s
                    method: Some(log_to_save.method.clone()),
                    path: Some(log_to_save.url.clone()),
                    user_agent: None, // We don't have UA in ProxyRequestLog easily accessible here without plumbing
                    status: Some(log_to_save.status as i32),
                    duration: Some(log_to_save.duration as i64),
                    api_key_hash: None,
                    blocked: false, // This comes from monitor, so it wasn't blocked by IP filter
                    block_reason: None,
                    username: log_to_save.username.clone(),
                };

                if let Err(e) = crate::modules::security_db::save_ip_access_log(&security_log) {
                     tracing::error!("Failed to save security log: {}", e);
                }
            }

            // Record token stats if available
            if let Some(account) = &log_to_save.account_email {
                let model = log_to_save
                    .mapped_model
                    .clone()
                    .or(log_to_save.model.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                let input = log_to_save.input_tokens.unwrap_or(0);
                let output = log_to_save.output_tokens.unwrap_or(0);
                let cache_creation = log_to_save.cache_creation_input_tokens.unwrap_or(0);
                let cache_read = log_to_save.cache_read_input_tokens.unwrap_or(0);
                if input > 0 || output > 0 || cache_creation > 0 || cache_read > 0 {
                    if let Err(e) = crate::modules::token_stats::record_usage(account, &model, input, output, cache_creation, cache_read) {
                        tracing::warn!("Failed to record token stats: {}", e);
                    }
                }
            }
        });
    }
    /// Log a pending request (status=0) before acquiring concurrency slot
    pub async fn log_pending_request(&self, log: ProxyRequestLog) {
        if !self.is_enabled() {
            return;
        }
        tracing::info!("[Monitor] Logging pending request: {} {}", log.method, log.url);

        // Add to memory
        {
            let mut logs = self.logs.write().await;
            if logs.len() >= self.max_logs {
                logs.pop_back();
            }
            logs.push_front(log.clone());
        }

        // Save to DB
        let log_to_save = log.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::modules::proxy_db::save_log(&log_to_save) {
                tracing::error!("Failed to save pending log to DB: {}", e);
            }
        });
    }

    /// Update an existing log entry (pending -> completed)
    pub async fn update_log(&self, log: ProxyRequestLog) {
        // Update stats
        if self.is_enabled() {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
            if log.status >= 200 && log.status < 400 {
                stats.success_count += 1;
            } else {
                stats.error_count += 1;
            }
        }

        tracing::debug!("update_log called: account={:?}, input={:?}, output={:?}, cache_creation={:?}, cache_read={:?}", 
            log.account_email, log.input_tokens, log.output_tokens, log.cache_creation_input_tokens, log.cache_read_input_tokens);

        if let Some(account) = &log.account_email {
            let input = log.input_tokens.unwrap_or(0);
            let output = log.output_tokens.unwrap_or(0);
            let cache_creation = log.cache_creation_input_tokens.unwrap_or(0);
            let cache_read = log.cache_read_input_tokens.unwrap_or(0);
            if input > 0 || output > 0 || cache_creation > 0 || cache_read > 0 {
                tracing::info!("Recording tokens: account={}, input={}, output={}, cache_creation={}, cache_read={}", 
                    account, input, output, cache_creation, cache_read);
                let model = log
                    .mapped_model
                    .clone()
                    .or(log.model.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                let account = account.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::modules::token_stats::record_usage(&account, &model, input, output, cache_creation, cache_read) {
                        tracing::warn!("Failed to record token stats: {}", e);
                    } else {
                        tracing::info!("Successfully recorded token stats for {}", account);
                    }
                });
            } else {
                tracing::debug!("No tokens to record for account {}: all zeros", account);
            }
        } else {
            tracing::debug!("No account_email in log, skipping token recording");
        }

        if !self.is_enabled() {
            return;
        }

        // Update in memory
        {
            let mut logs = self.logs.write().await;
            if let Some(existing) = logs.iter_mut().find(|l| l.id == log.id) {
                *existing = log.clone();
            }
        }

        // Update in DB
        let log_to_save = log.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::modules::proxy_db::update_log(&log_to_save) {
                tracing::error!("Failed to update log in DB: {}", e);
            }

            // Sync to Security DB
            if let Some(ip) = &log_to_save.client_ip {
                let security_log = crate::modules::security_db::IpAccessLog {
                    id: uuid::Uuid::new_v4().to_string(),
                    client_ip: ip.clone(),
                    timestamp: log_to_save.timestamp / 1000,
                    method: Some(log_to_save.method.clone()),
                    path: Some(log_to_save.url.clone()),
                    user_agent: None,
                    status: Some(log_to_save.status as i32),
                    duration: Some(log_to_save.duration as i64),
                    api_key_hash: None,
                    blocked: false,
                    block_reason: None,
                    username: log_to_save.username.clone(),
                };

                if let Err(e) = crate::modules::security_db::save_ip_access_log(&security_log) {
                    tracing::error!("Failed to save security log: {}", e);
                }
            }
        });
    }

    /// Remove a pending log entry (when the request proceeds normally and monitor middleware will log the final result)
    pub async fn remove_pending_log(&self, log_id: &str) {
        if !self.is_enabled() {
            return;
        }

        // Remove from memory
        {
            let mut logs = self.logs.write().await;
            logs.retain(|l| l.id != log_id);
        }

        // Remove from DB
        let log_id = log_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = crate::modules::proxy_db::delete_log(&log_id) {
                tracing::error!("Failed to delete pending log from DB: {}", e);
            }
        });
    }

    pub async fn get_logs(&self, limit: usize) -> Vec<ProxyRequestLog> {
        // Try to get from DB first for true history
        let db_result = tokio::task::spawn_blocking(move || {
            crate::modules::proxy_db::get_logs(limit)
        }).await;

        match db_result {
            Ok(Ok(logs)) => logs,
            Ok(Err(e)) => {
                tracing::error!("Failed to get logs from DB: {}", e);
                // Fallback to memory
                let logs = self.logs.read().await;
                logs.iter().take(limit).cloned().collect()
            }
            Err(e) => {
                tracing::error!("Spawn blocking failed for get_logs: {}", e);
                let logs = self.logs.read().await;
                logs.iter().take(limit).cloned().collect()
            }
        }
    }

    pub async fn get_stats(&self) -> ProxyStats {
        let db_result = tokio::task::spawn_blocking(|| {
            crate::modules::proxy_db::get_stats()
        }).await;

        match db_result {
            Ok(Ok(stats)) => stats,
            Ok(Err(e)) => {
                tracing::error!("Failed to get stats from DB: {}", e);
                self.stats.read().await.clone()
            }
            Err(e) => {
                tracing::error!("Spawn blocking failed for get_stats: {}", e);
                self.stats.read().await.clone()
            }
        }
    }
    
    pub async fn get_logs_filtered(
        &self,
        page: usize,
        page_size: usize,
        search_text: Option<String>,
        level: Option<String>,
    ) -> Result<Vec<ProxyRequestLog>, String> {
        let offset = (page.max(1) - 1) * page_size;
        let errors_only = level.as_deref() == Some("error");
        let search = search_text.unwrap_or_default();

        let res = tokio::task::spawn_blocking(move || {
            crate::modules::proxy_db::get_logs_filtered(&search, errors_only, page_size, offset)
        }).await;

        match res {
            Ok(r) => r,
            Err(e) => Err(format!("Spawn blocking failed: {}", e)),
        }
    }
    
    pub async fn clear(&self) {
        let mut logs = self.logs.write().await;
        logs.clear();
        let mut stats = self.stats.write().await;
        *stats = ProxyStats::default();

        let _ = tokio::task::spawn_blocking(|| {
            if let Err(e) = crate::modules::proxy_db::clear_logs() {
                tracing::error!("Failed to clear logs in DB: {}", e);
            }
        }).await;
    }
}
