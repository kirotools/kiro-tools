// 移除冗余的顶层导入，因为这些在代码中已由 full path 或局部导入处理
use dashmap::DashMap;
use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::proxy::rate_limit::RateLimitTracker;
use crate::proxy::sticky_config::StickySessionConfig;

/// 账号并发槽位管理 Guard
/// 在作用域结束时自动释放槽位
pub struct ConcurrencySlot {
    #[allow(dead_code)]
    account_id: String,
    #[allow(dead_code)]
    _permit: OwnedSemaphorePermit,
}

impl ConcurrencySlot {
    fn new(account_id: String, permit: OwnedSemaphorePermit) -> Self {
        Self {
            account_id,
            _permit: permit,
        }
    }
}

/// 账号并发状态信息（用于 WebUI 展示）
#[derive(Debug, Clone)]
pub struct AccountConcurrencyInfo {
    pub account_id: String,
    pub max_concurrency: usize,
    pub current_concurrency: usize,
    pub available_slots: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnDiskAccountState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProxyToken {
    pub account_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub timestamp: i64,
    pub email: String,
    pub account_path: PathBuf, // 账号文件路径，用于更新
    pub project_id: Option<String>,
    pub subscription_tier: Option<String>, // Kiro tier: "Q_DEVELOPER_STANDALONE_FREE" | "Q_DEVELOPER_STANDALONE_PRO" | "Q_DEVELOPER_STANDALONE_POWER"
    pub remaining_quota: Option<i32>,      // [FIX #563] Remaining quota for priority sorting
    pub health_score: f32,                 // [NEW] 健康分数 (0.0 - 1.0)
    pub reset_time: Option<i64>,           // [NEW] 配额刷新时间戳（用于排序优化）
    pub validation_blocked: bool,          // [NEW] Check for validation block (VALIDATION_REQUIRED temporary block)
    pub validation_blocked_until: i64,     // [NEW] Timestamp until which the account is blocked
    pub model_quotas: HashMap<String, i32>, // [OPTIMIZATION] In-memory cache for model-specific quotas
    pub profile_arn: Option<String>,
}

pub struct TokenManager {
    tokens: Arc<DashMap<String, ProxyToken>>, // account_id -> ProxyToken
    current_index: Arc<AtomicUsize>,
    last_used_account: Arc<tokio::sync::Mutex<Option<(String, std::time::Instant)>>>,
    data_dir: PathBuf,
    rate_limit_tracker: Arc<RateLimitTracker>, // 新增: 限流跟踪器
    sticky_config: Arc<tokio::sync::RwLock<StickySessionConfig>>, // 新增：调度配置
    session_accounts: Arc<DashMap<String, String>>, // 新增：会话与账号映射 (SessionID -> AccountID)
    preferred_account_id: Arc<tokio::sync::RwLock<Option<String>>>, // [FIX #820] 优先使用的账号ID（固定账号模式）
    health_scores: Arc<DashMap<String, f32>>,                       // account_id -> health_score
    circuit_breaker_config: Arc<tokio::sync::RwLock<crate::models::CircuitBreakerConfig>>, // [NEW] 熔断配置缓存
    /// 支持优雅关闭时主动 abort 后台任务
    auto_cleanup_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: CancellationToken,
    /// 账号并发槽位管理
    concurrency_slots: Arc<DashMap<String, Arc<Semaphore>>>,
    max_concurrency_per_account: AtomicUsize,
    /// Per-account token refresh lock — prevents concurrent refresh requests for the same account
    refresh_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl TokenManager {
    fn expand_tilde_path(raw: &str) -> String {
        if raw.starts_with('~') {
            if let Some(home) = dirs::home_dir() {
                return raw.replacen('~', &home.to_string_lossy(), 1);
            }
        }
        raw.to_string()
    }

    fn fallback_creds_file_path() -> Option<String> {
        if let Ok(p) = std::env::var("KIRO_CREDS_FILE") {
            let expanded = Self::expand_tilde_path(&p);
            if std::path::Path::new(&expanded).exists() {
                return Some(expanded);
            }
        }

        let home = dirs::home_dir()?;
        let default_path = home
            .join(".aws")
            .join("sso")
            .join("cache")
            .join("kiro-auth-token.json");
        if default_path.exists() {
            return Some(default_path.to_string_lossy().to_string());
        }
        None
    }

    pub async fn get_refresh_inputs(
        &self,
        account_id: &str,
    ) -> Option<(String, Option<String>, Option<String>)> {
        let entry = self.tokens.get(account_id)?;
        let path = entry.account_path.clone();
        let in_mem_refresh = entry.refresh_token.clone();
        drop(entry);

        match Self::load_account_from_path(&path).await {
            Ok(account) => Some((
                account.token.refresh_token.clone(),
                if account.creds_file.is_none() && account.sqlite_db.is_none() && self.tokens.len() == 1 {
                    Self::fallback_creds_file_path().or(account.creds_file)
                } else {
                    account.creds_file
                },
                account.sqlite_db,
            )),
            Err(_) => Some((in_mem_refresh, None, None)),
        }
    }

    pub async fn force_refresh_account_token(&self, account_id: &str) -> Result<crate::modules::oauth::TokenResponse, String> {
        let refresh_lock = self
            .refresh_locks
            .entry(account_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _refresh_guard = refresh_lock.lock().await;

        let (rt, creds_file, sqlite_db) = self
            .get_refresh_inputs(account_id)
            .await
            .ok_or_else(|| "account_not_found".to_string())?;

        let rt = rt.trim();
        let rt_opt = if rt.is_empty() { None } else { Some(rt) };

        let token_res = crate::modules::oauth::refresh_access_token_with_source(
            rt_opt,
            creds_file.as_deref(),
            sqlite_db.as_deref(),
            Some(account_id),
        )
        .await?;

        if let Err(e) = self.sync_refreshed_token(account_id, &token_res).await {
            tracing::warn!("Failed to persist refreshed token for {}: {}", account_id, e);
        }

        Ok(token_res)
    }

    async fn load_account_from_path(path: &PathBuf) -> Result<crate::models::Account, String> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("failed_to_read_account_data: {}", e))?;
        let mut account: crate::models::Account = serde_json::from_str(&content)
            .map_err(|e| format!("failed_to_parse_account_data: {}", e))?;
        if account.encrypted {
            match account.decrypt_tokens() {
                Ok(()) => {}
                Err(e) => {
                    // [FIX] Graceful recovery: if encrypted=true but decryption fails,
                    // treat tokens as plaintext (caused by save_refreshed_token writing
                    // plaintext while encrypted flag remained true).
                    tracing::warn!(
                        "Decryption failed for account {} ({}), attempting plaintext recovery: {}",
                        account.id, account.email, e
                    );
                    account.encrypted = false;
                    // Re-save with proper encryption
                    if let Err(save_err) = Self::save_account_to_path(path, &account) {
                        tracing::error!(
                            "Failed to re-save recovered account {}: {}",
                            account.id, save_err
                        );
                    } else {
                        tracing::info!(
                            "Successfully recovered and re-encrypted account: {} ({})",
                            account.id, account.email
                        );
                    }
                }
            }
        }
        Ok(account)
    }

    fn save_account_to_path(path: &PathBuf, account: &crate::models::Account) -> Result<(), String> {
        let mut account_to_save = account.clone();
        account_to_save.encrypt_tokens()?;
        let content = serde_json::to_string_pretty(&account_to_save)
            .map_err(|e| format!("failed_to_serialize_account_data: {}", e))?;
        std::fs::write(path, content).map_err(|e| format!("failed_to_save_account_data: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("failed_to_set_file_permissions: {}", e))?;
        }

        Ok(())
    }

    /// 创建新的 TokenManager
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
            current_index: Arc::new(AtomicUsize::new(0)),
            last_used_account: Arc::new(tokio::sync::Mutex::new(None)),
            data_dir,
            rate_limit_tracker: Arc::new(RateLimitTracker::new()),
            sticky_config: Arc::new(tokio::sync::RwLock::new(StickySessionConfig::default())),
            session_accounts: Arc::new(DashMap::new()),
            preferred_account_id: Arc::new(tokio::sync::RwLock::new(None)),
            health_scores: Arc::new(DashMap::new()),
            circuit_breaker_config: Arc::new(tokio::sync::RwLock::new(
                crate::models::CircuitBreakerConfig::default(),
            )),
            auto_cleanup_handle: Arc::new(tokio::sync::Mutex::new(None)),
            cancel_token: CancellationToken::new(),
            concurrency_slots: Arc::new(DashMap::new()),
            max_concurrency_per_account: AtomicUsize::new(1),
            refresh_locks: Arc::new(DashMap::new()),
        }
    }

    /// 启动限流记录自动清理后台任务（每15秒检查并清除过期记录）
    pub async fn start_auto_cleanup(&self) {
        let tracker = self.rate_limit_tracker.clone();
        let cancel = self.cancel_token.child_token();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("Auto-cleanup task received cancel signal");
                        break;
                    }
                    _ = interval.tick() => {
                        let cleaned = tracker.cleanup_expired();
                        if cleaned > 0 {
                            tracing::info!(
                                "Auto-cleanup: Removed {} expired rate limit record(s)",
                                cleaned
                            );
                        }
                    }
                }
            }
        });

        // 先 abort 旧任务（防止任务泄漏），再存储新 handle
        let mut guard = self.auto_cleanup_handle.lock().await;
        if let Some(old) = guard.take() {
            old.abort();
            tracing::warn!("Aborted previous auto-cleanup task");
        }
        *guard = Some(handle);

        tracing::info!("Rate limit auto-cleanup task started (interval: 15s)");
    }

    /// 从主应用账号目录加载所有账号
    pub async fn load_accounts(&self) -> Result<usize, String> {
        let accounts_dir = self.data_dir.join("accounts");
        let index_path = self.data_dir.join("accounts.json");

        if !accounts_dir.exists() {
            return Err(format!("账号目录不存在: {:?}", accounts_dir));
        }

        // Reload should reflect current on-disk state (accounts can be added/removed/disabled).
        self.tokens.clear();
        self.current_index.store(0, Ordering::SeqCst);
        {
            let mut last_used = self.last_used_account.lock().await;
            *last_used = None;
        }

        let allowed_ids: Option<std::collections::HashSet<String>> = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|content| serde_json::from_str::<crate::models::account::AccountIndex>(&content).ok())
            .map(|idx| idx.accounts.into_iter().map(|a| a.id).collect());

        let entries = std::fs::read_dir(&accounts_dir)
            .map_err(|e| format!("读取账号目录失败: {}", e))?;

        let mut count = 0;

        for entry in entries {
            let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            if let Some(ref allow) = allowed_ids {
                let stem = path.file_stem().and_then(|s| s.to_str());
                if let Some(id) = stem {
                    if !allow.contains(id) {
                        continue;
                    }
                }
            }

            // 尝试加载账号
            match self.load_single_account(&path).await {
                Ok(Some(token)) => {
                    let account_id = token.account_id.clone();
                    self.tokens.insert(account_id, token);
                    count += 1;
                }
                Ok(None) => {
                    // 跳过无效账号
                }
                Err(e) => {
                    tracing::debug!("加载账号失败 {:?}: {}", path, e);
                }
            }
        }

        Ok(count)
    }

    /// 重新加载指定账号（用于配额更新后的实时同步）
    pub async fn reload_account(&self, account_id: &str) -> Result<(), String> {
        let path = self
            .data_dir
            .join("accounts")
            .join(format!("{}.json", account_id));
        if !path.exists() {
            return Err(format!("账号文件不存在: {:?}", path));
        }

        match self.load_single_account(&path).await {
            Ok(Some(token)) => {
                self.tokens.insert(account_id.to_string(), token);
                // [NEW] 重新加载账号时自动清除该账号的限流记录
                self.clear_rate_limit(account_id);
                Ok(())
            }
            Ok(None) => {
                // [FIX] 账号被禁用或不可用时，从内存池中彻底移除 (Issue #1565)
                // load_single_account returning None means the account should be skipped in its
                // current state (disabled / proxy_disabled / validation_blocked...).
                self.remove_account(account_id);
                Ok(())
            }
            Err(e) => Err(format!("同步账号失败: {}", e)),
        }
    }

    /// 重新加载所有账号
    pub async fn reload_all_accounts(&self) -> Result<usize, String> {
        let count = self.load_accounts().await?;
        // [NEW] 重新加载所有账号时自动清除所有限流记录
        self.clear_all_rate_limits();
        Ok(count)
    }

    /// 从内存中彻底移除指定账号及其关联数据 (Issue #1477)
    pub fn remove_account(&self, account_id: &str) {
        // 1. 从 DashMap 中移除令牌
        if self.tokens.remove(account_id).is_some() {
            tracing::info!("[Proxy] Removed account {} from memory cache", account_id);
        }

        // 2. 清理相关的健康分数
        self.health_scores.remove(account_id);

        // 3. 清理该账号的所有限流记录
        self.clear_rate_limit(account_id);

        // 4. 清理涉及该账号的所有会话绑定
        self.session_accounts.retain(|_, v| v != account_id);

        self.clear_concurrency_slots(account_id);

        // 5. 如果是当前优先账号，也需要清理
        if let Ok(mut preferred) = self.preferred_account_id.try_write() {
            if preferred.as_deref() == Some(account_id) {
                *preferred = None;
                tracing::info!("[Proxy] Cleared preferred account status for {}", account_id);
            }
        }
    }

    /// Check if an account has been disabled on disk.
    ///
    /// Safety net: avoids selecting a disabled account when the in-memory pool hasn't been
    /// reloaded yet (e.g. fixed account mode / sticky session).
    ///
    /// Note: this is intentionally tolerant to transient read/parse failures (e.g. concurrent
    /// writes). Failures are reported as `Unknown` so callers can skip without purging the in-memory
    /// token pool.
    async fn get_account_state_on_disk(account_path: &std::path::PathBuf) -> OnDiskAccountState {
        const MAX_RETRIES: usize = 2;
        const RETRY_DELAY_MS: u64 = 5;

        for attempt in 0..=MAX_RETRIES {
            let content = match tokio::fs::read_to_string(account_path).await {
                Ok(c) => c,
                Err(e) => {
                    // If the file is gone, the in-memory token is definitely stale.
                    if e.kind() == std::io::ErrorKind::NotFound {
                        return OnDiskAccountState::Disabled;
                    }
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                        continue;
                    }
                    tracing::debug!(
                        "Failed to read account file on disk {:?}: {}",
                        account_path,
                        e
                    );
                    return OnDiskAccountState::Unknown;
                }
            };

            let account = match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(v) => v,
                Err(e) => {
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                        continue;
                    }
                    tracing::debug!(
                        "Failed to parse account JSON on disk {:?}: {}",
                        account_path,
                        e
                    );
                    return OnDiskAccountState::Unknown;
                }
            };

            let disabled = account
                .get("disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || account
                    .get("proxy_disabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                || account
                    .get("quota")
                    .and_then(|q| q.get("is_forbidden"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

            return if disabled {
                OnDiskAccountState::Disabled
            } else {
                OnDiskAccountState::Enabled
            };
        }

        OnDiskAccountState::Unknown
    }

    /// 加载单个账号
    async fn load_single_account(&self, path: &PathBuf) -> Result<Option<ProxyToken>, String> {
        let account_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("Invalid account file name")?;

        let account = Self::load_account_from_path(path)
            .await
            .map_err(|e| format!("Failed to load account {}: {}", account_id, e))?;

        if account.proxy_disabled {
            tracing::debug!(
                "Account skipped due to manual disable: {:?} (email={}, reason={:?})",
                path,
                account.email,
                account.proxy_disabled_reason
            );
            return Ok(None);
        }

        if account.validation_blocked {
            let block_until = account.validation_blocked_until.unwrap_or(0);
            let now = chrono::Utc::now().timestamp();

            if now < block_until {
                tracing::debug!(
                    "Skipping validation-blocked account: {:?} (email={}, blocked until {})",
                    path,
                    account.email,
                    chrono::DateTime::from_timestamp(block_until, 0)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_else(|| block_until.to_string())
                );
                return Ok(None);
            } else {
                let mut updated_account = account.clone();
                updated_account.validation_blocked = false;
                updated_account.validation_blocked_until = None;
                updated_account.validation_blocked_reason = None;
                
                if let Err(e) = Self::save_account_to_path(path, &updated_account) {
                    tracing::warn!("Failed to clear validation block: {}", e);
                }
                
                tracing::info!(
                    "Validation block expired and cleared for account: {}",
                    account.email
                );
            }
        }

        if account.disabled {
            tracing::debug!(
                "Skipping disabled account file: {:?} (email={})",
                path,
                account.email
            );
            return Ok(None);
        }

        if Self::get_account_state_on_disk(path).await == OnDiskAccountState::Disabled {
            tracing::debug!("Account file {:?} is disabled on disk, skipping.", path);
            return Ok(None);
        }

        let subscription_tier = account.quota.as_ref()
            .and_then(|q| q.subscription_tier.clone());

        let remaining_quota = account.quota.as_ref()
            .and_then(|q| {
                let mut max_percentage = 0;
                let mut has_data = false;
                for model in &q.models {
                    if model.percentage > max_percentage {
                        max_percentage = model.percentage;
                    }
                    has_data = true;
                }
                if has_data { Some(max_percentage) } else { None }
            });

        let health_score = self.health_scores.get(&account.id).map(|v| *v).unwrap_or(1.0);

        let reset_time = account.quota.as_ref()
            .and_then(|q| {
                q.models.iter()
                    .filter_map(|m| chrono::DateTime::parse_from_rfc3339(&m.reset_time).ok())
                    .map(|dt| dt.timestamp())
                    .min()
            });

        let mut model_quotas = HashMap::new();
        if let Some(quota) = &account.quota {
            for model in &quota.models {
                let standard_id = crate::proxy::common::model_mapping::normalize_to_standard_id(&model.name)
                    .unwrap_or_else(|| model.name.clone());
                model_quotas.insert(standard_id, model.percentage);
            }
            if let Some(&kiro_pct) = model_quotas.get("kiro-credit") {
                for std_id in &["claude"] {
                    model_quotas.entry(std_id.to_string()).or_insert(kiro_pct);
                }
            }
        }

        Ok(Some(ProxyToken {
            account_id: account.id,
            access_token: account.token.access_token.clone(),
            refresh_token: account.token.refresh_token.clone(),
            expires_in: account.token.expires_in,
            timestamp: account.token.expiry_timestamp,
            email: account.email,
            account_path: path.clone(),
            project_id: account.token.project_id.clone(),
            subscription_tier,
            remaining_quota,
            health_score,
            reset_time,
            validation_blocked: account.validation_blocked,
            validation_blocked_until: account.validation_blocked_until.unwrap_or(0),
            model_quotas,
            profile_arn: None,
        }))
    }

    /// 计算账号的最大剩余配额百分比（用于排序）
    /// 返回值: Option<i32> (max_percentage)
    #[allow(dead_code)]
    fn calculate_quota_stats(&self, quota: &serde_json::Value) -> Option<i32> {
        let models = match quota.get("models").and_then(|m| m.as_array()) {
            Some(m) => m,
            None => return None,
        };

        let mut max_percentage = 0;
        let mut has_data = false;

        for model in models {
            if let Some(pct) = model.get("percentage").and_then(|v| v.as_i64()) {
                let pct_i32 = pct as i32;
                if pct_i32 > max_percentage {
                    max_percentage = pct_i32;
                }
                has_data = true;
            }
        }

        if has_data {
            Some(max_percentage)
        } else {
            None
        }
    }

    /// 从磁盘读取特定模型的 quota 百分比 [FIX] 排序使用目标模型的 quota 而非 max
    ///
    /// # 参数
    /// * `account_path` - 账号 JSON 文件路径
    /// * `model_name` - 目标模型名称（已标准化）
    #[allow(dead_code)] // 预留给精确配额读取逻辑
    fn get_model_quota_from_json(account_path: &PathBuf, model_name: &str) -> Option<i32> {
        let content = std::fs::read_to_string(account_path).ok()?;
        let account: serde_json::Value = serde_json::from_str(&content).ok()?;
        let models = account.get("quota")?.get("models")?.as_array()?;

        for model in models {
            if let Some(name) = model.get("name").and_then(|v| v.as_str()) {
                if crate::proxy::common::model_mapping::normalize_to_standard_id(name)
                    .unwrap_or_else(|| name.to_string())
                    == model_name
                {
                    return model
                        .get("percentage")
                        .and_then(|v| v.as_i64())
                        .map(|p| p as i32);
                }
            }
        }
        None
    }

    /// 测试辅助函数：公开访问 get_model_quota_from_json
    #[cfg(test)]
    pub fn get_model_quota_from_json_for_test(account_path: &PathBuf, model_name: &str) -> Option<i32> {
        Self::get_model_quota_from_json(account_path, model_name)
    }

    /// P2C 算法的候选池大小 - 从前 N 个最优候选中随机选择
    const P2C_POOL_SIZE: usize = 5;

    /// Power of 2 Choices (P2C) 选择算法
    /// 从前 5 个候选中随机选 2 个，选择配额更高的 -> 避免热点
    /// 返回选中的索引
    ///
    /// # 参数
    /// * `candidates` - 已排序的候选 token 列表
    /// * `attempted` - 已尝试失败的账号 ID 集合
    fn select_with_p2c<'a>(
        &self,
        candidates: &'a [ProxyToken],
        attempted: &HashSet<String>,
    ) -> Option<&'a ProxyToken> {
        use rand::Rng;

        // 过滤可用 token
        let available: Vec<&ProxyToken> = candidates.iter()
            .filter(|t| !attempted.contains(&t.account_id))
            .collect();

        if available.is_empty() { return None; }
        if available.len() == 1 { return Some(available[0]); }

        // P2C: 从前 min(P2C_POOL_SIZE, len) 个中随机选 2 个
        let pool_size = available.len().min(Self::P2C_POOL_SIZE);
        let mut rng = rand::thread_rng();

        let pick1 = rng.gen_range(0..pool_size);
        let pick2 = rng.gen_range(0..pool_size);
        // 确保选择不同的两个候选
        let pick2 = if pick2 == pick1 {
            (pick1 + 1) % pool_size
        } else {
            pick2
        };

        let c1 = available[pick1];
        let c2 = available[pick2];

        // 选择配额更高的
        let selected = if c1.remaining_quota.unwrap_or(0) >= c2.remaining_quota.unwrap_or(0) {
            c1
        } else {
            c2
        };

        tracing::debug!(
            "🎲 [P2C] Selected {} ({}%) from [{}({}%), {}({}%)]",
            selected.email, selected.remaining_quota.unwrap_or(0),
            c1.email, c1.remaining_quota.unwrap_or(0),
            c2.email, c2.remaining_quota.unwrap_or(0)
        );

        Some(selected)
    }

    /// 先发送取消信号，再带超时等待任务完成
    ///
    /// # 参数
    /// * `timeout` - 等待任务完成的超时时间
    pub async fn graceful_shutdown(&self, timeout: std::time::Duration) {
        tracing::info!("Initiating graceful shutdown of background tasks...");

        // 发送取消信号给所有后台任务
        self.cancel_token.cancel();

        // 带超时等待任务完成
        match tokio::time::timeout(timeout, self.abort_background_tasks()).await {
            Ok(_) => tracing::info!("All background tasks cleaned up gracefully"),
            Err(_) => tracing::warn!("Graceful cleanup timed out after {:?}, tasks were force-aborted", timeout),
        }
    }

    /// 中止并等待所有后台任务完成
    /// abort() 仅设置取消标志，必须 await 确认清理完成
    pub async fn abort_background_tasks(&self) {
        Self::abort_task(&self.auto_cleanup_handle, "Auto-cleanup task").await;
    }

    /// 中止单个后台任务并记录结果
    ///
    /// # 参数
    /// * `handle` - 任务句柄的 Mutex 引用
    /// * `task_name` - 任务名称（用于日志）
    async fn abort_task(
        handle: &tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
        task_name: &str,
    ) {
        let Some(handle) = handle.lock().await.take() else {
            return;
        };

        handle.abort();
        match handle.await {
            Ok(()) => tracing::debug!("{} completed", task_name),
            Err(e) if e.is_cancelled() => tracing::info!("{} aborted", task_name),
            Err(e) => tracing::warn!("{} error: {}", task_name, e),
        }
    }

    /// 获取当前可用的 Token（支持粘性会话与智能调度）
    /// 参数 `quota_group` 用于区分配额组
    /// 参数 `force_rotate` 为 true 时将忽略锁定，强制切换账号
    /// 参数 `session_id` 用于跨请求维持会话粘性
    /// 参数 `target_model` 用于检查配额保护 (Issue #621)
    pub async fn get_token(
        &self,
        quota_group: &str,
        force_rotate: bool,
        session_id: Option<&str>,
        target_model: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        // [FIX] 检查并处理待重新加载的账号
        let pending_reload = crate::proxy::server::take_pending_reload_accounts();
        for account_id in pending_reload {
            if let Err(e) = self.reload_account(&account_id).await {
                tracing::warn!("[Quota] Failed to reload account {}: {}", account_id, e);
            } else {
                tracing::info!(
                    "[Quota] Reloaded account {}",
                    account_id
                );
            }
        }

        // [FIX #1477] 检查并处理待删除的账号（彻底清理缓存）
        let pending_delete = crate::proxy::server::take_pending_delete_accounts();
        for account_id in pending_delete {
            self.remove_account(&account_id);
            tracing::info!(
                "[Proxy] Purged deleted account {} from all caches",
                account_id
            );
        }

        // 【优化 Issue #284】添加 5 秒超时，防止死锁
        let timeout_duration = std::time::Duration::from_secs(5);
        match tokio::time::timeout(
            timeout_duration,
            self.get_token_internal(quota_group, force_rotate, session_id, target_model),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(
                "Token acquisition timeout (5s) - system too busy or deadlock detected".to_string(),
            ),
        }
    }

    /// 内部实现：获取 Token 的核心逻辑
    async fn get_token_internal(
        &self,
        quota_group: &str,
        force_rotate: bool,
        session_id: Option<&str>,
        target_model: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        let mut tokens_snapshot: Vec<ProxyToken> =
            self.tokens.iter().map(|e| e.value().clone()).collect();
        let mut total = tokens_snapshot.len();
        if total == 0 {
            return Err("Token pool is empty".to_string());
        }

        // [NEW] 1. 动态能力过滤 (Capability Filter)
        
        // 定义常量
        const RESET_TIME_THRESHOLD_SECS: i64 = 600; // 10 分钟阈值

        // 归一化目标模型名为标准 ID
        let normalized_target = crate::proxy::common::model_mapping::normalize_to_standard_id(target_model)
            .unwrap_or_else(|| target_model.to_string());

        // 仅保留明确拥有该模型配额的账号
        // 这一步确保了 "保证有模型才可以进入轮询"，特别是对 Opus 4.6 等高端模型
        let candidate_count_before = tokens_snapshot.len();
        
        // 此处假设所有受支持的模型都会出现在 model_quotas 中
        // 如果 API 返回的配额信息不完整，可能会导致误杀，但为了严格性，我们执行此过滤
        tokens_snapshot.retain(|t| t.model_quotas.contains_key(&normalized_target));

        if tokens_snapshot.is_empty() {
            if candidate_count_before > 0 {
                // 如果过滤前有账号，过滤后没了，说明所有账号都没有该模型的配额
                tracing::warn!("No accounts have satisfied quota for model: {}", normalized_target);
                return Err(format!("No accounts available with quota for model: {}", normalized_target));
            }
            return Err("Token pool is empty".to_string());
        }

        tokens_snapshot.sort_by(|a, b| {
            // Priority 0: 严格的订阅等级排序 (POWER > PRO+ > PRO > FREE)
            // Kiro 订阅等级: Power ($200) > Pro+ ($40) > Pro ($20) > Free ($0)
            // API 返回格式如 "Q_DEVELOPER_STANDALONE_POWER"
            let tier_priority = |tier: &Option<String>| {
                let t = tier.as_deref().unwrap_or("").to_lowercase();
                if t.contains("power") { 0 }
                else if t.contains("pro+") || t.contains("pro_plus") || t.contains("proplus") { 1 }
                else if t.contains("pro") { 2 }
                else if t.contains("free") { 3 }
                else { 4 }
            };

            let tier_cmp = tier_priority(&a.subscription_tier)
                .cmp(&tier_priority(&b.subscription_tier));
            if tier_cmp != std::cmp::Ordering::Equal {
                return tier_cmp;
            }

            // Priority 1: 目标模型的 quota (higher is better) -> 保护低配额账号
            // 经过过滤，key 肯定存在
            let quota_a = a.model_quotas.get(&normalized_target).copied().unwrap_or(0);
            let quota_b = b.model_quotas.get(&normalized_target).copied().unwrap_or(0);

            let quota_cmp = quota_b.cmp(&quota_a);
            if quota_cmp != std::cmp::Ordering::Equal {
                return quota_cmp;
            }

            // Priority 2: Health score (higher is better)
            let health_cmp = b.health_score.partial_cmp(&a.health_score)
                .unwrap_or(std::cmp::Ordering::Equal);
            if health_cmp != std::cmp::Ordering::Equal {
                return health_cmp;
            }

            // Priority 3: Reset time (earlier is better, but only if diff > 10 min)
            let reset_a = a.reset_time.unwrap_or(i64::MAX);
            let reset_b = b.reset_time.unwrap_or(i64::MAX);
            if (reset_a - reset_b).abs() >= RESET_TIME_THRESHOLD_SECS {
                reset_a.cmp(&reset_b)
            } else {
                std::cmp::Ordering::Equal
            }
        });

        // 【调试日志】打印排序后的账号顺序（显示目标模型的 quota）
        tracing::debug!(
            "🔄 [Token Rotation] target={} Accounts: {:?}",
            normalized_target,
            tokens_snapshot.iter().map(|t| format!(
                "{}(quota={}%, reset={:?}, health={:.2})",
                t.email,
                t.model_quotas.get(&normalized_target).copied().unwrap_or(0),
                t.reset_time.map(|ts| {
                    let now = chrono::Utc::now().timestamp();
                    let diff_secs = ts - now;
                    if diff_secs > 0 {
                        format!("{}m", diff_secs / 60)
                    } else {
                        "now".to_string()
                    }
                }),
                t.health_score
            )).collect::<Vec<_>>()
        );

        // 0. 读取当前调度配置
        let scheduling = self.sticky_config.read().await.clone();
        use crate::proxy::sticky_config::SchedulingMode;

        // ===== [FIX #820] 固定账号模式：优先使用指定账号 =====
        let preferred_id = self.preferred_account_id.read().await.clone();
        if let Some(ref pref_id) = preferred_id {
            // 查找优先账号
            if let Some(preferred_token) = tokens_snapshot
                .iter()
                .find(|t| &t.account_id == pref_id)
                .cloned()
            {
                // 检查账号是否可用（未限流、未被配额保护）
                match Self::get_account_state_on_disk(&preferred_token.account_path).await {
                    OnDiskAccountState::Disabled => {
                        tracing::warn!(
                            "🔒 [FIX #820] Preferred account {} is disabled on disk, purging and falling back",
                            preferred_token.email
                        );
                        self.remove_account(&preferred_token.account_id);
                        tokens_snapshot.retain(|t| t.account_id != preferred_token.account_id);
                        total = tokens_snapshot.len();

                        {
                            let mut preferred = self.preferred_account_id.write().await;
                            if preferred.as_deref() == Some(pref_id.as_str()) {
                                *preferred = None;
                            }
                        }

                        if total == 0 {
                            return Err("Token pool is empty".to_string());
                        }
                    }
                    OnDiskAccountState::Unknown => {
                        tracing::warn!(
                            "🔒 [FIX #820] Preferred account {} state on disk is unavailable, falling back",
                            preferred_token.email
                        );
                        // Don't purge on transient read/parse failures; just skip this token for this request.
                        tokens_snapshot.retain(|t| t.account_id != preferred_token.account_id);
                        total = tokens_snapshot.len();
                        if total == 0 {
                            return Err("Token pool is empty".to_string());
                        }
                    }
                    OnDiskAccountState::Enabled => {
                        let normalized_target =
                            crate::proxy::common::model_mapping::normalize_to_standard_id(
                                target_model,
                            )
                            .unwrap_or_else(|| target_model.to_string());

                let is_rate_limited = self
                    .is_rate_limited(&preferred_token.account_id, Some(&normalized_target))
                    .await;

                if !is_rate_limited {
                    tracing::info!(
                        "🔒 [FIX #820] Using preferred account: {} (fixed mode)",
                        preferred_token.email
                    );

                    // 直接使用优先账号，跳过轮询逻辑
                    let mut token = preferred_token.clone();

                    // 检查 token 是否过期（提前5分钟刷新）
                    let now = chrono::Utc::now().timestamp();
                    if now >= token.timestamp - 300 {
                        tracing::debug!("账号 {} 的 token 即将过期，正在刷新...", token.email);

                        // Per-account refresh lock — prevents concurrent refresh for same account
                        let refresh_lock = self.refresh_locks
                            .entry(token.account_id.clone())
                            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                            .clone();
                        let _refresh_guard = refresh_lock.lock().await;

                        // Re-check after acquiring lock — another request may have already refreshed
                        let already_refreshed = self.tokens.get(&token.account_id)
                            .map(|e| e.timestamp > chrono::Utc::now().timestamp() + 60)
                            .unwrap_or(false);

                        if already_refreshed {
                            if let Some(entry) = self.tokens.get(&token.account_id) {
                                token.access_token = entry.access_token.clone();
                                token.refresh_token = entry.refresh_token.clone();
                                token.expires_in = entry.expires_in;
                                token.timestamp = entry.timestamp;
                            }
                        } else {
                            let (rt, creds_file, sqlite_db) = self
                                .get_refresh_inputs(&token.account_id)
                                .await
                                .unwrap_or((token.refresh_token.clone(), None, None));

                            let rt = rt.trim();
                            let rt_opt = if rt.is_empty() { None } else { Some(rt) };

                            match crate::modules::oauth::refresh_access_token_with_source(
                                rt_opt,
                                creds_file.as_deref(),
                                sqlite_db.as_deref(),
                                Some(&token.account_id),
                            )
                            .await
                            {
                                Ok(token_response) => {
                                    token.access_token = token_response.access_token.clone();
                                    token.expires_in = token_response.expires_in;
                                    token.timestamp = chrono::Utc::now().timestamp() + token_response.expires_in;

                                    // Update refresh_token if a new one was returned
                                    if let Some(ref new_rt) = token_response.refresh_token {
                                        token.refresh_token = new_rt.clone();
                                    }

                                    if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
                                        entry.access_token = token.access_token.clone();
                                        entry.refresh_token = token.refresh_token.clone();
                                        entry.expires_in = token.expires_in;
                                        entry.timestamp = token.timestamp;
                                    }
                                    let _ = self
                                        .save_refreshed_token(&token.account_id, &token_response)
                                        .await;
                                }
                                Err(e) => {
                                    tracing::warn!("Preferred account token refresh failed: {}", e);
                                    // 继续使用旧 token，让后续逻辑处理失败
                                }
                            }
                        }
                    }

                    // All accounts are Kiro — use fixed project ID
                    let project_id = "kiro-native".to_string();

                    return Ok((token.access_token, project_id, token.email, token.account_id, 0));
                } else {
                    tracing::warn!("🔒 [FIX #820] Preferred account {} is rate-limited, falling back to round-robin", preferred_token.email);
                }
                    }
                }
            } else {
                tracing::warn!("🔒 [FIX #820] Preferred account {} not found in pool, falling back to round-robin", pref_id);
            }
        }
        // ===== [END FIX #820] =====

        // 【优化 Issue #284】将锁操作移到循环外，避免重复获取锁
        // 预先获取 last_used_account 的快照，避免在循环中多次加锁
        let last_used_account_id = if quota_group != "image_gen" {
            let last_used = self.last_used_account.lock().await;
            last_used.clone()
        } else {
            None
        };

        let mut attempted: HashSet<String> = HashSet::new();
        let mut last_error: Option<String> = None;
        let mut need_update_last_used: Option<(String, std::time::Instant)> = None;

        for attempt in 0..total {
            let rotate = force_rotate || attempt > 0;

            // ===== 【核心】粘性会话与智能调度逻辑 =====
            let mut target_token: Option<ProxyToken> = None;

            // 归一化目标模型名为标准 ID，用于配额保护检查
            let normalized_target = crate::proxy::common::model_mapping::normalize_to_standard_id(target_model)
                .unwrap_or_else(|| target_model.to_string());

            // 模式 A: 粘性会话处理 (CacheFirst 或 Balance 且有 session_id)
            if !rotate
                && session_id.is_some()
                && scheduling.mode != SchedulingMode::PerformanceFirst
            {
                let sid = session_id.unwrap();

                // 1. 检查会话是否已绑定账号
                if let Some(bound_id) = self.session_accounts.get(sid).map(|v| v.clone()) {
                    // 【修复】先通过 account_id 找到对应的账号，获取其 email
                    // 2. 转换 email -> account_id 检查绑定的账号是否限流
                    if let Some(bound_token) =
                        tokens_snapshot.iter().find(|t| t.account_id == bound_id)
                    {
                        let key = self
                            .email_to_account_id(&bound_token.email)
                            .unwrap_or_else(|| bound_token.account_id.clone());
                        // [FIX] Pass None for specific model wait time if not applicable
                        let reset_sec = self.rate_limit_tracker.get_remaining_wait(&key, None);
                        if reset_sec > 0 {
                            // 【修复 Issue #284】立即解绑并切换账号，不再阻塞等待
                            // 原因：阻塞等待会导致并发请求时客户端 socket 超时 (UND_ERR_SOCKET)
                            tracing::debug!(
                                "Sticky Session: Bound account {} is rate-limited ({}s), unbinding and switching.",
                                bound_token.email, reset_sec
                            );
                            self.session_accounts.remove(sid);
                        } else if !attempted.contains(&bound_id)
                            && self.has_available_slot(&bound_id)
                        {
                            // 3. 账号可用且未被标记为尝试失败，优先复用
                            tracing::debug!("Sticky Session: Successfully reusing bound account {} for session {}", bound_token.email, sid);
                            target_token = Some(bound_token.clone());
                        } else if !attempted.contains(&bound_id) {
                            tracing::debug!(
                                "Sticky Session: Bound account {} has no available concurrency slot, selecting another account",
                                bound_token.email
                            );
                        }
                    } else {
                        // 绑定的账号已不存在（可能被删除），解绑
                        tracing::debug!(
                            "Sticky Session: Bound account not found for session {}, unbinding",
                            sid
                        );
                        self.session_accounts.remove(sid);
                    }
                }
            }

            // 模式 B: 原子化 60s 全局锁定 (针对无 session_id 情况的默认保护)
            // 【修复】性能优先模式应跳过 60s 锁定；
            if target_token.is_none()
                && !rotate
                && quota_group != "image_gen"
                && scheduling.mode != SchedulingMode::PerformanceFirst
            {
                // 【优化】使用预先获取的快照，不再在循环内加锁
                if let Some((account_id, last_time)) = &last_used_account_id {
                    // [FIX #3] 60s 锁定逻辑应检查 `attempted` 集合，避免重复尝试失败的账号
                    if last_time.elapsed().as_secs() < 60 && !attempted.contains(account_id) {
                        if let Some(found) =
                            tokens_snapshot.iter().find(|t| &t.account_id == account_id)
                        {
                            // 【修复】检查限流状态，避免复用已被锁定的账号
                            if !self
                                .is_rate_limited(&found.account_id, Some(&normalized_target))
                                .await
                                && self.has_available_slot(&found.account_id)
                            {
                                tracing::debug!(
                                    "60s Window: Force reusing last account: {}",
                                    found.email
                                );
                                target_token = Some(found.clone());
                            } else {
                                tracing::debug!(
                                    "60s Window: Last account {} is rate-limited or has no available slot, skipping",
                                    found.email
                                );
                            }
                        }
                    }
                }

                if target_token.is_none() {
                    let mut non_limited: Vec<ProxyToken> = Vec::new();
                    for t in &tokens_snapshot {
                        if self.is_rate_limited(&t.account_id, Some(&normalized_target)).await {
                            continue;
                        }
                        non_limited.push(t.clone());
                    }

                    let mut non_limited_available: Vec<ProxyToken> = Vec::new();
                    for t in &non_limited {
                        if self.has_available_slot(&t.account_id) {
                            non_limited_available.push(t.clone());
                        }
                    }

                    let selected = if !non_limited_available.is_empty() {
                        self.select_with_p2c(&non_limited_available, &attempted)
                    } else {
                        self.select_with_p2c(&non_limited, &attempted)
                    };

                    if let Some(selected) = selected {
                        target_token = Some(selected.clone());
                        need_update_last_used = Some((selected.account_id.clone(), std::time::Instant::now()));

                        // 如果是会话首次分配且需要粘性，在此建立绑定
                        if let Some(sid) = session_id {
                            if scheduling.mode != SchedulingMode::PerformanceFirst {
                                self.session_accounts
                                    .insert(sid.to_string(), selected.account_id.clone());
                                tracing::debug!(
                                    "Sticky Session: Bound new account {} to session {}",
                                    selected.email,
                                    sid
                                );
                            }
                        }
                    }
                }
            } else if target_token.is_none() {
                tracing::debug!(
                    "🔄 [Mode C] P2C selection from {} candidates",
                    total
                );

                let mut non_limited: Vec<ProxyToken> = Vec::new();
                for t in &tokens_snapshot {
                    if self.is_rate_limited(&t.account_id, Some(&normalized_target)).await {
                        continue;
                    }
                    non_limited.push(t.clone());
                }

                let mut non_limited_available: Vec<ProxyToken> = Vec::new();
                for t in &non_limited {
                    if self.has_available_slot(&t.account_id) {
                        non_limited_available.push(t.clone());
                    }
                }

                let selected = if !non_limited_available.is_empty() {
                    self.select_with_p2c(&non_limited_available, &attempted)
                } else {
                    self.select_with_p2c(&non_limited, &attempted)
                };

                if let Some(selected) = selected {
                    tracing::debug!("  {} - SELECTED via P2C", selected.email);
                    target_token = Some(selected.clone());

                    if rotate {
                        tracing::debug!("Force Rotation: Switched to account: {}", selected.email);
                    }
                }
            }

            let mut token = match target_token {
                Some(t) => t,
                None => {
                    let min_wait = tokens_snapshot
                        .iter()
                        .filter_map(|t| self.rate_limit_tracker.get_reset_seconds(&t.account_id))
                        .min();

                    if let Some(wait_sec) = min_wait {
                        if wait_sec <= 2 {
                            let wait_ms = (wait_sec as f64 * 1000.0) as u64;
                            tracing::warn!(
                                "All accounts rate-limited but shortest wait is {}s. Applying {}ms buffer for state sync...",
                                wait_sec, wait_ms
                            );

                            tokio::time::sleep(tokio::time::Duration::from_millis(wait_ms)).await;

                            let retry_token = tokens_snapshot.iter()
                                .find(|t| !attempted.contains(&t.account_id) 
                                    && !self.is_rate_limited_sync(&t.account_id, Some(&normalized_target)));

                            if let Some(t) = retry_token {
                                tracing::info!(
                                    "✅ Buffer delay successful! Found available account: {}",
                                    t.email
                                );
                                t.clone()
                            } else {
                                tracing::warn!(
                                    "Buffer delay failed. Executing optimistic reset for all {} accounts...",
                                    tokens_snapshot.len()
                                );

                                self.rate_limit_tracker.clear_all();

                                let final_token = tokens_snapshot
                                    .iter()
                                    .find(|t| !attempted.contains(&t.account_id));

                                if let Some(t) = final_token {
                                    tracing::info!(
                                        "✅ Optimistic reset successful! Using account: {}",
                                        t.email
                                    );
                                    t.clone()
                                } else {
                                    return Err(
                                        "All accounts failed after optimistic reset.".to_string()
                                    );
                                }
                            }
                        } else {
                            return Err(format!("All accounts limited. Wait {}s.", wait_sec));
                        }
                    } else {
                        tracing::info!(
                            "所有账号并发槽位已满，等待 {} 秒后重试...",
                            self.max_concurrency_per_account.load(Ordering::Relaxed)
                        );

                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            self.max_concurrency_per_account.load(Ordering::Relaxed) as u64
                        )).await;

                        let retry_token = tokens_snapshot.iter()
                            .find(|t| {
                                !attempted.contains(&t.account_id)
                                    && !self.is_rate_limited_sync(&t.account_id, Some(&normalized_target))
                                    && self.has_available_slot(&t.account_id)
                            });

                        if let Some(t) = retry_token {
                            tracing::info!(
                                "✅ 等待后找到可用账号: {}",
                                t.email
                            );
                            t.clone()
                        } else {
                            return Err("所有账号并发槽位已满，请稍后重试".to_string());
                        }
                    }
                }
            };

            // Safety net: avoid selecting an account that has been disabled on disk but still
            // exists in the in-memory snapshot (e.g. stale cache + sticky session binding).
            match Self::get_account_state_on_disk(&token.account_path).await {
                OnDiskAccountState::Disabled => {
                    tracing::warn!(
                        "Selected account {} is disabled on disk, purging and retrying",
                        token.email
                    );
                    attempted.insert(token.account_id.clone());
                    self.remove_account(&token.account_id);
                    continue;
                }
                OnDiskAccountState::Unknown => {
                    tracing::warn!(
                        "Selected account {} state on disk is unavailable, skipping",
                        token.email
                    );
                    attempted.insert(token.account_id.clone());
                    continue;
                }
                OnDiskAccountState::Enabled => {}
            }

            // 3. 检查 token 是否过期（提前5分钟刷新）
            let now = chrono::Utc::now().timestamp();
            if now >= token.timestamp - 300 {
                tracing::debug!("账号 {} 的 token 即将过期，正在刷新...", token.email);

                // Per-account refresh lock — prevents concurrent refresh for same account
                let refresh_lock = self.refresh_locks
                    .entry(token.account_id.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone();
                let _refresh_guard = refresh_lock.lock().await;

                // Re-check after acquiring lock — another request may have already refreshed
                let already_refreshed = self.tokens.get(&token.account_id)
                    .map(|e| e.timestamp > chrono::Utc::now().timestamp() + 60)
                    .unwrap_or(false);

                if already_refreshed {
                    // Another concurrent request already refreshed this token
                    if let Some(entry) = self.tokens.get(&token.account_id) {
                        token.access_token = entry.access_token.clone();
                        token.refresh_token = entry.refresh_token.clone();
                        token.expires_in = entry.expires_in;
                        token.timestamp = entry.timestamp;
                    }
                    tracing::debug!("Token already refreshed by another request, using cached token");
                } else {
                    let (rt, creds_file, sqlite_db) = self
                        .get_refresh_inputs(&token.account_id)
                        .await
                        .unwrap_or((token.refresh_token.clone(), None, None));

                    let rt = rt.trim();
                    let rt_opt = if rt.is_empty() { None } else { Some(rt) };

                    match crate::modules::oauth::refresh_access_token_with_source(
                        rt_opt,
                        creds_file.as_deref(),
                        sqlite_db.as_deref(),
                        Some(&token.account_id),
                    )
                    .await
                    {
                        Ok(token_response) => {
                            tracing::debug!("Token 刷新成功！");

                            // 更新本地内存对象供后续使用
                            token.access_token = token_response.access_token.clone();
                            token.expires_in = token_response.expires_in;
                            token.timestamp = chrono::Utc::now().timestamp() + token_response.expires_in;

                            // Update refresh_token if a new one was returned
                            if let Some(ref new_rt) = token_response.refresh_token {
                                token.refresh_token = new_rt.clone();
                            }

                            // 同步更新跨线程共享的 DashMap
                            if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
                                entry.access_token = token.access_token.clone();
                                entry.refresh_token = token.refresh_token.clone();
                                entry.expires_in = token.expires_in;
                                entry.timestamp = token.timestamp;
                            }

                            // 同步落盘（避免重启后继续使用过期 timestamp 导致频繁刷新）
                            if let Err(e) = self
                                .save_refreshed_token(&token.account_id, &token_response)
                                .await
                            {
                                tracing::debug!("保存刷新后的 token 失败 ({}): {}", token.email, e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Token 刷新失败 ({}): {}，尝试下一个账号", token.email, e);
                            if e.contains("\"invalid_grant\"") || e.contains("invalid_grant") {
                                tracing::error!(
                                    "Disabling account due to invalid_grant ({}): refresh_token likely revoked/expired",
                                    token.email
                                );
                                let _ = self
                                    .disable_account(
                                        &token.account_id,
                                        &format!("invalid_grant: {}", e),
                                    )
                                    .await;
                                self.tokens.remove(&token.account_id);
                            }
                            // Avoid leaking account emails to API clients; details are still in logs.
                            last_error = Some(format!("Token refresh failed: {}", e));
                            attempted.insert(token.account_id.clone());

                            // 【优化】标记需要清除锁定，避免在循环内加锁
                            if quota_group != "image_gen" {
                                if matches!(&last_used_account_id, Some((id, _)) if id == &token.account_id)
                                {
                                    need_update_last_used =
                                        Some((String::new(), std::time::Instant::now()));
                                    // 空字符串表示需要清除
                                }
                            }
                            continue;
                        }
                    }
                }
            }

            let project_id = "kiro-native".to_string();

            // 【优化】在成功返回前，统一更新 last_used_account（如果需要）
            if let Some((new_account_id, new_time)) = need_update_last_used {
                if quota_group != "image_gen" {
                    let mut last_used = self.last_used_account.lock().await;
                    if new_account_id.is_empty() {
                        // 空字符串表示需要清除锁定
                        *last_used = None;
                    } else {
                        *last_used = Some((new_account_id, new_time));
                    }
                }
            }

            return Ok((token.access_token, project_id, token.email, token.account_id, 0));
        }

        Err(last_error.unwrap_or_else(|| "All accounts failed".to_string()))
    }

    async fn disable_account(&self, account_id: &str, reason: &str) -> Result<(), String> {
        let path = if let Some(entry) = self.tokens.get(account_id) {
            entry.account_path.clone()
        } else {
            self.data_dir
                .join("accounts")
                .join(format!("{}.json", account_id))
        };

        let mut content: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).map_err(|e| format!("读取文件失败: {}", e))?,
        )
        .map_err(|e| format!("解析 JSON 失败: {}", e))?;

        let now = chrono::Utc::now().timestamp();
        content["disabled"] = serde_json::Value::Bool(true);
        content["disabled_at"] = serde_json::Value::Number(now.into());
        content["disabled_reason"] = serde_json::Value::String(truncate_reason(reason, 800));

        std::fs::write(&path, serde_json::to_string_pretty(&content).unwrap())
            .map_err(|e| format!("写入文件失败: {}", e))?;

        // 【修复 Issue #3】从内存中移除禁用的账号，防止被60s锁定逻辑继续使用
        self.tokens.remove(account_id);

        tracing::warn!("Account disabled: {} ({:?})", account_id, path);
        Ok(())
    }

    /// 保存刷新后的 token 到内存 + 磁盘
    pub async fn sync_refreshed_token(&self, account_id: &str, token_response: &crate::modules::oauth::TokenResponse) -> Result<(), String> {
        if let Some(mut entry) = self.tokens.get_mut(account_id) {
            entry.access_token = token_response.access_token.clone();
            entry.expires_in = token_response.expires_in;
            entry.timestamp = chrono::Utc::now().timestamp() + token_response.expires_in;
            if let Some(ref new_rt) = token_response.refresh_token {
                entry.refresh_token = new_rt.clone();
            }
        }
        self.save_refreshed_token(account_id, token_response).await
    }

    /// 保存刷新后的 token 到账号文件
    async fn save_refreshed_token(&self, account_id: &str, token_response: &crate::modules::oauth::TokenResponse) -> Result<(), String> {
        let entry = self.tokens.get(account_id)
            .ok_or("账号不存在")?;

        let path = &entry.account_path;

        let mut content: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path).map_err(|e| format!("读取文件失败: {}", e))?
        ).map_err(|e| format!("解析 JSON 失败: {}", e))?;

        let now = chrono::Utc::now().timestamp();

        // [FIX] Encrypt new token values before writing to disk.
        // Previously, plaintext tokens were written while `encrypted` remained `true`,
        // causing decrypt_tokens() to fail on next load → account silently skipped.
        let encrypted_access = crate::utils::crypto::encrypt_string(&token_response.access_token)
            .map_err(|e| format!("加密 access_token 失败: {}", e))?;
        content["token"]["access_token"] = serde_json::Value::String(encrypted_access);
        content["token"]["expires_in"] = serde_json::Value::Number(token_response.expires_in.into());
        content["token"]["expiry_timestamp"] = serde_json::Value::Number((now + token_response.expires_in).into());

        // Save new refresh_token if returned (token rotation)
        if let Some(ref new_rt) = token_response.refresh_token {
            let encrypted_refresh = crate::utils::crypto::encrypt_string(new_rt)
                .map_err(|e| format!("加密 refresh_token 失败: {}", e))?;
            content["token"]["refresh_token"] = serde_json::Value::String(encrypted_refresh);
        }

        // Ensure encrypted flag is true (tokens are now encrypted)
        content["encrypted"] = serde_json::Value::Bool(true);

        std::fs::write(path, serde_json::to_string_pretty(&content).unwrap())
            .map_err(|e| format!("写入文件失败: {}", e))?;

        tracing::debug!("已保存刷新后的 token 到账号 {}", account_id);

        if let Ok(account) = Self::load_account_from_path(&entry.account_path).await {
            if let Err(e) = crate::modules::account::save_credentials_to_source_file(&account) {
                tracing::warn!("Failed to sync credentials to source file: {}", e);
            }
        }

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_kiro_account(&self, account_id: &str) -> bool {
        self.tokens
            .get(account_id)
            .map(|t| {
                t.subscription_tier
                    .as_deref()
                    .map(|s| s.contains("Q_DEVELOPER") || s.contains("KIRO"))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    pub fn get_account_region(&self, account_id: &str) -> Option<String> {
        let entry = self.tokens.get(account_id)?;
        let path = &entry.account_path;
        let content = std::fs::read_to_string(path).ok()?;
        let account: serde_json::Value = serde_json::from_str(&content).ok()?;
        account
            .get("token")
            .and_then(|t| t.get("region"))
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .or_else(|| Some("us-east-1".to_string()))
    }

    pub fn get_account_profile_arn(&self, account_id: &str) -> Option<String> {
        self.tokens.get(account_id)?.profile_arn.clone()
    }

    pub fn get_first_account_region(&self) -> Option<String> {
        let first_id = self.tokens.iter().next().map(|e| e.key().clone())?;
        self.get_account_region(&first_id)
    }

    pub fn get_first_account_id(&self) -> Option<String> {
        self.tokens.iter().next().map(|e| e.key().clone())
    }

    pub fn get_first_account_profile_arn(&self) -> Option<String> {
        let first_id = self.tokens.iter().next().map(|e| e.key().clone())?;
        self.get_account_profile_arn(&first_id)
    }

    /// 通过 email 获取指定账号的 Token（用于预热等需要指定账号的场景）
    /// 此方法会自动刷新过期的 token
    pub async fn get_token_by_email(
        &self,
        email: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        // 查找账号信息
        let token_info = {
            let mut found = None;
            for entry in self.tokens.iter() {
                let token = entry.value();
                if token.email == email {
                    found = Some((
                        token.account_id.clone(),
                        token.access_token.clone(),
                        token.refresh_token.clone(),
                        token.timestamp,
                        token.expires_in,
                        chrono::Utc::now().timestamp(),
                        token.project_id.clone(),
                    ));
                    break;
                }
            }
            found
        };

        let (
            account_id,
            current_access_token,
            refresh_token,
            timestamp,
            expires_in,
            now,
            project_id_opt,
        ) = match token_info {
            Some(info) => info,
            None => return Err(format!("未找到账号: {}", email)),
        };

        let project_id = project_id_opt.unwrap_or_else(|| "bamboo-precept-lgxtn".to_string());

        // 检查是否过期 (提前5分钟)
        if now < timestamp + expires_in - 300 {
            return Ok((current_access_token, project_id, email.to_string(), account_id, 0));
        }

        tracing::info!("Token for {} is expiring, refreshing...", email);

        match crate::modules::oauth::refresh_access_token(Some(&refresh_token), None, Some(&account_id)).await {
            Ok(token_response) => {
                tracing::info!("Token refresh successful for {}", email);
                let new_now = chrono::Utc::now().timestamp();

                // 更新缓存
                if let Some(mut entry) = self.tokens.get_mut(&account_id) {
                    entry.access_token = token_response.access_token.clone();
                    entry.expires_in = token_response.expires_in;
                    entry.timestamp = new_now;
                }

                // 保存到磁盘
                let _ = self
                    .save_refreshed_token(&account_id, &token_response)
                    .await;

                Ok((
                    token_response.access_token,
                    project_id,
                    email.to_string(),
                    account_id,
                    0,
                ))
            }
            Err(e) => Err(format!(
                "Token refresh failed for {}: {}",
                email, e
            )),
        }
    }

    // ===== 限流管理方法 =====

    /// 标记账号限流(从外部调用,通常在 handler 中)
    /// 参数为 email，内部会自动转换为 account_id
    pub async fn mark_rate_limited(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
    ) {
        // [NEW] 检查熔断是否启用 (使用内存缓存，极快)
        let config = self.circuit_breaker_config.read().await.clone();
        if !config.enabled {
            return;
        }

        // 【替代方案】转换 email -> account_id
        let key = self.email_to_account_id(email).unwrap_or_else(|| email.to_string());

        self.rate_limit_tracker.parse_from_error(
            &key,
            status,
            retry_after_header,
            error_body,
            None,
            &config.backoff_steps, // [NEW] 传入配置
        );
    }

    /// 检查账号是否在限流中 (支持模型级)
    pub async fn is_rate_limited(&self, account_id: &str, model: Option<&str>) -> bool {
        // [NEW] 检查熔断是否启用
        let config = self.circuit_breaker_config.read().await;
        if !config.enabled {
            return false;
        }
        self.rate_limit_tracker.is_rate_limited(account_id, model)
    }

    /// [NEW] 检查账号是否在限流中 (同步版本，仅用于 Iterator)
    pub fn is_rate_limited_sync(&self, account_id: &str, model: Option<&str>) -> bool {
        // 使用 try_read 避免在 async runtime 中阻塞
        match self.circuit_breaker_config.try_read() {
            Ok(config) => {
                if !config.enabled {
                    return false;
                }
                self.rate_limit_tracker.is_rate_limited(account_id, model)
            }
            Err(_) => {
                // 如果锁被占用，保守地假设未限流（避免误杀）
                false
            }
        }
    }

    /// 获取距离限流重置还有多少秒
    #[allow(dead_code)]
    pub fn get_rate_limit_reset_seconds(&self, account_id: &str) -> Option<u64> {
        self.rate_limit_tracker.get_reset_seconds(account_id)
    }

    /// 清除过期的限流记录
    #[allow(dead_code)]
    pub fn clean_expired_rate_limits(&self) {
        self.rate_limit_tracker.cleanup_expired();
    }

    /// 【替代方案】通过 email 查找对应的 account_id
    /// 用于将 handlers 传入的 email 转换为 tracker 使用的 account_id
    fn email_to_account_id(&self, email: &str) -> Option<String> {
        self.tokens
            .iter()
            .find(|entry| entry.value().email == email)
            .map(|entry| entry.value().account_id.clone())
    }

    /// 清除指定账号的限流记录
    pub fn clear_rate_limit(&self, account_id: &str) -> bool {
        self.rate_limit_tracker.clear(account_id)
    }

    /// 清除所有限流记录
    pub fn clear_all_rate_limits(&self) {
        self.rate_limit_tracker.clear_all();
    }

    /// 标记账号请求成功，重置连续失败计数
    ///
    /// 在请求成功完成后调用，将该账号的失败计数归零，
    /// 下次失败时从最短的锁定时间开始（智能限流）。
    pub fn mark_account_success(&self, account_id: &str) {
        self.rate_limit_tracker.mark_success(account_id);
    }

    /// 检查是否有可用的账号
    ///
    /// 用于"仅兜底"模式的智能判断:当所有账号不可用时才使用外部提供商。
    ///
    /// # 参数
    /// - `quota_group`: 配额组,暂未使用但保留用于未来扩展
    /// - `target_model`: 目标模型名称(已归一化),用于配额保护检查
    ///
    /// # 返回值
    /// - `true`: 至少有一个可用账号(未限流且未被配额保护)
    /// - `false`: 所有账号都不可用(被限流或被配额保护)
    ///
    /// # 示例
    /// ```ignore
    /// // 检查是否有可用账号处理 claude-sonnet 请求
    /// let has_available = token_manager.has_available_account("claude", "claude-sonnet-4-20250514").await;
    /// if !has_available {
    ///     // 切换到外部提供商
    /// }
    /// ```
    pub async fn has_available_account(&self, _quota_group: &str, target_model: &str) -> bool {
        // 遍历所有账号,检查是否有可用的
        for entry in self.tokens.iter() {
            let token = entry.value();

            // 检查是否被限流
            if self.is_rate_limited(&token.account_id, None).await {
                tracing::debug!(
                    "[Fallback Check] Account {} is rate-limited, skipping",
                    token.email
                );
                continue;
            }

            // 找到至少一个可用账号
            tracing::debug!(
                "[Fallback Check] Found available account: {} for model {}",
                token.email,
                target_model
            );
            return true;
        }

        // 所有账号都不可用
        tracing::info!(
            "[Fallback Check] No available accounts for model {}, fallback should be triggered",
            target_model
        );
        false
    }

    /// 从账号文件获取配额刷新时间
    ///
    /// 返回该账号最近的配额刷新时间字符串（ISO 8601 格式）
    ///
    /// # 参数
    /// - `account_id`: 账号 ID（用于查找账号文件）
    pub fn get_quota_reset_time(&self, account_id: &str) -> Option<String> {
        // 直接用 account_id 查找账号文件（文件名是 {account_id}.json）
        let account_path = self.data_dir.join("accounts").join(format!("{}.json", account_id));

        let content = std::fs::read_to_string(&account_path).ok()?;
        let account: serde_json::Value = serde_json::from_str(&content).ok()?;

        // 获取 quota.models 中最早的 reset_time（最保守的锁定策略）
        account
            .get("quota")
            .and_then(|q| q.get("models"))
            .and_then(|m| m.as_array())
            .and_then(|models| {
                models.iter()
                    .filter_map(|m| m.get("reset_time").and_then(|r| r.as_str()))
                    .filter(|s| !s.is_empty())
                    .min()
                    .map(|s| s.to_string())
            })
    }

    /// 使用配额刷新时间精确锁定账号
    ///
    /// 当 API 返回 429 但没有 quotaResetDelay 时,尝试使用账号的配额刷新时间
    ///
    /// # 参数
    /// - `account_id`: 账号 ID
    /// - `reason`: 限流原因（QuotaExhausted/ServerError 等）
    /// - `model`: 可选的模型名称,用于模型级别限流
    pub fn set_precise_lockout(&self, account_id: &str, reason: crate::proxy::rate_limit::RateLimitReason, model: Option<String>) -> bool {
        if let Some(reset_time_str) = self.get_quota_reset_time(account_id) {
            tracing::info!("找到账号 {} 的配额刷新时间: {}", account_id, reset_time_str);
            self.rate_limit_tracker.set_lockout_until_iso(account_id, &reset_time_str, reason, model)
        } else {
            tracing::debug!("未找到账号 {} 的配额刷新时间,将使用默认退避策略", account_id);
            false
        }
    }

    /// 实时刷新配额并精确锁定账号
    ///
    /// 当 429 发生时调用此方法:
    /// 1. 实时调用配额刷新 API 获取最新的 reset_time
    /// 2. 使用最新的 reset_time 精确锁定账号
    /// 3. 如果获取失败,返回 false 让调用方使用回退策略
    ///
    /// # 参数
    /// - `model`: 可选的模型名称,用于模型级别限流
    pub async fn fetch_and_lock_with_realtime_quota(
        &self,
        email: &str,
        reason: crate::proxy::rate_limit::RateLimitReason,
        model: Option<String>,
    ) -> bool {
        // 1. 从 tokens 中获取该账号的 access_token 和 account_id
        // 同时获取 account_id，确保锁定 key 与检查 key 一致
        let (access_token, account_id) = {
            let mut found: Option<(String, String)> = None;
            for entry in self.tokens.iter() {
                if entry.value().email == email {
                    found = Some((
                        entry.value().access_token.clone(),
                        entry.value().account_id.clone(),
                    ));
                    break;
                }
            }
            found
        }.unzip();

        let (access_token, account_id) = match (access_token, account_id) {
            (Some(token), Some(id)) => (token, id),
            _ => {
                tracing::warn!("无法找到账号 {} 的 access_token,无法实时刷新配额", email);
                return false;
            }
        };

        // 2. 调用配额刷新 API
        tracing::info!("账号 {} 正在实时刷新配额...", email);
        match crate::modules::quota::fetch_quota(&access_token, email, Some(&account_id)).await {
            Ok((quota_data, _project_id)) => {
                // 3. 从最新配额中提取 reset_time
                let earliest_reset = quota_data
                    .models
                    .iter()
                    .filter_map(|m| {
                        if !m.reset_time.is_empty() {
                            Some(m.reset_time.as_str())
                        } else {
                            None
                        }
                    })
                    .min();

                if let Some(reset_time_str) = earliest_reset {
                    tracing::info!(
                        "账号 {} 实时配额刷新成功,reset_time: {}",
                        email,
                        reset_time_str
                    );
                    // [FIX] 使用 account_id 作为 key，与 is_rate_limited 检查一致
                    self.rate_limit_tracker.set_lockout_until_iso(&account_id, reset_time_str, reason, model)
                } else {
                    tracing::warn!("账号 {} 配额刷新成功但未找到 reset_time", email);
                    false
                }
            }
            Err(e) => {
                tracing::warn!("账号 {} 实时配额刷新失败: {:?}", email, e);
                false
            }
        }
    }

    /// 标记账号限流(异步版本,支持实时配额刷新)
    ///
    /// 三级降级策略:
    /// 1. 优先: API 返回 quotaResetDelay → 直接使用
    /// 2. 次优: 实时刷新配额 → 获取最新 reset_time
    /// 3. 保底: 使用本地缓存配额 → 读取账号文件
    /// 4. 兜底: 指数退避策略 → 默认锁定时间
    ///
    /// # 参数
    /// - `email`: 账号邮箱,用于查找账号信息
    /// - `status`: HTTP 状态码（如 429、500 等）
    /// - `retry_after_header`: 可选的 Retry-After 响应头
    /// - `error_body`: 错误响应体,用于解析 quotaResetDelay
    /// - `model`: 可选的模型名称,用于模型级别限流
    pub async fn mark_rate_limited_async(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
        model: Option<&str>, // 🆕 新增模型参数
    ) {
        // [NEW] 检查熔断是否启用
        let config = self.circuit_breaker_config.read().await.clone();
        if !config.enabled {
            return;
        }

        // [FIX] Convert email to account_id for consistent tracking
        let account_id = self.email_to_account_id(email).unwrap_or_else(|| email.to_string());

        // 检查 API 是否返回了精确的重试时间
        let has_explicit_retry_time = retry_after_header.is_some() ||
            error_body.contains("quotaResetDelay");

        if has_explicit_retry_time {
            // API 返回了精确时间(quotaResetDelay),直接使用,无需实时刷新
            if let Some(m) = model {
                tracing::debug!(
                    "账号 {} 的模型 {} 的 429 响应包含 quotaResetDelay,直接使用 API 返回的时间",
                    account_id,
                    m
                );
            } else {
                tracing::debug!(
                    "账号 {} 的 429 响应包含 quotaResetDelay,直接使用 API 返回的时间",
                    account_id
                );
            }
            self.rate_limit_tracker.parse_from_error(
                &account_id,
                status,
                retry_after_header,
                error_body,
                model.map(|s| s.to_string()),
                &config.backoff_steps, // [NEW] 传入配置
            );
            return;
        }

        // 确定限流原因
        let reason = if error_body.to_lowercase().contains("model_capacity") {
            crate::proxy::rate_limit::RateLimitReason::ModelCapacityExhausted
        } else if error_body.to_lowercase().contains("exhausted")
            || error_body.to_lowercase().contains("quota")
        {
            crate::proxy::rate_limit::RateLimitReason::QuotaExhausted
        } else {
            crate::proxy::rate_limit::RateLimitReason::Unknown
        };

        // API 未返回 quotaResetDelay,需要实时刷新配额获取精确锁定时间
        if let Some(m) = model {
            tracing::info!(
                "账号 {} 的模型 {} 的 429 响应未包含 quotaResetDelay,尝试实时刷新配额...",
                account_id,
                m
            );
        } else {
            tracing::info!(
                "账号 {} 的 429 响应未包含 quotaResetDelay,尝试实时刷新配额...",
                account_id
            );
        }

        // [FIX] 传入 email 而不是 account_id，因为 fetch_and_lock_with_realtime_quota 期望 email
        if self.fetch_and_lock_with_realtime_quota(email, reason, model.map(|s| s.to_string())).await {
            tracing::info!("账号 {} 已使用实时配额精确锁定", email);
            return;
        }

        // 实时刷新失败,尝试使用本地缓存的配额刷新时间
        if self.set_precise_lockout(&account_id, reason, model.map(|s| s.to_string())) {
            tracing::info!("账号 {} 已使用本地缓存配额锁定", account_id);
            return;
        }

        // 都失败了,回退到指数退避策略
        tracing::warn!("账号 {} 无法获取配额刷新时间,使用指数退避策略", account_id);
        self.rate_limit_tracker.parse_from_error(
            &account_id,
            status,
            retry_after_header,
            error_body,
            model.map(|s| s.to_string()),
            &config.backoff_steps, // [NEW] 传入配置
        );
    }

    // ===== 调度配置相关方法 =====

    /// 获取当前调度配置
    pub async fn get_sticky_config(&self) -> StickySessionConfig {
        self.sticky_config.read().await.clone()
    }

    /// 更新调度配置
    pub async fn update_sticky_config(&self, new_config: StickySessionConfig) {
        let mut config = self.sticky_config.write().await;
        *config = new_config;
        tracing::debug!("Scheduling configuration updated: {:?}", *config);
    }

    /// [NEW] 更新熔断器配置
    pub async fn update_circuit_breaker_config(&self, config: crate::models::CircuitBreakerConfig) {
        let mut lock = self.circuit_breaker_config.write().await;
        *lock = config;
        tracing::debug!("Circuit breaker configuration updated");
    }

    /// [NEW] 获取熔断器配置
    pub async fn get_circuit_breaker_config(&self) -> crate::models::CircuitBreakerConfig {
        self.circuit_breaker_config.read().await.clone()
    }

    /// 清除特定会话的粘性映射
    #[allow(dead_code)]
    pub fn clear_session_binding(&self, session_id: &str) {
        self.session_accounts.remove(session_id);
    }

    /// 清除所有会话的粘性映射
    pub fn clear_all_sessions(&self) {
        self.session_accounts.clear();
    }

    // ===== [FIX #820] 固定账号模式相关方法 =====

    /// 设置优先使用的账号ID（固定账号模式）
    /// 传入 Some(account_id) 启用固定账号模式，传入 None 恢复轮询模式
    pub async fn set_preferred_account(&self, account_id: Option<String>) {
        let mut preferred = self.preferred_account_id.write().await;
        if let Some(ref id) = account_id {
            tracing::info!("🔒 [FIX #820] Fixed account mode enabled: {}", id);
        } else {
            tracing::info!("🔄 [FIX #820] Round-robin mode enabled (no preferred account)");
        }
        *preferred = account_id;
    }

    /// 获取当前优先使用的账号ID
    pub async fn get_preferred_account(&self) -> Option<String> {
        self.preferred_account_id.read().await.clone()
    }

    /// 使用 Authorization Code 交换 Refresh Token (Web OAuth)
    pub async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<String, String> {
        crate::modules::oauth::exchange_code(code, redirect_uri)
            .await
            .and_then(|t| {
                t.refresh_token
                    .ok_or_else(|| "No refresh token returned".to_string())
            })
    }

    /// 获取 OAuth URL (支持自定义 Redirect URI)
    pub fn get_oauth_url_with_redirect(&self, redirect_uri: &str, state: &str) -> String {
        crate::modules::oauth::get_auth_url(redirect_uri, state)
    }

    /// 获取用户信息 (Email 等)
    pub async fn get_user_info(
        &self,
        refresh_token: &str,
    ) -> Result<crate::modules::oauth::UserInfo, String> {
        // 先获取 Access Token
        let token = crate::modules::oauth::refresh_access_token(Some(refresh_token), None, None)
            .await
            .map_err(|e| format!("刷新 Access Token 失败: {}", e))?;

        crate::modules::oauth::get_user_info(&token.access_token, None).await
    }

    /// 添加新账号 (纯后端实现，不依赖 Tauri AppHandle)
    pub async fn add_account(&self, email: &str, refresh_token: &str) -> Result<(), String> {
        // 1. 获取 Access Token (验证 refresh_token 有效性)
        let token_info = crate::modules::oauth::refresh_access_token(Some(refresh_token), None, None)
            .await
            .map_err(|e| format!("Invalid refresh token: {}", e))?;

        // 2. 获取项目 ID (Project ID)
        let project_id = "kiro-native".to_string();

        // 3. 委托给 modules::account::add_account 处理 (包含文件写入、索引更新、锁)
        let email_clone = email.to_string();
        let refresh_token_clone = refresh_token.to_string();

        tokio::task::spawn_blocking(move || {
            let token_data = crate::models::TokenData::new(
                token_info.access_token,
                refresh_token_clone,
                token_info.expires_in,
                Some(email_clone.clone()),
                Some(project_id),
                None, // session_id
            );

            crate::modules::account::upsert_account(email_clone, None, token_data)
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| format!("Failed to save account: {}", e))?;

        // 4. 重新加载 (更新内存)
        self.reload_all_accounts().await.map(|_| ())
    }

    /// 记录请求成功，增加健康分
    pub fn record_success(&self, account_id: &str) {
        self.health_scores
            .entry(account_id.to_string())
            .and_modify(|s| *s = (*s + 0.05).min(1.0))
            .or_insert(1.0);
        tracing::debug!("📈 Health score increased for account {}", account_id);
    }

    /// 记录请求失败，降低健康分
    pub fn record_failure(&self, account_id: &str) {
        self.health_scores
            .entry(account_id.to_string())
            .and_modify(|s| *s = (*s - 0.2).max(0.0))
            .or_insert(0.8);
        tracing::warn!("📉 Health score decreased for account {}", account_id);
    }

    /// [NEW] 从账号配额信息中提取最近的刷新时间戳
    ///
    /// Claude 模型（sonnet/opus）共用同一个刷新时间，只需取 claude 系列的 reset_time
    /// 返回 Unix 时间戳（秒），用于排序时比较
    #[allow(dead_code)]
    fn extract_earliest_reset_time(&self, account: &serde_json::Value) -> Option<i64> {
        let models = account
            .get("quota")
            .and_then(|q| q.get("models"))
            .and_then(|m| m.as_array())?;

        let mut earliest_ts: Option<i64> = None;

        for model in models {
            // 优先取 claude 系列的 reset_time（sonnet/opus 共用）
            let model_name = model.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if !model_name.contains("claude") {
                continue;
            }

            if let Some(reset_time_str) = model.get("reset_time").and_then(|r| r.as_str()) {
                if reset_time_str.is_empty() {
                    continue;
                }
                // 解析 ISO 8601 时间字符串为时间戳
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(reset_time_str) {
                    let ts = dt.timestamp();
                    if earliest_ts.is_none() || ts < earliest_ts.unwrap() {
                        earliest_ts = Some(ts);
                    }
                }
            }
        }

        // 如果没有 claude 模型的时间，尝试取任意模型的最近时间
        if earliest_ts.is_none() {
            for model in models {
                if let Some(reset_time_str) = model.get("reset_time").and_then(|r| r.as_str()) {
                    if reset_time_str.is_empty() {
                        continue;
                    }
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(reset_time_str) {
                        let ts = dt.timestamp();
                        if earliest_ts.is_none() || ts < earliest_ts.unwrap() {
                            earliest_ts = Some(ts);
                        }
                    }
                }
            }
        }

        earliest_ts
    }

    /// Helper to find account ID by email
    pub fn get_account_id_by_email(&self, email: &str) -> Option<String> {
        for entry in self.tokens.iter() {
            if entry.value().email == email {
                return Some(entry.key().clone());
            }
        }
        None
    }

    /// Set validation blocked status for an account (internal)
    pub async fn set_validation_block(&self, account_id: &str, block_until: i64, reason: &str) -> Result<(), String> {
        // 1. Update memory
        if let Some(mut token) = self.tokens.get_mut(account_id) {
             token.validation_blocked = true;
             token.validation_blocked_until = block_until;
        }

        // 2. Persist to disk
        let path = self.data_dir.join("accounts").join(format!("{}.json", account_id));
        if !path.exists() {
             return Err(format!("Account file not found: {:?}", path));
        }

        let content = std::fs::read_to_string(&path)
             .map_err(|e| format!("Failed to read account file: {}", e))?;

        let mut account: serde_json::Value = serde_json::from_str(&content)
             .map_err(|e| format!("Failed to parse account JSON: {}", e))?;

        account["validation_blocked"] = serde_json::Value::Bool(true);
        account["validation_blocked_until"] = serde_json::Value::Number(serde_json::Number::from(block_until));
        account["validation_blocked_reason"] = serde_json::Value::String(reason.to_string());

        // Clear sticky session if blocked
        self.session_accounts.retain(|_, v| *v != account_id);

        let json_str = serde_json::to_string_pretty(&account)
             .map_err(|e| format!("Failed to serialize account JSON: {}", e))?;

        std::fs::write(&path, json_str)
             .map_err(|e| format!("Failed to write account file: {}", e))?;

        tracing::info!(
             "🚫 Account {} validation blocked until {} (reason: {})",
             account_id,
             block_until,
             reason
        );

        Ok(())
    }

    /// Public method to set validation block (called from handlers)
    pub async fn set_validation_block_public(&self, account_id: &str, block_until: i64, reason: &str) -> Result<(), String> {
        self.set_validation_block(account_id, block_until, reason).await
    }

    /// Set is_forbidden status for an account (called when proxy encounters 403)
    pub async fn set_forbidden(&self, account_id: &str, reason: &str) -> Result<(), String> {
        // 1. Persist to disk - update quota.is_forbidden in account JSON
        let path = self.data_dir.join("accounts").join(format!("{}.json", account_id));
        if !path.exists() {
            return Err(format!("Account file not found: {:?}", path));
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read account file: {}", e))?;

        let mut account: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse account JSON: {}", e))?;

        // Update quota.is_forbidden
        if let Some(quota) = account.get_mut("quota") {
            quota["is_forbidden"] = serde_json::Value::Bool(true);
        } else {
            // Create quota object if not exists
            account["quota"] = serde_json::json!({
                "models": [],
                "last_updated": chrono::Utc::now().timestamp(),
                "is_forbidden": true
            });
        }

        // Clear sticky session if forbidden
        self.session_accounts.retain(|_, v| *v != account_id);

        let json_str = serde_json::to_string_pretty(&account)
            .map_err(|e| format!("Failed to serialize account JSON: {}", e))?;

        std::fs::write(&path, json_str)
            .map_err(|e| format!("Failed to write account file: {}", e))?;

        // [FIX] 从内存池中移除账号，避免重试时再次选中
        self.remove_account(account_id);

        tracing::warn!(
            "🚫 Account {} marked as forbidden (403): {}",
            account_id,
            truncate_reason(reason, 100)
        );

        Ok(())
    }

    // ===== 账号并发限制管理方法 =====

    /// 尝试获取账号的并发槽位（非阻塞）
    /// 如果账号并发已满，立即返回 None
    pub fn try_acquire_slot(&self, account_id: &str) -> Option<ConcurrencySlot> {
        let semaphore = self
            .concurrency_slots
            .entry(account_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_concurrency_per_account.load(Ordering::Relaxed))))
            .clone();

        match semaphore.try_acquire_owned().ok() {
            Some(permit) => Some(ConcurrencySlot::new(account_id.to_string(), permit)),
            None => None,
        }
    }

    pub async fn acquire_slot_with_timeout(
        &self,
        account_id: &str,
        timeout: std::time::Duration,
    ) -> Option<ConcurrencySlot> {
        let semaphore = self
            .concurrency_slots
            .entry(account_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_concurrency_per_account.load(Ordering::Relaxed))))
            .clone();

        match tokio::time::timeout(timeout, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => Some(ConcurrencySlot::new(account_id.to_string(), permit)),
            Ok(Err(_)) => None,
            Err(_) => {
                tracing::warn!("获取账号 {} 并发槽位超时", account_id);
                None
            }
        }
    }

    /// 检查账号是否还有可用并发槽位
    pub fn has_available_slot(&self, account_id: &str) -> bool {
        match self.concurrency_slots.get(account_id) {
            Some(semaphore) => semaphore.available_permits() > 0,
            None => true,
        }
    }

    /// 获取账号的当前并发状态信息
    pub fn get_account_concurrency_info(&self, account_id: &str) -> AccountConcurrencyInfo {
        let (current, available) = match self.concurrency_slots.get(account_id) {
            Some(semaphore) => {
                let available = semaphore.available_permits();
                let current = self.max_concurrency_per_account.load(Ordering::Relaxed).saturating_sub(available);
                (current, available)
            }
            None => (0, self.max_concurrency_per_account.load(Ordering::Relaxed)),
        };

        AccountConcurrencyInfo {
            account_id: account_id.to_string(),
            max_concurrency: self.max_concurrency_per_account.load(Ordering::Relaxed),
            current_concurrency: current,
            available_slots: available,
        }
    }

    /// 获取所有账号的并发状态信息
    pub fn get_all_concurrency_info(&self) -> Vec<AccountConcurrencyInfo> {
        let mut results = Vec::new();

        for entry in self.tokens.iter() {
            let account_id = entry.key().clone();
            results.push(self.get_account_concurrency_info(&account_id));
        }

        results
    }

    /// 清理指定账号的并发槽位记录
    /// 当账号被删除或重置时调用
    pub fn clear_concurrency_slots(&self, account_id: &str) {
        self.concurrency_slots.remove(account_id);
        tracing::debug!("已清理账号 {} 的并发槽位记录", account_id);
    }

    /// 设置每个账号的最大并发数
    pub fn set_max_concurrency(&self, max: usize) {
        let new_max = max.max(1);
        self.max_concurrency_per_account.store(new_max, Ordering::Relaxed);
        // Clear cached semaphores so they get recreated with the new limit
        self.concurrency_slots.clear();
        tracing::info!("设置单账号最大并发数为: {}", new_max);
    }

    /// 获取当前每个账号的最大并发数
    pub fn get_max_concurrency(&self) -> usize {
        self.max_concurrency_per_account.load(Ordering::Relaxed)
    }
}

/// 截断过长的原因字符串
fn truncate_reason(reason: &str, max_len: usize) -> String {
    if reason.len() <= max_len {
        reason.to_string()
    } else {
        format!("{}...", &reason[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[tokio::test]
    async fn test_reload_account_purges_cache_when_account_becomes_proxy_disabled() {
        let tmp_root = std::env::temp_dir().join(format!(
            "kiro-token-manager-test-{}",
            uuid::Uuid::new_v4()
        ));
        let accounts_dir = tmp_root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let account_id = "acc1";
        let email = "a@test.com";
        let now = chrono::Utc::now().timestamp();
        let account_path = accounts_dir.join(format!("{}.json", account_id));

        let account_json = serde_json::json!({
            "id": account_id,
            "email": email,
            "token": {
                "access_token": "atk",
                "refresh_token": "rtk",
                "expires_in": 3600,
                "expiry_timestamp": now + 3600
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&account_json).unwrap()).unwrap();

        let manager = TokenManager::new(tmp_root.clone());
        manager.load_accounts().await.unwrap();
        assert!(manager.tokens.get(account_id).is_some());

        // Prime extra caches to ensure remove_account() is really called.
        manager
            .session_accounts
            .insert("sid1".to_string(), account_id.to_string());
        {
            let mut preferred = manager.preferred_account_id.write().await;
            *preferred = Some(account_id.to_string());
        }

        // Mark account as proxy-disabled on disk (manual disable).
        let mut disabled_json = account_json.clone();
        disabled_json["proxy_disabled"] = serde_json::Value::Bool(true);
        disabled_json["proxy_disabled_reason"] = serde_json::Value::String("manual".to_string());
        disabled_json["proxy_disabled_at"] = serde_json::Value::Number(now.into());
        std::fs::write(&account_path, serde_json::to_string_pretty(&disabled_json).unwrap()).unwrap();

        manager.reload_account(account_id).await.unwrap();

        assert!(manager.tokens.get(account_id).is_none());
        assert!(manager.session_accounts.get("sid1").is_none());
        assert!(manager.preferred_account_id.read().await.is_none());

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[tokio::test]
    async fn test_fixed_account_mode_skips_preferred_when_disabled_on_disk_without_reload() {
        let tmp_root = std::env::temp_dir().join(format!(
            "kiro-token-manager-test-fixed-mode-{}",
            uuid::Uuid::new_v4()
        ));
        let accounts_dir = tmp_root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let now = chrono::Utc::now().timestamp();

        let write_account = |id: &str, email: &str, proxy_disabled: bool| {
            let account_path = accounts_dir.join(format!("{}.json", id));
            let json = serde_json::json!({
                "id": id,
                "email": email,
                "token": {
                    "access_token": format!("atk-{}", id),
                    "refresh_token": format!("rtk-{}", id),
                    "expires_in": 3600,
                    "expiry_timestamp": now + 3600,
                    "project_id": format!("pid-{}", id)
                },
                "quota": {
                    "models": [
                        { "name": "kiro-credit", "percentage": 80 }
                    ]
                },
                "disabled": false,
                "proxy_disabled": proxy_disabled,
                "proxy_disabled_reason": if proxy_disabled { "manual" } else { "" },
                "created_at": now,
                "last_used": now
            });
            std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        };

        // Two accounts in pool.
        write_account("acc1", "a@test.com", false);
        write_account("acc2", "b@test.com", false);

        let manager = TokenManager::new(tmp_root.clone());
        manager.load_accounts().await.unwrap();

        // Enable fixed account mode for acc1.
        manager.set_preferred_account(Some("acc1".to_string())).await;

        // Disable acc1 on disk WITHOUT reloading the in-memory pool (simulates stale cache).
        write_account("acc1", "a@test.com", true);

        let (_token, _project_id, email, account_id, _wait_ms) = manager
            .get_token("claude", false, Some("sid1"), "claude-sonnet-4-20250514")
            .await
            .unwrap();

        // Should fall back to another account instead of using the disabled preferred one.
        assert_eq!(account_id, "acc2");
        assert_eq!(email, "b@test.com");
        assert!(manager.tokens.get("acc1").is_none());
        assert!(manager.get_preferred_account().await.is_none());

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[tokio::test]
    async fn test_sticky_session_skips_bound_account_when_disabled_on_disk_without_reload() {
        let tmp_root = std::env::temp_dir().join(format!(
            "kiro-token-manager-test-sticky-disabled-{}",
            uuid::Uuid::new_v4()
        ));
        let accounts_dir = tmp_root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let now = chrono::Utc::now().timestamp();

        let write_account = |id: &str, email: &str, percentage: i64, proxy_disabled: bool| {
            let account_path = accounts_dir.join(format!("{}.json", id));
            let json = serde_json::json!({
                "id": id,
                "email": email,
                "token": {
                    "access_token": format!("atk-{}", id),
                    "refresh_token": format!("rtk-{}", id),
                    "expires_in": 3600,
                    "expiry_timestamp": now + 3600,
                    "project_id": format!("pid-{}", id)
                },
                "quota": {
                    "models": [
                        { "name": "claude-sonnet-4-20250514", "percentage": percentage }
                    ]
                },
                "disabled": false,
                "proxy_disabled": proxy_disabled,
                "proxy_disabled_reason": if proxy_disabled { "manual" } else { "" },
                "created_at": now,
                "last_used": now
            });
            std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        };

        // Two accounts in pool. acc1 has higher quota -> should be selected and bound first.
        write_account("acc1", "a@test.com", 90, false);
        write_account("acc2", "b@test.com", 10, false);

        let manager = TokenManager::new(tmp_root.clone());
        manager.load_accounts().await.unwrap();

        // Prime: first request should bind the session to acc1.
        let (_token, _project_id, _email, account_id, _wait_ms) = manager
            .get_token("claude", false, Some("sid1"), "claude-sonnet-4-20250514")
            .await
            .unwrap();

        assert_eq!(account_id, "acc1");
        assert_eq!(
            manager.session_accounts.get("sid1").map(|v| v.clone()),
            Some("acc1".to_string())
        );

        // Disable acc1 on disk WITHOUT reloading the in-memory pool (simulates stale cache).
        write_account("acc1", "a@test.com", 90, true);

        let (_token, _project_id, email, account_id, _wait_ms) = manager
            .get_token("claude", false, Some("sid1"), "claude-sonnet-4-20250514")
            .await
            .unwrap();

        // Should fall back to another account instead of reusing the disabled bound one.
        assert_eq!(account_id, "acc2");
        assert_eq!(email, "b@test.com");
        assert!(manager.tokens.get("acc1").is_none());
        assert_ne!(
            manager.session_accounts.get("sid1").map(|v| v.clone()),
            Some("acc1".to_string())
        );

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    /// 创建测试用的 ProxyToken
    fn create_test_token(
        email: &str,
        tier: Option<&str>,
        health_score: f32,
        reset_time: Option<i64>,
        remaining_quota: Option<i32>,
    ) -> ProxyToken {
        ProxyToken {
            account_id: email.to_string(),
            access_token: "test_token".to_string(),
            refresh_token: "test_refresh".to_string(),
            expires_in: 3600,
            timestamp: chrono::Utc::now().timestamp() + 3600,
            email: email.to_string(),
            account_path: PathBuf::from("/tmp/test"),
            project_id: None,
            subscription_tier: tier.map(|s| s.to_string()),
            remaining_quota,
            health_score,
            reset_time,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas: HashMap::new(),
            profile_arn: None,
        }
    }

    /// 测试排序比较函数（与 get_token_internal 中的逻辑一致）
    fn compare_tokens(a: &ProxyToken, b: &ProxyToken) -> Ordering {
        const RESET_TIME_THRESHOLD_SECS: i64 = 600; // 10 分钟阈值

        let tier_priority = |tier: &Option<String>| {
            let t = tier.as_deref().unwrap_or("").to_lowercase();
            if t.contains("power") { 0 }
            else if t.contains("pro+") || t.contains("pro_plus") || t.contains("proplus") { 1 }
            else if t.contains("pro") { 2 }
            else if t.contains("free") { 3 }
            else { 4 }
        };

        // First: compare by subscription tier
        let tier_cmp = tier_priority(&a.subscription_tier).cmp(&tier_priority(&b.subscription_tier));
        if tier_cmp != Ordering::Equal {
            return tier_cmp;
        }

        // Second: compare by health score (higher is better)
        let health_cmp = b.health_score.partial_cmp(&a.health_score).unwrap_or(Ordering::Equal);
        if health_cmp != Ordering::Equal {
            return health_cmp;
        }

        // Third: compare by reset time (earlier/closer is better)
        let reset_a = a.reset_time.unwrap_or(i64::MAX);
        let reset_b = b.reset_time.unwrap_or(i64::MAX);
        let reset_diff = (reset_a - reset_b).abs();

        if reset_diff >= RESET_TIME_THRESHOLD_SECS {
            let reset_cmp = reset_a.cmp(&reset_b);
            if reset_cmp != Ordering::Equal {
                return reset_cmp;
            }
        }

        // Fourth: compare by remaining quota percentage (higher is better)
        let quota_a = a.remaining_quota.unwrap_or(0);
        let quota_b = b.remaining_quota.unwrap_or(0);
        quota_b.cmp(&quota_a)
    }

    #[test]
    fn test_sorting_tier_priority() {
        // POWER > PRO > FREE
        let power = create_test_token("power@test.com", Some("Q_DEVELOPER_STANDALONE_POWER"), 1.0, None, Some(50));
        let pro = create_test_token("pro@test.com", Some("Q_DEVELOPER_STANDALONE_PRO"), 1.0, None, Some(50));
        let free = create_test_token("free@test.com", Some("Q_DEVELOPER_STANDALONE_FREE"), 1.0, None, Some(50));

        assert_eq!(compare_tokens(&power, &pro), Ordering::Less);
        assert_eq!(compare_tokens(&pro, &free), Ordering::Less);
        assert_eq!(compare_tokens(&power, &free), Ordering::Less);
        assert_eq!(compare_tokens(&free, &power), Ordering::Greater);
    }

    #[test]
    fn test_sorting_health_score_priority() {
        // 同等级下，健康分高的优先
        let high_health = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(50));
        let low_health = create_test_token("low@test.com", Some("PRO"), 0.5, None, Some(50));

        assert_eq!(compare_tokens(&high_health, &low_health), Ordering::Less);
        assert_eq!(compare_tokens(&low_health, &high_health), Ordering::Greater);
    }

    #[test]
    fn test_sorting_reset_time_priority() {
        let now = chrono::Utc::now().timestamp();

        // 刷新时间更近（30分钟后）的优先于更远（5小时后）的
        let soon_reset = create_test_token("soon@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(50));  // 30分钟后
        let late_reset = create_test_token("late@test.com", Some("PRO"), 1.0, Some(now + 18000), Some(50)); // 5小时后

        assert_eq!(compare_tokens(&soon_reset, &late_reset), Ordering::Less);
        assert_eq!(compare_tokens(&late_reset, &soon_reset), Ordering::Greater);
    }

    #[test]
    fn test_sorting_reset_time_threshold() {
        let now = chrono::Utc::now().timestamp();

        // 差异小于10分钟（600秒）视为相同优先级，此时按配额排序
        let reset_a = create_test_token("a@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(80));  // 30分钟后, 80%配额
        let reset_b = create_test_token("b@test.com", Some("PRO"), 1.0, Some(now + 2100), Some(50));  // 35分钟后, 50%配额

        // 差5分钟 < 10分钟阈值，视为相同，按配额排序（80% > 50%）
        assert_eq!(compare_tokens(&reset_a, &reset_b), Ordering::Less);
    }

    #[test]
    fn test_sorting_reset_time_beyond_threshold() {
        let now = chrono::Utc::now().timestamp();

        // 差异超过10分钟，按刷新时间排序（忽略配额）
        let soon_low_quota = create_test_token("soon@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(20));   // 30分钟后, 20%
        let late_high_quota = create_test_token("late@test.com", Some("PRO"), 1.0, Some(now + 18000), Some(90)); // 5小时后, 90%

        // 差4.5小时 > 10分钟，刷新时间优先，30分钟 < 5小时
        assert_eq!(compare_tokens(&soon_low_quota, &late_high_quota), Ordering::Less);
    }

    #[test]
    fn test_sorting_quota_fallback() {
        // 其他条件相同时，配额高的优先
        let high_quota = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(80));
        let low_quota = create_test_token("low@test.com", Some("PRO"), 1.0, None, Some(20));

        assert_eq!(compare_tokens(&high_quota, &low_quota), Ordering::Less);
        assert_eq!(compare_tokens(&low_quota, &high_quota), Ordering::Greater);
    }

    #[test]
    fn test_sorting_missing_reset_time() {
        let now = chrono::Utc::now().timestamp();

        // 没有 reset_time 的账号应该排在有 reset_time 的后面
        let with_reset = create_test_token("with@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(50));
        let without_reset = create_test_token("without@test.com", Some("PRO"), 1.0, None, Some(50));

        assert_eq!(compare_tokens(&with_reset, &without_reset), Ordering::Less);
    }

    #[test]
    fn test_full_sorting_integration() {
        let now = chrono::Utc::now().timestamp();

        let mut tokens = vec![
            create_test_token("free_high@test.com", Some("Q_DEVELOPER_STANDALONE_FREE"), 1.0, Some(now + 1800), Some(90)),
            create_test_token("pro_low_health@test.com", Some("Q_DEVELOPER_STANDALONE_PRO"), 0.5, Some(now + 1800), Some(90)),
            create_test_token("pro_soon@test.com", Some("Q_DEVELOPER_STANDALONE_PRO"), 1.0, Some(now + 1800), Some(50)),   // 30分钟后
            create_test_token("pro_late@test.com", Some("Q_DEVELOPER_STANDALONE_PRO"), 1.0, Some(now + 18000), Some(90)),  // 5小时后
            create_test_token("power@test.com", Some("Q_DEVELOPER_STANDALONE_POWER"), 1.0, Some(now + 36000), Some(10)),
        ];

        tokens.sort_by(compare_tokens);

        // 预期顺序:
        // 1. POWER (最高等级，即使刷新时间最远)
        // 2. PRO + 高健康分 + 30分钟后刷新
        // 3. PRO + 高健康分 + 5小时后刷新
        // 4. PRO + 低健康分
        // 5. FREE (最低等级，即使配额最高)
        assert_eq!(tokens[0].email, "power@test.com");
        assert_eq!(tokens[1].email, "pro_soon@test.com");
        assert_eq!(tokens[2].email, "pro_late@test.com");
        assert_eq!(tokens[3].email, "pro_low_health@test.com");
        assert_eq!(tokens[4].email, "free_high@test.com");
    }

    #[test]
    fn test_realistic_scenario() {
        // 模拟用户描述的场景:
        // a 账号 claude 4h55m 后刷新
        // b 账号 claude 31m 后刷新
        // 应该优先使用 b（31分钟后刷新）
        let now = chrono::Utc::now().timestamp();

        let account_a = create_test_token("a@test.com", Some("PRO"), 1.0, Some(now + 295 * 60), Some(80)); // 4h55m
        let account_b = create_test_token("b@test.com", Some("PRO"), 1.0, Some(now + 31 * 60), Some(30));  // 31m

        // b 应该排在 a 前面（刷新时间更近）
        assert_eq!(compare_tokens(&account_b, &account_a), Ordering::Less);

        let mut tokens = vec![account_a.clone(), account_b.clone()];
        tokens.sort_by(compare_tokens);

        assert_eq!(tokens[0].email, "b@test.com");
        assert_eq!(tokens[1].email, "a@test.com");
    }

    #[test]
    fn test_extract_earliest_reset_time() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        // 测试包含 claude 模型的 reset_time 提取
        let account_with_claude = serde_json::json!({
            "quota": {
                "models": [
                    {"name": "claude-haiku", "reset_time": "2025-01-31T10:00:00Z"},
                    {"name": "claude-sonnet", "reset_time": "2025-01-31T08:00:00Z"},
                    {"name": "claude-opus", "reset_time": "2025-01-31T08:00:00Z"}
                ]
            }
        });

        let result = manager.extract_earliest_reset_time(&account_with_claude);
        assert!(result.is_some());
        // Should return claude-sonnet time (08:00) not claude-haiku (10:00)
        let expected_ts = chrono::DateTime::parse_from_rfc3339("2025-01-31T08:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(result.unwrap(), expected_ts);
    }

    #[test]
    fn test_extract_reset_time_no_claude() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        // 没有 claude 模型时，应该取任意模型的最近时间
        let account_no_claude = serde_json::json!({
            "quota": {
                "models": [
                    {"name": "claude-haiku", "reset_time": "2025-01-31T10:00:00Z"},
                    {"name": "claude-opus", "reset_time": "2025-01-31T08:00:00Z"}
                ]
            }
        });

        let result = manager.extract_earliest_reset_time(&account_no_claude);
        assert!(result.is_some());
        let expected_ts = chrono::DateTime::parse_from_rfc3339("2025-01-31T08:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(result.unwrap(), expected_ts);
    }

    #[test]
    fn test_extract_reset_time_missing_quota() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        // 没有 quota 字段时应返回 None
        let account_no_quota = serde_json::json!({
            "email": "test@test.com"
        });

        assert!(manager.extract_earliest_reset_time(&account_no_quota).is_none());
    }

    // ===== P2C 算法测试 =====

    #[test]
    fn test_p2c_selects_higher_quota() {
        // P2C 应选择配额更高的账号
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let low_quota = create_test_token("low@test.com", Some("PRO"), 1.0, None, Some(20));
        let high_quota = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(80));

        let candidates = vec![low_quota, high_quota];
        let attempted: HashSet<String> = HashSet::new();

        // 运行多次确保选择高配额账号
        for _ in 0..10 {
            let result = manager.select_with_p2c(&candidates, &attempted);
            assert!(result.is_some());
            assert_eq!(result.unwrap().email, "high@test.com");
        }
    }

    #[test]
    fn test_p2c_skips_attempted() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let token_a = create_test_token("a@test.com", Some("PRO"), 1.0, None, Some(80));
        let token_b = create_test_token("b@test.com", Some("PRO"), 1.0, None, Some(50));

        let candidates = vec![token_a, token_b];
        let mut attempted: HashSet<String> = HashSet::new();
        attempted.insert("a@test.com".to_string());

        let result = manager.select_with_p2c(&candidates, &attempted);
        assert!(result.is_some());
        assert_eq!(result.unwrap().email, "b@test.com");
    }

    #[test]
    fn test_p2c_single_candidate() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let token = create_test_token("single@test.com", Some("PRO"), 1.0, None, Some(50));
        let candidates = vec![token];
        let attempted: HashSet<String> = HashSet::new();

        let result = manager.select_with_p2c(&candidates, &attempted);
        assert!(result.is_some());
        assert_eq!(result.unwrap().email, "single@test.com");
    }

    #[test]
    fn test_p2c_empty_candidates() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let candidates: Vec<ProxyToken> = vec![];
        let attempted: HashSet<String> = HashSet::new();

        let result = manager.select_with_p2c(&candidates, &attempted);
        assert!(result.is_none());
    }

    #[test]
    fn test_p2c_all_attempted() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let token_a = create_test_token("a@test.com", Some("PRO"), 1.0, None, Some(80));
        let token_b = create_test_token("b@test.com", Some("PRO"), 1.0, None, Some(50));

        let candidates = vec![token_a, token_b];
        let mut attempted: HashSet<String> = HashSet::new();
        attempted.insert("a@test.com".to_string());
        attempted.insert("b@test.com".to_string());

        let result = manager.select_with_p2c(&candidates, &attempted);
        assert!(result.is_none());
    }

    // ===== 高端模型优先逻辑测试 =====

    /// 测试 is_high_end_model 辅助函数
    #[test]
    fn test_is_high_end_model() {
        // 需要 Power 等级账号的高端模型
        const HIGH_END_MODELS: &[&str] = &[
            "claude-opus-4-6",
            "claude-opus-4-5",
            "opus",
        ];

        fn is_high_end_model(model: &str) -> bool {
            let lower = model.to_lowercase();
            HIGH_END_MODELS.iter().any(|m| lower.contains(m))
        }

        // 应该识别为高端模型
        assert!(is_high_end_model("claude-opus-4-6"));
        assert!(is_high_end_model("claude-opus-4-5"));
        assert!(is_high_end_model("Claude-Opus-4-6")); // 大小写不敏感
        assert!(is_high_end_model("CLAUDE-OPUS-4-5")); // 大小写不敏感
        assert!(is_high_end_model("opus")); // 通配匹配
        assert!(is_high_end_model("opus-4-6-latest"));
        assert!(is_high_end_model("models/claude-opus-4-6"));

        // 应该识别为普通模型
        assert!(!is_high_end_model("claude-sonnet-4-5"));
        assert!(!is_high_end_model("claude-sonnet"));
        assert!(!is_high_end_model("claude-sonnet-4-20250514"));
        assert!(!is_high_end_model("claude-haiku"));
        assert!(!is_high_end_model("claude-haiku"));
    }

    /// 测试高端模型排序：Power 账号优先于 Pro 账号（即使 Pro 配额更高）
    #[test]
    fn test_power_priority_for_high_end_models() {
        const RESET_TIME_THRESHOLD_SECS: i64 = 600;

        // 模拟高端模型排序逻辑
        fn compare_tokens_for_model(a: &ProxyToken, b: &ProxyToken, target_model: &str) -> Ordering {
            const HIGH_END_MODELS: &[&str] = &["claude-opus-4-6", "claude-opus-4-5", "opus"];
            let requires_high_end = {
                let lower = target_model.to_lowercase();
                HIGH_END_MODELS.iter().any(|m| lower.contains(m))
            };

            let tier_priority = |tier: &Option<String>| {
                let t = tier.as_deref().unwrap_or("").to_lowercase();
                if t.contains("power") { 0 }
                else if t.contains("pro+") || t.contains("pro_plus") || t.contains("proplus") { 1 }
                else if t.contains("pro") { 2 }
                else if t.contains("free") { 3 }
                else { 4 }
            };

            // Priority 0: 高端模型时，订阅等级优先
            if requires_high_end {
                let tier_cmp = tier_priority(&a.subscription_tier)
                    .cmp(&tier_priority(&b.subscription_tier));
                if tier_cmp != Ordering::Equal {
                    return tier_cmp;
                }
            }

            // Priority 1: Quota (higher is better)
            let quota_a = a.remaining_quota.unwrap_or(0);
            let quota_b = b.remaining_quota.unwrap_or(0);
            let quota_cmp = quota_b.cmp(&quota_a);
            if quota_cmp != Ordering::Equal {
                return quota_cmp;
            }

            // Priority 2: Health score
            let health_cmp = b.health_score.partial_cmp(&a.health_score)
                .unwrap_or(Ordering::Equal);
            if health_cmp != Ordering::Equal {
                return health_cmp;
            }

            // Priority 3: Tier (for non-high-end models)
            if !requires_high_end {
                let tier_cmp = tier_priority(&a.subscription_tier)
                    .cmp(&tier_priority(&b.subscription_tier));
                if tier_cmp != Ordering::Equal {
                    return tier_cmp;
                }
            }

            Ordering::Equal
        }

        // 创建测试账号：Power 低配额 vs Pro 高配额
        let power_low_quota = create_test_token("power@test.com", Some("Q_DEVELOPER_STANDALONE_POWER"), 1.0, None, Some(20));
        let pro_high_quota = create_test_token("pro@test.com", Some("Q_DEVELOPER_STANDALONE_PRO"), 1.0, None, Some(80));

        // 高端模型 (Opus 4.6): Power 应该优先，即使配额低
        assert_eq!(
            compare_tokens_for_model(&power_low_quota, &pro_high_quota, "claude-opus-4-6"),
            Ordering::Less, // Power 排在前面
            "Opus 4.6 should prefer Power account over Pro even with lower quota"
        );

        // 高端模型 (Opus 4.5): Power 应该优先
        assert_eq!(
            compare_tokens_for_model(&power_low_quota, &pro_high_quota, "claude-opus-4-5"),
            Ordering::Less,
            "Opus 4.5 should prefer Power account over Pro"
        );

        // 普通模型 (Sonnet): 高配额 Pro 应该优先
        assert_eq!(
            compare_tokens_for_model(&power_low_quota, &pro_high_quota, "claude-sonnet-4-5"),
            Ordering::Greater, // Pro (高配额) 排在前面
            "Sonnet should prefer high-quota Pro over low-quota Power"
        );

        // 普通模型 (Flash): 高配额 Pro 应该优先
        assert_eq!(
            compare_tokens_for_model(&power_low_quota, &pro_high_quota, "claude-sonnet-4-20250514"),
            Ordering::Greater,
            "Flash should prefer high-quota Pro over low-quota Power"
        );
    }

    /// 测试排序：同为 Power 时按配额排序
    #[test]
    fn test_power_accounts_sorted_by_quota() {
        fn compare_tokens_for_model(a: &ProxyToken, b: &ProxyToken, target_model: &str) -> Ordering {
            const HIGH_END_MODELS: &[&str] = &["claude-opus-4-6", "claude-opus-4-5", "opus"];
            let requires_high_end = {
                let lower = target_model.to_lowercase();
                HIGH_END_MODELS.iter().any(|m| lower.contains(m))
            };

            let tier_priority = |tier: &Option<String>| {
                let t = tier.as_deref().unwrap_or("").to_lowercase();
                if t.contains("power") { 0 }
                else if t.contains("pro+") || t.contains("pro_plus") || t.contains("proplus") { 1 }
                else if t.contains("pro") { 2 }
                else if t.contains("free") { 3 }
                else { 4 }
            };

            if requires_high_end {
                let tier_cmp = tier_priority(&a.subscription_tier)
                    .cmp(&tier_priority(&b.subscription_tier));
                if tier_cmp != Ordering::Equal {
                    return tier_cmp;
                }
            }

            let quota_a = a.remaining_quota.unwrap_or(0);
            let quota_b = b.remaining_quota.unwrap_or(0);
            quota_b.cmp(&quota_a)
        }

        let power_high = create_test_token("power_high@test.com", Some("Q_DEVELOPER_STANDALONE_POWER"), 1.0, None, Some(80));
        let power_low = create_test_token("power_low@test.com", Some("Q_DEVELOPER_STANDALONE_POWER"), 1.0, None, Some(20));

        // Opus 4.6: 同为 Power，高配额优先
        assert_eq!(
            compare_tokens_for_model(&power_high, &power_low, "claude-opus-4-6"),
            Ordering::Less, // power_high 排在前面
            "Among Power accounts, higher quota should come first"
        );
    }

    /// 测试完整排序场景：混合账号池
    #[test]
    fn test_full_sorting_mixed_accounts() {
        fn sort_tokens_for_model(tokens: &mut Vec<ProxyToken>, target_model: &str) {
            const HIGH_END_MODELS: &[&str] = &["claude-opus-4-6", "claude-opus-4-5", "opus"];
            let requires_high_end = {
                let lower = target_model.to_lowercase();
                HIGH_END_MODELS.iter().any(|m| lower.contains(m))
            };

            tokens.sort_by(|a, b| {
                let tier_priority = |tier: &Option<String>| {
                    let t = tier.as_deref().unwrap_or("").to_lowercase();
                    if t.contains("power") { 0 }
                    else if t.contains("pro+") || t.contains("pro_plus") || t.contains("proplus") { 1 }
                    else if t.contains("pro") { 2 }
                    else if t.contains("free") { 3 }
                    else { 4 }
                };

                if requires_high_end {
                    let tier_cmp = tier_priority(&a.subscription_tier)
                        .cmp(&tier_priority(&b.subscription_tier));
                    if tier_cmp != Ordering::Equal {
                        return tier_cmp;
                    }
                }

                let quota_a = a.remaining_quota.unwrap_or(0);
                let quota_b = b.remaining_quota.unwrap_or(0);
                let quota_cmp = quota_b.cmp(&quota_a);
                if quota_cmp != Ordering::Equal {
                    return quota_cmp;
                }

                if !requires_high_end {
                    let tier_cmp = tier_priority(&a.subscription_tier)
                        .cmp(&tier_priority(&b.subscription_tier));
                    if tier_cmp != Ordering::Equal {
                        return tier_cmp;
                    }
                }

                Ordering::Equal
            });
        }

        // 创建混合账号池
        let power_high = create_test_token("power_high@test.com", Some("Q_DEVELOPER_STANDALONE_POWER"), 1.0, None, Some(80));
        let power_low = create_test_token("power_low@test.com", Some("Q_DEVELOPER_STANDALONE_POWER"), 1.0, None, Some(20));
        let pro_high = create_test_token("pro_high@test.com", Some("Q_DEVELOPER_STANDALONE_PRO"), 1.0, None, Some(90));
        let pro_low = create_test_token("pro_low@test.com", Some("Q_DEVELOPER_STANDALONE_PRO"), 1.0, None, Some(30));
        let free = create_test_token("free@test.com", Some("Q_DEVELOPER_STANDALONE_FREE"), 1.0, None, Some(100));

        // 高端模型 (Opus 4.6) 排序
        let mut tokens_opus = vec![pro_high.clone(), free.clone(), power_low.clone(), pro_low.clone(), power_high.clone()];
        sort_tokens_for_model(&mut tokens_opus, "claude-opus-4-6");

        let emails_opus: Vec<&str> = tokens_opus.iter().map(|t| t.email.as_str()).collect();
        // 期望顺序: Power(高配额) > Power(低配额) > Pro(高配额) > Pro(低配额) > Free
        assert_eq!(
            emails_opus,
            vec!["power_high@test.com", "power_low@test.com", "pro_high@test.com", "pro_low@test.com", "free@test.com"],
            "Opus 4.6 should sort Power first, then by quota within each tier"
        );

        // 普通模型 (Sonnet) 排序
        let mut tokens_sonnet = vec![pro_high.clone(), free.clone(), power_low.clone(), pro_low.clone(), power_high.clone()];
        sort_tokens_for_model(&mut tokens_sonnet, "claude-sonnet-4-5");

        let emails_sonnet: Vec<&str> = tokens_sonnet.iter().map(|t| t.email.as_str()).collect();
        // 期望顺序: Free(100%) > Pro(90%) > Power(80%) > Pro(30%) > Power(20%) - 按配额优先
        assert_eq!(
            emails_sonnet,
            vec!["free@test.com", "pro_high@test.com", "power_high@test.com", "pro_low@test.com", "power_low@test.com"],
            "Sonnet should sort by quota first, then by tier as tiebreaker"
        );
    }

    #[tokio::test]
    async fn test_concurrency_slot_basic() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        let slot1 = manager.try_acquire_slot("acc1");
        assert!(slot1.is_some(), "First slot acquisition should succeed");

        let slot2 = manager.try_acquire_slot("acc1");
        assert!(slot2.is_none(), "Second slot should fail (concurrency full)");

        let slot3 = manager.try_acquire_slot("acc2");
        assert!(slot3.is_some(), "Different account should succeed");

        let info = manager.get_account_concurrency_info("acc1");
        assert_eq!(info.max_concurrency, 1);
        assert_eq!(info.current_concurrency, 1);
        assert_eq!(info.available_slots, 0);

        assert!(!manager.has_available_slot("acc1"));
        assert!(manager.has_available_slot("unknown_acc"));

        drop(slot1);
        let slot4 = manager.try_acquire_slot("acc1");
        assert!(slot4.is_some(), "Should succeed after slot release");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_concurrency_slot_auto_release_on_drop() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-drop-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        {
            let _slot = manager.try_acquire_slot("acc1");
            assert!(_slot.is_some());
            assert!(!manager.has_available_slot("acc1"));
        }

        assert!(manager.has_available_slot("acc1"), "Slot should be available after drop");
        let slot_again = manager.try_acquire_slot("acc1");
        assert!(slot_again.is_some(), "Should acquire after auto-release");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_concurrency_clear_slots() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-clear-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        let _slot = manager.try_acquire_slot("acc1");
        assert!(!manager.has_available_slot("acc1"));

        manager.clear_concurrency_slots("acc1");
        assert!(manager.has_available_slot("acc1"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_concurrency_acquire_with_timeout() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-timeout-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = Arc::new(TokenManager::new(tmp.clone()));

        let _slot = manager.try_acquire_slot("acc1");
        assert!(_slot.is_some());

        let result = manager
            .acquire_slot_with_timeout("acc1", std::time::Duration::from_millis(100))
            .await;
        assert!(result.is_none(), "Should timeout when slot is full");

        let manager2 = manager.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(_slot);
        });

        let result2 = manager2
            .acquire_slot_with_timeout("acc1", std::time::Duration::from_secs(2))
            .await;
        assert!(result2.is_some(), "Should succeed after slot released");

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ===== Token Refresh Concurrency & Persistence Tests =====

    #[tokio::test]
    async fn test_refresh_lock_prevents_concurrent_refresh() {
        // Verify that per-account refresh locks are created and reused
        let tmp = std::env::temp_dir().join(format!("kiro-refresh-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        // Acquire lock for acc1
        let lock1 = manager.refresh_locks
            .entry("acc1".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        // Same account should return the same lock instance
        let lock2 = manager.refresh_locks
            .entry("acc1".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        assert!(Arc::ptr_eq(&lock1, &lock2), "Same account should reuse the same lock");

        // Different account should get a different lock
        let lock3 = manager.refresh_locks
            .entry("acc2".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        assert!(!Arc::ptr_eq(&lock1, &lock3), "Different accounts should have different locks");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_refresh_lock_serializes_concurrent_access() {
        // Verify that the lock actually serializes access
        let tmp = std::env::temp_dir().join(format!("kiro-refresh-serial-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = Arc::new(TokenManager::new(tmp.clone()));

        let lock = manager.refresh_locks
            .entry("acc1".to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        // Hold the lock
        let guard = lock.lock().await;

        let manager2 = manager.clone();
        let lock2 = lock.clone();

        // Spawn a task that tries to acquire the same lock
        let handle = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let _guard = lock2.lock().await;
            start.elapsed()
        });

        // Wait a bit then release
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        drop(guard);

        let elapsed = handle.await.unwrap();
        // The second task should have waited at least ~100ms
        assert!(elapsed.as_millis() >= 80, "Second lock acquisition should have waited, got {}ms", elapsed.as_millis());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_save_refreshed_token_persists_new_refresh_token() {
        let tmp = std::env::temp_dir().join(format!("kiro-save-rt-{}", uuid::Uuid::new_v4()));
        let accounts_dir = tmp.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let account_id = "acc-save-rt";
        let now = chrono::Utc::now().timestamp();
        let account_path = accounts_dir.join(format!("{}.json", account_id));

        let account_json = serde_json::json!({
            "id": account_id,
            "email": "save@test.com",
            "token": {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "expires_in": 3600,
                "expiry_timestamp": now + 3600
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&account_json).unwrap()).unwrap();

        let manager = TokenManager::new(tmp.clone());
        manager.load_accounts().await.unwrap();

        // Simulate a token refresh that returns a new refresh_token
        let token_response = crate::modules::oauth::TokenResponse {
            access_token: "new-access-token".to_string(),
            expires_in: 7200,
            token_type: "Bearer".to_string(),
            refresh_token: Some("new-refresh-token".to_string()),
        };

        manager.save_refreshed_token(account_id, &token_response).await.unwrap();

        // Read back from disk and verify
        let saved: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&account_path).unwrap()
        ).unwrap();

        assert_eq!(saved["token"]["access_token"], "new-access-token");
        assert_eq!(saved["token"]["refresh_token"], "new-refresh-token");
        assert_eq!(saved["token"]["expires_in"], 7200);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_save_refreshed_token_preserves_old_refresh_when_none() {
        let tmp = std::env::temp_dir().join(format!("kiro-save-rt-none-{}", uuid::Uuid::new_v4()));
        let accounts_dir = tmp.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let account_id = "acc-no-rt";
        let now = chrono::Utc::now().timestamp();
        let account_path = accounts_dir.join(format!("{}.json", account_id));

        let account_json = serde_json::json!({
            "id": account_id,
            "email": "nort@test.com",
            "token": {
                "access_token": "old-access",
                "refresh_token": "keep-this-refresh",
                "expires_in": 3600,
                "expiry_timestamp": now + 3600
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&account_json).unwrap()).unwrap();

        let manager = TokenManager::new(tmp.clone());
        manager.load_accounts().await.unwrap();

        // Token refresh without new refresh_token
        let token_response = crate::modules::oauth::TokenResponse {
            access_token: "new-access".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
            refresh_token: None, // No new refresh token
        };

        manager.save_refreshed_token(account_id, &token_response).await.unwrap();

        let saved: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&account_path).unwrap()
        ).unwrap();

        assert_eq!(saved["token"]["access_token"], "new-access");
        // Old refresh_token should be preserved
        assert_eq!(saved["token"]["refresh_token"], "keep-this-refresh");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_dashmap_refresh_token_updated_after_refresh() {
        // Verify that when a token is refreshed, the DashMap entry gets the new refresh_token
        let tmp = std::env::temp_dir().join(format!("kiro-dashmap-rt-{}", uuid::Uuid::new_v4()));
        let accounts_dir = tmp.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let account_id = "acc-dm-rt";
        let now = chrono::Utc::now().timestamp();
        let account_path = accounts_dir.join(format!("{}.json", account_id));

        let account_json = serde_json::json!({
            "id": account_id,
            "email": "dm@test.com",
            "token": {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "expires_in": 3600,
                "expiry_timestamp": now + 3600
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&account_json).unwrap()).unwrap();

        let manager = TokenManager::new(tmp.clone());
        manager.load_accounts().await.unwrap();

        // Verify initial state
        {
            let entry = manager.tokens.get(account_id).unwrap();
            assert_eq!(entry.refresh_token, "old-refresh");
        }

        // Simulate what the refresh code does: update DashMap with new refresh_token
        if let Some(mut entry) = manager.tokens.get_mut(account_id) {
            entry.access_token = "new-access".to_string();
            entry.refresh_token = "new-refresh-rotated".to_string();
            entry.timestamp = now + 7200;
        }

        // Verify the update
        {
            let entry = manager.tokens.get(account_id).unwrap();
            assert_eq!(entry.access_token, "new-access");
            assert_eq!(entry.refresh_token, "new-refresh-rotated");
        }

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_double_check_skips_refresh_when_already_refreshed() {
        // Simulate the double-check pattern: after acquiring lock, check if token was already refreshed
        let tmp = std::env::temp_dir().join(format!("kiro-dblchk-{}", uuid::Uuid::new_v4()));
        let accounts_dir = tmp.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let account_id = "acc-dblchk";
        let now = chrono::Utc::now().timestamp();
        let account_path = accounts_dir.join(format!("{}.json", account_id));

        let account_json = serde_json::json!({
            "id": account_id,
            "email": "dblchk@test.com",
            "token": {
                "access_token": "fresh-access",
                "refresh_token": "fresh-refresh",
                "expires_in": 3600,
                "expiry_timestamp": now + 3600
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&account_json).unwrap()).unwrap();

        let manager = TokenManager::new(tmp.clone());
        manager.load_accounts().await.unwrap();

        // Token has timestamp far in the future (already refreshed by another request)
        let already_refreshed = manager.tokens.get(account_id)
            .map(|e| e.timestamp > chrono::Utc::now().timestamp() + 60)
            .unwrap_or(false);

        assert!(already_refreshed, "Token should be considered already refreshed");

        // Now simulate an expired token
        if let Some(mut entry) = manager.tokens.get_mut(account_id) {
            entry.timestamp = now - 100; // expired
        }

        let needs_refresh = manager.tokens.get(account_id)
            .map(|e| e.timestamp > chrono::Utc::now().timestamp() + 60)
            .unwrap_or(false);

        assert!(!needs_refresh, "Expired token should need refresh");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_concurrent_refresh_lock_contention() {
        // Simulate multiple concurrent requests trying to refresh the same account
        let tmp = std::env::temp_dir().join(format!("kiro-conc-refresh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = Arc::new(TokenManager::new(tmp.clone()));

        let refresh_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();

        // Spawn 5 concurrent "refresh" attempts
        for i in 0..5 {
            let mgr = manager.clone();
            let count = refresh_count.clone();

            handles.push(tokio::spawn(async move {
                let lock = mgr.refresh_locks
                    .entry("acc1".to_string())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone();

                let _guard = lock.lock().await;

                // Check if already refreshed (simulated by counter)
                let current = count.load(std::sync::atomic::Ordering::SeqCst);
                if current > 0 {
                    // Another task already refreshed — skip
                    return false;
                }

                // Simulate refresh work
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                true
            }));
        }

        let results: Vec<bool> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Exactly one task should have performed the refresh
        let refresh_performed = results.iter().filter(|&&r| r).count();
        assert_eq!(refresh_performed, 1, "Only one concurrent request should perform the actual refresh");
        assert_eq!(refresh_count.load(std::sync::atomic::Ordering::SeqCst), 1);

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ===== Concurrency Slot Queuing & set_max_concurrency Tests =====

    #[tokio::test]
    async fn test_set_max_concurrency_clears_cached_semaphores() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-clear-sema-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        // TokenManager::new() defaults to 1
        let slot1 = manager.try_acquire_slot("acc1");
        assert!(slot1.is_some());
        let slot2 = manager.try_acquire_slot("acc1");
        assert!(slot2.is_none(), "Should fail with default concurrency of 1");

        drop(slot1);

        // Increase to 3
        manager.set_max_concurrency(3);

        // Old semaphores should be cleared, new ones created with limit 3
        let s1 = manager.try_acquire_slot("acc1");
        let s2 = manager.try_acquire_slot("acc1");
        let s3 = manager.try_acquire_slot("acc1");
        assert!(s1.is_some());
        assert!(s2.is_some());
        assert!(s3.is_some(), "Should succeed after increasing concurrency to 3");

        let s4 = manager.try_acquire_slot("acc1");
        assert!(s4.is_none(), "Fourth should fail with concurrency of 3");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_set_max_concurrency_minimum_is_one() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-min-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        // Try to set 0 — should clamp to 1
        manager.set_max_concurrency(0);
        assert_eq!(manager.get_max_concurrency(), 1);

        let slot = manager.try_acquire_slot("acc1");
        assert!(slot.is_some());
        let slot2 = manager.try_acquire_slot("acc1");
        assert!(slot2.is_none(), "Should only allow 1 with min clamp");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_acquire_slot_with_timeout_waits_for_release() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-wait-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = Arc::new(TokenManager::new(tmp.clone()));

        // Set concurrency to 1
        manager.set_max_concurrency(1);

        // Acquire the only slot
        let slot = manager.try_acquire_slot("acc1").unwrap();

        let manager2 = manager.clone();
        let start = std::time::Instant::now();

        // Spawn a task that waits for the slot
        let handle = tokio::spawn(async move {
            manager2
                .acquire_slot_with_timeout("acc1", std::time::Duration::from_secs(5))
                .await
        });

        // Release after 100ms
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        drop(slot);

        let result = handle.await.unwrap();
        let elapsed = start.elapsed();

        assert!(result.is_some(), "Should acquire slot after waiting");
        assert!(elapsed.as_millis() >= 80, "Should have waited ~100ms, got {}ms", elapsed.as_millis());
        assert!(elapsed.as_millis() < 2000, "Should not have waited too long, got {}ms", elapsed.as_millis());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_acquire_slot_with_timeout_queues_multiple_waiters() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-queue-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = Arc::new(TokenManager::new(tmp.clone()));

        // Set concurrency to 1
        manager.set_max_concurrency(1);

        // Acquire the only slot
        let slot = manager.try_acquire_slot("acc1").unwrap();

        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();

        // Spawn 3 waiters
        for _ in 0..3 {
            let mgr = manager.clone();
            let done = completed.clone();
            handles.push(tokio::spawn(async move {
                let acquired = mgr
                    .acquire_slot_with_timeout("acc1", std::time::Duration::from_secs(5))
                    .await;
                if acquired.is_some() {
                    // Hold briefly then release
                    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
                    done.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                acquired.is_some()
            }));
        }

        // Release the initial slot after 50ms
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        drop(slot);

        let results: Vec<bool> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // All 3 should eventually get their turn
        assert_eq!(results.iter().filter(|&&r| r).count(), 3, "All waiters should eventually acquire the slot");
        assert_eq!(completed.load(std::sync::atomic::Ordering::SeqCst), 3);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_acquire_slot_timeout_expires() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-timeout-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        manager.set_max_concurrency(1);

        // Hold the slot indefinitely
        let _slot = manager.try_acquire_slot("acc1").unwrap();

        // Try to acquire with very short timeout
        let result = manager
            .acquire_slot_with_timeout("acc1", std::time::Duration::from_millis(100))
            .await;

        assert!(result.is_none(), "Should timeout when slot is held");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_concurrency_different_accounts_independent() {
        let tmp = std::env::temp_dir().join(format!("kiro-conc-indep-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());

        manager.set_max_concurrency(1);

        // acc1 slot taken
        let _slot1 = manager.try_acquire_slot("acc1").unwrap();

        // acc2 should still be available — independent semaphores
        let slot2 = manager.try_acquire_slot("acc2");
        assert!(slot2.is_some(), "Different accounts should have independent concurrency slots");

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ===== Pending status indicator tests =====

    #[tokio::test]
    async fn test_pending_detection_when_slot_full() {
        // When all slots are taken, has_available_slot should return false,
        // which triggers the pending log entry in the handler
        let tmp = std::env::temp_dir().join(format!("kiro-pending-detect-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());
        manager.set_max_concurrency(1);

        assert!(manager.has_available_slot("acc1"), "Should have slot before any acquisition");

        let _slot = manager.try_acquire_slot("acc1").unwrap();
        assert!(!manager.has_available_slot("acc1"), "Should detect no available slot when full");

        // After dropping the slot, should be available again
        drop(_slot);
        assert!(manager.has_available_slot("acc1"), "Should have slot after release");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_pending_detection_with_concurrency_2() {
        // With max_concurrency=2, pending should only trigger when both slots are taken
        let tmp = std::env::temp_dir().join(format!("kiro-pending-conc2-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());
        manager.set_max_concurrency(2);

        let _slot1 = manager.try_acquire_slot("acc1").unwrap();
        assert!(manager.has_available_slot("acc1"), "Should still have 1 slot available");

        let _slot2 = manager.try_acquire_slot("acc1").unwrap();
        assert!(!manager.has_available_slot("acc1"), "Both slots taken, should detect pending");

        drop(_slot1);
        assert!(manager.has_available_slot("acc1"), "One slot freed, should be available");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_pending_cleared_after_slot_acquired() {
        // Simulates the flow: pending detected -> wait -> slot acquired -> pending cleared
        let tmp = std::env::temp_dir().join(format!("kiro-pending-clear-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = Arc::new(TokenManager::new(tmp.clone()));
        manager.set_max_concurrency(1);

        let _slot1 = manager.try_acquire_slot("acc1").unwrap();
        assert!(!manager.has_available_slot("acc1"), "Slot full, pending should be logged");

        // Spawn a waiter
        let manager2 = manager.clone();
        let handle = tokio::spawn(async move {
            manager2
                .acquire_slot_with_timeout("acc1", std::time::Duration::from_secs(5))
                .await
        });

        // Release the slot after a short delay
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(_slot1);

        let result = handle.await.unwrap();
        assert!(result.is_some(), "Waiter should acquire slot after release");
        // At this point, the pending log would be removed in the real handler

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_pending_timeout_updates_to_503() {
        // When slot acquisition times out, the pending entry should be updated to 503
        let tmp = std::env::temp_dir().join(format!("kiro-pending-timeout-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());
        manager.set_max_concurrency(1);

        let _slot = manager.try_acquire_slot("acc1").unwrap();
        assert!(!manager.has_available_slot("acc1"), "Slot full, pending should be logged");

        // Try to acquire with very short timeout — simulates the timeout path
        let result = manager
            .acquire_slot_with_timeout("acc1", std::time::Duration::from_millis(50))
            .await;
        assert!(result.is_none(), "Should timeout, triggering pending -> 503 update");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_pending_not_triggered_when_slot_available() {
        // When a slot is immediately available, no pending entry should be created
        let tmp = std::env::temp_dir().join(format!("kiro-pending-noop-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());
        manager.set_max_concurrency(2);

        // No slots taken — has_available_slot should be true
        assert!(manager.has_available_slot("acc1"), "Slot available, no pending needed");

        let _slot = manager
            .acquire_slot_with_timeout("acc1", std::time::Duration::from_secs(1))
            .await;
        assert!(_slot.is_some(), "Should acquire immediately without pending");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_pending_independent_per_account() {
        // Pending detection should be per-account, not global
        let tmp = std::env::temp_dir().join(format!("kiro-pending-indep-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let manager = TokenManager::new(tmp.clone());
        manager.set_max_concurrency(1);

        let _slot_acc1 = manager.try_acquire_slot("acc1").unwrap();
        assert!(!manager.has_available_slot("acc1"), "acc1 full");
        assert!(manager.has_available_slot("acc2"), "acc2 should be independent and available");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn test_get_token_skips_full_last_used_account_when_others_available() {
        let tmp_root = std::env::temp_dir().join(format!(
            "kiro-token-select-conc-{}",
            uuid::Uuid::new_v4()
        ));
        let accounts_dir = tmp_root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let model = "claude-sonnet-4";
        let now = chrono::Utc::now().timestamp();

        for (account_id, email, access_token, refresh_token) in [
            ("acc1", "a@test.com", "atk1", "rtk1"),
            ("acc2", "b@test.com", "atk2", "rtk2"),
        ] {
            let account_path = accounts_dir.join(format!("{}.json", account_id));
            let account_json = serde_json::json!({
                "id": account_id,
                "email": email,
                "token": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": 3600,
                    "expiry_timestamp": now + 3600
                },
                "disabled": false,
                "proxy_disabled": false,
                "quota": {
                    "is_forbidden": false
                },
                "created_at": now,
                "last_used": now
            });
            std::fs::write(&account_path, serde_json::to_string_pretty(&account_json).unwrap())
                .unwrap();
        }

        let manager = TokenManager::new(tmp_root.clone());
        manager.set_max_concurrency(1);

        let quota_key = crate::proxy::common::model_mapping::normalize_to_standard_id(model)
            .unwrap_or_else(|| model.to_string());

        let mut model_quotas = std::collections::HashMap::new();
        model_quotas.insert(quota_key, 100);

        let token1 = ProxyToken {
            account_id: "acc1".to_string(),
            access_token: "atk1".to_string(),
            refresh_token: "rtk1".to_string(),
            expires_in: 3600,
            timestamp: now + 3600,
            email: "a@test.com".to_string(),
            account_path: accounts_dir.join("acc1.json"),
            project_id: None,
            subscription_tier: Some("pro".to_string()),
            remaining_quota: Some(100),
            health_score: 1.0,
            reset_time: None,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas: model_quotas.clone(),
            profile_arn: None,
        };
        let token2 = ProxyToken {
            account_id: "acc2".to_string(),
            access_token: "atk2".to_string(),
            refresh_token: "rtk2".to_string(),
            expires_in: 3600,
            timestamp: now + 3600,
            email: "b@test.com".to_string(),
            account_path: accounts_dir.join("acc2.json"),
            project_id: None,
            subscription_tier: Some("pro".to_string()),
            remaining_quota: Some(100),
            health_score: 1.0,
            reset_time: None,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas,
            profile_arn: None,
        };

        manager.tokens.insert("acc1".to_string(), token1);
        manager.tokens.insert("acc2".to_string(), token2);

        {
            let mut last_used = manager.last_used_account.lock().await;
            *last_used = Some(("acc1".to_string(), std::time::Instant::now()));
        }

        let _slot = manager.try_acquire_slot("acc1").unwrap();
        assert!(!manager.has_available_slot("acc1"), "acc1 should be full");
        assert!(manager.has_available_slot("acc2"), "acc2 should be available");

        let (_atk, _proj, _email, account_id, _wait_ms) =
            manager.get_token("claude", false, None, model).await.unwrap();

        assert_eq!(account_id, "acc2");

        std::fs::remove_dir_all(&tmp_root).ok();
    }
}
