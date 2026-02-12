use serde::{Deserialize, Serialize};
// use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

// ============================================================================
// 辅助工具函数
// ============================================================================

/// 标准化代理 URL，如果缺失协议则默认补全 http://
pub fn normalize_proxy_url(url: &str) -> String {
    let url = url.trim();
    if url.is_empty() {
        return String::new();
    }
    if !url.contains("://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    }
}

// ============================================================================
// 全局系统提示词配置存储
// 用户可在设置中配置一段全局提示词，自动注入到所有请求的 systemInstruction 中
// ============================================================================
static GLOBAL_SYSTEM_PROMPT_CONFIG: OnceLock<RwLock<GlobalSystemPromptConfig>> = OnceLock::new();

#[allow(dead_code)]
pub fn get_global_system_prompt() -> GlobalSystemPromptConfig {
    GLOBAL_SYSTEM_PROMPT_CONFIG
        .get()
        .and_then(|lock| lock.read().ok())
        .map(|cfg| cfg.clone())
        .unwrap_or_default()
}

/// 更新全局系统提示词配置
pub fn update_global_system_prompt_config(config: GlobalSystemPromptConfig) {
    if let Some(lock) = GLOBAL_SYSTEM_PROMPT_CONFIG.get() {
        if let Ok(mut cfg) = lock.write() {
            *cfg = config.clone();
            tracing::info!(
                "[Global-System-Prompt] Config updated: enabled={}, content_len={}",
                config.enabled,
                config.content.len()
            );
        }
    } else {
        // 首次初始化
        let _ = GLOBAL_SYSTEM_PROMPT_CONFIG.set(RwLock::new(config.clone()));
        tracing::info!(
            "[Global-System-Prompt] Config initialized: enabled={}, content_len={}",
            config.enabled,
            config.content.len()
        );
    }
}

/// 全局系统提示词配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSystemPromptConfig {
    /// 是否启用全局系统提示词
    #[serde(default)]
    pub enabled: bool,
    /// 系统提示词内容
    #[serde(default)]
    pub content: String,
}

impl Default for GlobalSystemPromptConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            content: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAuthMode {
    Off,
    Strict,
    AllExceptHealth,
    Auto,
}

impl Default for ProxyAuthMode {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LegacyDispatchMode {
    /// Never use legacy provider.
    Off,
    /// Use legacy provider for all Anthropic protocol requests.
    Exclusive,
    /// Treat legacy provider as one additional slot in the shared pool.
    Pooled,
    /// Use legacy provider only when the primary pool is unavailable.
    Fallback,
}

/// Backward-compatible alias for deserialization.
#[allow(dead_code)]
impl Default for LegacyDispatchMode {
    fn default() -> Self {
        Self::Off
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyModelDefaults {
    #[serde(default = "default_legacy_opus_model")]
    pub opus: String,
    #[serde(default = "default_legacy_sonnet_model")]
    pub sonnet: String,
    #[serde(default = "default_legacy_haiku_model")]
    pub haiku: String,
}

impl Default for LegacyModelDefaults {
    fn default() -> Self {
        Self {
            opus: default_legacy_opus_model(),
            sonnet: default_legacy_sonnet_model(),
            haiku: default_legacy_haiku_model(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyMcpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub web_search_enabled: bool,
    #[serde(default)]
    pub web_reader_enabled: bool,
    #[serde(default)]
    pub vision_enabled: bool,
}

impl Default for LegacyMcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            web_search_enabled: false,
            web_reader_enabled: false,
            vision_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_legacy_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub dispatch_mode: LegacyDispatchMode,
    #[serde(default)]
    pub model_mapping: HashMap<String, String>,
    #[serde(default)]
    pub models: LegacyModelDefaults,
    #[serde(default)]
    pub mcp: LegacyMcpConfig,
}

impl Default for LegacyProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: default_legacy_base_url(),
            api_key: String::new(),
            dispatch_mode: LegacyDispatchMode::Off,
            model_mapping: HashMap::new(),
            models: LegacyModelDefaults::default(),
            mcp: LegacyMcpConfig::default(),
        }
    }
}

/// 实验性功能配置 (Feature Flags)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentalConfig {
    /// 启用双层签名缓存 (Signature Cache)
    #[serde(default = "default_true")]
    pub enable_signature_cache: bool,

    /// 启用工具循环自动恢复 (Tool Loop Recovery)
    #[serde(default = "default_true")]
    pub enable_tool_loop_recovery: bool,

    /// 启用跨模型兼容性检查 (Cross-Model Checks)
    #[serde(default = "default_true")]
    pub enable_cross_model_checks: bool,

    /// 启用上下文用量缩放 (Context Usage Scaling)
    /// 激进模式: 缩放用量并激活自动压缩以突破 200k 限制
    /// 默认关闭以保持透明度,让客户端能触发原生压缩指令
    #[serde(default = "default_false")]
    pub enable_usage_scaling: bool,

    /// 上下文压缩阈值 L1 (Tool Trimming)
    #[serde(default = "default_threshold_l1")]
    pub context_compression_threshold_l1: f32,

    /// 上下文压缩阈值 L2 (Thinking Compression)
    #[serde(default = "default_threshold_l2")]
    pub context_compression_threshold_l2: f32,

    /// 上下文压缩阈值 L3 (Fork + Summary)
    #[serde(default = "default_threshold_l3")]
    pub context_compression_threshold_l3: f32,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            enable_signature_cache: true,
            enable_tool_loop_recovery: true,
            enable_cross_model_checks: true,
            enable_usage_scaling: false, // 默认关闭,回归透明模式
            context_compression_threshold_l1: 0.4,
            context_compression_threshold_l2: 0.55,
            context_compression_threshold_l3: 0.7,
        }
    }
}

fn default_threshold_l1() -> f32 {
    0.4
}
fn default_threshold_l2() -> f32 {
    0.55
}
fn default_threshold_l3() -> f32 {
    0.7
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugLoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub output_dir: Option<String>,
}

impl Default for DebugLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output_dir: None,
        }
    }
}

/// IP 黑名单配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlacklistConfig {
    /// 是否启用黑名单
    #[serde(default)]
    pub enabled: bool,

    /// 自定义封禁消息
    #[serde(default = "default_block_message")]
    pub block_message: String,
}

impl Default for IpBlacklistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_message: default_block_message(),
        }
    }
}

fn default_block_message() -> String {
    "Access denied".to_string()
}

/// IP 白名单配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWhitelistConfig {
    /// 是否启用白名单模式 (启用后只允许白名单IP访问)
    #[serde(default)]
    pub enabled: bool,

    /// 白名单优先模式 (白名单IP跳过黑名单检查)
    #[serde(default = "default_true")]
    pub whitelist_priority: bool,
}

impl Default for IpWhitelistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            whitelist_priority: true,
        }
    }
}

/// 安全监控配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMonitorConfig {
    /// IP 黑名单配置
    #[serde(default)]
    pub blacklist: IpBlacklistConfig,

    /// IP 白名单配置
    #[serde(default)]
    pub whitelist: IpWhitelistConfig,
}

impl Default for SecurityMonitorConfig {
    fn default() -> Self {
        Self {
            blacklist: IpBlacklistConfig::default(),
            whitelist: IpWhitelistConfig::default(),
        }
    }
}

// ============================================================================
// Gateway 迁移：新增配置结构体
// ============================================================================

/// Fake Reasoning 配置
/// 控制是否注入或剥离 fake reasoning 标签
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeReasoningConfig {
    /// 是否启用 fake reasoning
    #[serde(default)]
    pub enabled: bool,
    /// 处理方式: "inject" | "strip"
    #[serde(default = "default_fake_reasoning_handling")]
    pub handling: String,
    /// 最大 token 数
    #[serde(default = "default_fake_reasoning_max_tokens")]
    pub max_tokens: u32,
    /// 开放标签列表
    #[serde(default = "default_fake_reasoning_open_tags")]
    pub open_tags: Vec<String>,
}

fn default_fake_reasoning_handling() -> String {
    "inject".to_string()
}

fn default_fake_reasoning_max_tokens() -> u32 {
    8000
}

fn default_fake_reasoning_open_tags() -> Vec<String> {
    vec![
        "<thinking>".to_string(),
        "<think>".to_string(),
        "<reasoning>".to_string(),
    ]
}

impl Default for FakeReasoningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            handling: default_fake_reasoning_handling(),
            max_tokens: default_fake_reasoning_max_tokens(),
            open_tags: default_fake_reasoning_open_tags(),
        }
    }
}

/// 截断恢复配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruncationConfig {
    /// 是否启用截断恢复
    #[serde(default = "default_true")]
    pub recovery_enabled: bool,
}

impl Default for TruncationConfig {
    fn default() -> Self {
        Self {
            recovery_enabled: true,
        }
    }
}

/// 流式处理配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// 首 token 超时时间（秒）
    #[serde(default = "default_first_token_timeout_secs")]
    pub first_token_timeout_secs: u64,
    /// 首 token 超时最大重试次数
    #[serde(default = "default_first_token_max_retries")]
    pub first_token_max_retries: u32,
    /// 读取超时时间（秒）
    #[serde(default = "default_read_timeout_secs")]
    pub read_timeout_secs: u64,
}

fn default_first_token_timeout_secs() -> u64 {
    30
}

fn default_first_token_max_retries() -> u32 {
    2
}

fn default_read_timeout_secs() -> u64 {
    120
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            first_token_timeout_secs: default_first_token_timeout_secs(),
            first_token_max_retries: default_first_token_max_retries(),
            read_timeout_secs: default_read_timeout_secs(),
        }
    }
}

/// 模型相关配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// 工具描述最大长度
    #[serde(default = "default_tool_description_max_length")]
    pub tool_description_max_length: usize,
    /// 模型别名映射 (别名 → 实际模型名)
    #[serde(default = "default_model_aliases")]
    pub model_aliases: HashMap<String, String>,
    /// 隐藏模型映射 (显示名 → 内部 Kiro ID)
    #[serde(default = "default_hidden_models")]
    pub hidden_models: HashMap<String, String>,
    /// 回退模型列表
    #[serde(default)]
    pub fallback_models: Vec<String>,
    /// 从 /v1/models 列表中隐藏的模型 (仍可直接请求)
    #[serde(default = "default_hidden_from_list")]
    pub hidden_from_list: Vec<String>,
}

fn default_tool_description_max_length() -> usize {
    4096
}

fn default_hidden_models() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "claude-3.7-sonnet".to_string(),
        "CLAUDE_3_7_SONNET_20250219_V1_0".to_string(),
    );
    m
}

fn default_model_aliases() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("auto-kiro".to_string(), "auto".to_string());
    m
}

fn default_hidden_from_list() -> Vec<String> {
    vec!["auto".to_string()]
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            tool_description_max_length: default_tool_description_max_length(),
            model_aliases: default_model_aliases(),
            hidden_models: default_hidden_models(),
            fallback_models: Vec::new(),
            hidden_from_list: default_hidden_from_list(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamProxyConfig {
    #[serde(default)]
    pub kiro_enabled: bool,
    #[serde(default)]
    pub use_preset_proxy: bool,
    #[serde(default)]
    pub custom_proxy_url: String,
    #[serde(default)]
    pub kiro_api_region: String,
}

/// 反代服务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// 是否启用反代服务
    pub enabled: bool,

    /// 是否允许局域网访问
    /// - false: 仅本机访问 127.0.0.1（默认，隐私优先）
    /// - true: 允许局域网访问 0.0.0.0
    #[serde(default)]
    pub allow_lan_access: bool,

    /// Authorization policy for the proxy.
    /// - off: no auth required
    /// - strict: auth required for all routes
    /// - all_except_health: auth required for all routes except `/healthz`
    /// - auto: recommended defaults (currently: allow_lan_access => all_except_health, else off)
    #[serde(default)]
    pub auth_mode: ProxyAuthMode,

    /// 监听端口
    pub port: u16,

    /// API 密钥
    pub api_key: String,

    /// Web UI 管理后台密码 (可选，如未设置则使用 api_key)
    pub admin_password: Option<String>,

    /// 是否自动启动
    pub auto_start: bool,

    /// 自定义精确模型映射表 (key: 原始模型名, value: 目标模型名)
    #[serde(default)]
    pub custom_mapping: std::collections::HashMap<String, String>,

    /// API 请求超时时间(秒)
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,

    /// 是否开启请求日志记录 (监控)
    #[serde(default)]
    pub enable_logging: bool,

    /// 调试日志配置 (保存完整链路)
    #[serde(default)]
    pub debug_logging: DebugLoggingConfig,

    /// 上游代理配置
    #[serde(default)]
    pub upstream_proxy: UpstreamProxyConfig,

    /// Legacy provider configuration (Anthropic-compatible, retained for serde compat).
    #[serde(default, alias = "zai")]
    pub legacy_provider: LegacyProviderConfig,

    /// 自定义 User-Agent 请求头 (可选覆盖)
    #[serde(default)]
    pub user_agent_override: Option<String>,

    /// 账号调度配置 (粘性会话/限流重试)
    #[serde(default)]
    pub scheduling: crate::proxy::sticky_config::StickySessionConfig,

    /// 实验性功能配置
    #[serde(default)]
    pub experimental: ExperimentalConfig,

    /// 安全监控配置 (IP 黑白名单)
    #[serde(default)]
    pub security_monitor: SecurityMonitorConfig,

    /// 固定账号模式的账号ID (Fixed Account Mode)
    /// - None: 使用轮询模式
    /// - Some(account_id): 固定使用指定账号
    #[serde(default)]
    pub preferred_account_id: Option<String>,

    /// Saved User-Agent string (persisted even when override is disabled)
    #[serde(default)]
    pub saved_user_agent: Option<String>,

    /// 全局系统提示词配置
    /// 自动注入到所有 API 请求的 systemInstruction 中
    #[serde(default)]
    pub global_system_prompt: GlobalSystemPromptConfig,

    /// 代理池配置
    #[serde(default)]
    pub proxy_pool: ProxyPoolConfig,

    /// 每个账号的最大并发数
    #[serde(default = "default_max_concurrency_per_account")]
    pub max_concurrency_per_account: usize,

    /// Fake Reasoning 配置
    #[serde(default)]
    pub fake_reasoning: FakeReasoningConfig,

    /// 截断恢复配置
    #[serde(default)]
    pub truncation: TruncationConfig,

    /// 流式处理配置
    #[serde(default)]
    pub streaming: StreamingConfig,

    /// 模型相关配置
    #[serde(default)]
    pub model_config: ModelConfig,
}

fn default_max_concurrency_per_account() -> usize {
    2 // 默认并发为2，支持同时处理主对话和辅助请求(如标题生成)
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_lan_access: false, // 默认仅本机访问，隐私优先
            auth_mode: ProxyAuthMode::default(),
            port: 8045,
            api_key: format!("sk-{}", uuid::Uuid::new_v4().simple()),
            admin_password: None,
            auto_start: false,
            custom_mapping: std::collections::HashMap::new(),
            request_timeout: default_request_timeout(),
            enable_logging: true, // 默认开启，支持 token 统计功能
            debug_logging: DebugLoggingConfig::default(),
            upstream_proxy: UpstreamProxyConfig::default(),
            legacy_provider: LegacyProviderConfig::default(),
            scheduling: crate::proxy::sticky_config::StickySessionConfig::default(),
            experimental: ExperimentalConfig::default(),
            security_monitor: SecurityMonitorConfig::default(),
            preferred_account_id: None, // 默认使用轮询模式
            user_agent_override: None,
            saved_user_agent: None,
            global_system_prompt: GlobalSystemPromptConfig::default(),
            proxy_pool: ProxyPoolConfig::default(),
            max_concurrency_per_account: default_max_concurrency_per_account(),
            fake_reasoning: FakeReasoningConfig::default(),
            truncation: TruncationConfig::default(),
            streaming: StreamingConfig::default(),
            model_config: ModelConfig::default(),
        }
    }
}

fn default_request_timeout() -> u64 {
    120 // 默认 120 秒,原来 60 秒太短
}

fn default_legacy_base_url() -> String {
    "https://api.legacy-provider.local/api/anthropic".to_string()
}

fn default_legacy_opus_model() -> String {
    "glm-4.7".to_string()
}

fn default_legacy_sonnet_model() -> String {
    "glm-4.7".to_string()
}

fn default_legacy_haiku_model() -> String {
    "glm-4.5-air".to_string()
}

impl ProxyConfig {
    /// 获取实际的监听地址
    /// - allow_lan_access = false: 返回 "127.0.0.1"（默认，隐私优先）
    /// - allow_lan_access = true: 返回 "0.0.0.0"（允许局域网访问）
    pub fn get_bind_address(&self) -> &str {
        if self.allow_lan_access {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        }
    }
}

/// 代理认证信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// 单个代理配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: String,                       // 唯一标识
    pub name: String,                     // 显示名称
    pub url: String,                      // 代理地址 (http://, https://, socks5://)
    pub auth: Option<ProxyAuth>,          // 认证信息 (可选)
    pub enabled: bool,                    // 是否启用
    pub priority: i32,                    // 优先级 (数字越小优先级越高)
    pub tags: Vec<String>,                // 标签 (如 "美国", "住宅IP")
    pub max_accounts: Option<usize>,      // 最大绑定账号数 (0 = 无限制)
    pub health_check_url: Option<String>, // 健康检查 URL
    pub last_check_time: Option<i64>,     // 上次检查时间
    pub is_healthy: bool,                 // 健康状态
    pub latency: Option<u64>,             // 延迟 (毫秒) [NEW]
}

/// 代理池配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPoolConfig {
    pub enabled: bool, // 是否启用代理池
    // pub mode: ProxyPoolMode,        // [REMOVED] 代理池模式，统一为 Hybrid 逻辑
    pub proxies: Vec<ProxyEntry>,         // 代理列表
    pub health_check_interval: u64,       // 健康检查间隔 (秒)
    pub auto_failover: bool,              // 自动故障转移
    pub strategy: ProxySelectionStrategy, // 代理选择策略
    /// 账号到代理的绑定关系 (account_id -> proxy_id)，持久化存储
    #[serde(default)]
    pub account_bindings: HashMap<String, String>,
}

impl Default for ProxyPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            // mode: ProxyPoolMode::Global,
            proxies: Vec::new(),
            health_check_interval: 300,
            auto_failover: true,
            strategy: ProxySelectionStrategy::Priority,
            account_bindings: HashMap::new(),
        }
    }
}

/// 代理选择策略
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxySelectionStrategy {
    /// 轮询: 依次使用
    RoundRobin,
    /// 随机: 随机选择
    Random,
    /// 优先级: 按 priority 字段排序
    Priority,
    /// 最少连接: 选择当前使用最少的代理
    LeastConnections,
    /// 加权轮询: 根据健康状态和优先级
    WeightedRoundRobin,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_proxy_url() {
        // 测试已有协议
        assert_eq!(
            normalize_proxy_url("http://127.0.0.1:7890"),
            "http://127.0.0.1:7890"
        );
        assert_eq!(
            normalize_proxy_url("https://proxy.com"),
            "https://proxy.com"
        );
        assert_eq!(
            normalize_proxy_url("socks5://127.0.0.1:1080"),
            "socks5://127.0.0.1:1080"
        );
        assert_eq!(
            normalize_proxy_url("socks5h://127.0.0.1:1080"),
            "socks5h://127.0.0.1:1080"
        );

        // 测试缺少协议（默认补全 http://）
        assert_eq!(
            normalize_proxy_url("127.0.0.1:7890"),
            "http://127.0.0.1:7890"
        );
        assert_eq!(
            normalize_proxy_url("localhost:1082"),
            "http://localhost:1082"
        );

        // 测试边缘情况
        assert_eq!(normalize_proxy_url(""), "");
        assert_eq!(normalize_proxy_url("   "), "");
    }

    use proptest::prelude::*;

    proptest! {
        /// Property 14: FakeReasoningConfig serde roundtrip.
        #[test]
        fn prop_fake_reasoning_config_roundtrip(
            enabled in any::<bool>(),
            max_tokens in 1..100_000u32,
        ) {
            let cfg = FakeReasoningConfig {
                enabled,
                handling: "inject".into(),
                max_tokens,
                open_tags: vec!["<thinking>".into()],
            };
            let toml_str = toml::to_string(&cfg).unwrap();
            let back: FakeReasoningConfig = toml::from_str(&toml_str).unwrap();
            prop_assert_eq!(back.enabled, cfg.enabled);
            prop_assert_eq!(back.max_tokens, cfg.max_tokens);
            prop_assert_eq!(back.handling, cfg.handling);
        }

        #[test]
        fn prop_truncation_config_roundtrip(recovery_enabled in any::<bool>()) {
            let cfg = TruncationConfig { recovery_enabled };
            let toml_str = toml::to_string(&cfg).unwrap();
            let back: TruncationConfig = toml::from_str(&toml_str).unwrap();
            prop_assert_eq!(back.recovery_enabled, cfg.recovery_enabled);
        }

        #[test]
        fn prop_streaming_config_roundtrip(
            first_token in 1..300u64,
            retries in 0..10u32,
            read_timeout in 1..600u64,
        ) {
            let cfg = StreamingConfig {
                first_token_timeout_secs: first_token,
                first_token_max_retries: retries,
                read_timeout_secs: read_timeout,
            };
            let toml_str = toml::to_string(&cfg).unwrap();
            let back: StreamingConfig = toml::from_str(&toml_str).unwrap();
            prop_assert_eq!(back.first_token_timeout_secs, cfg.first_token_timeout_secs);
            prop_assert_eq!(back.first_token_max_retries, cfg.first_token_max_retries);
            prop_assert_eq!(back.read_timeout_secs, cfg.read_timeout_secs);
        }

        #[test]
        fn prop_model_config_roundtrip(max_len in 1..10_000usize) {
            let cfg = ModelConfig {
                tool_description_max_length: max_len,
                model_aliases: std::collections::HashMap::new(),
                hidden_models: std::collections::HashMap::new(),
                fallback_models: Vec::new(),
                hidden_from_list: Vec::new(),
            };
            let toml_str = toml::to_string(&cfg).unwrap();
            let back: ModelConfig = toml::from_str(&toml_str).unwrap();
            prop_assert_eq!(back.tool_description_max_length, cfg.tool_description_max_length);
        }
    }

    #[test]
    fn test_model_config_defaults() {
        let config = ModelConfig::default();
        assert!(config.hidden_models.contains_key("claude-3.7-sonnet"));
        assert_eq!(
            config.hidden_models["claude-3.7-sonnet"],
            "CLAUDE_3_7_SONNET_20250219_V1_0"
        );
        assert!(config.model_aliases.contains_key("auto-kiro"));
        assert_eq!(config.model_aliases["auto-kiro"], "auto");
        assert!(config.hidden_from_list.contains(&"auto".to_string()));
    }

    #[test]
    fn test_model_config_toml_roundtrip() {
        let config = ModelConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: ModelConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.hidden_models, config.hidden_models);
        assert_eq!(parsed.model_aliases, config.model_aliases);
        assert_eq!(parsed.hidden_from_list, config.hidden_from_list);
    }
}
