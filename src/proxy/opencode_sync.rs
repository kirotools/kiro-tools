use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::fs;
use std::collections::HashMap;
use std::env;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const OPENCODE_DIR: &str = ".config/opencode";
const OPENCODE_CONFIG_FILE: &str = "opencode.json";
const KIRO_CONFIG_FILE: &str = "kiro.json";
const KIRO_ACCOUNTS_FILE: &str = "kiro-accounts.json";
const BACKUP_SUFFIX: &str = ".kiro.bak";

const ANTHROPIC_MODELS: &[&str] = &[
    "claude-sonnet-4-5",
    "claude-sonnet-4-5-thinking",
    "claude-opus-4-5-thinking",
];

#[allow(dead_code)]
const KIRO_MODELS: &[&str] = &[
    "kiro-3-pro-high",
    "kiro-3-pro-low",
    "kiro-3-flash",
    "kiro-3-pro-image",
    "kiro-2.5-flash",
    "kiro-2.5-flash-lite",
    "kiro-2.5-flash-thinking",
    "kiro-2.5-pro",
];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpencodeStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub is_synced: bool,
    pub has_backup: bool,
    pub current_base_url: Option<String>,
    pub files: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpencodeAccount {
    email: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "projectId", skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    #[serde(rename = "rateLimitResetTimes", skip_serializing_if = "Option::is_none")]
    rate_limit_reset_times: Option<HashMap<String, i64>>,
}

fn get_opencode_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(OPENCODE_DIR))
}

fn get_config_paths() -> Option<(PathBuf, PathBuf, PathBuf)> {
    get_opencode_dir().map(|dir| {
        (
            dir.join(OPENCODE_CONFIG_FILE),
            dir.join(KIRO_CONFIG_FILE),
            dir.join(KIRO_ACCOUNTS_FILE),
        )
    })
}

fn extract_version(raw: &str) -> String {
    let trimmed = raw.trim();
    
    // Try to extract version from formats like "opencode/1.2.3" or "codex-cli 0.86.0"
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    for part in parts {
        // Check for format like "opencode/1.2.3"
        if let Some(slash_idx) = part.find('/') {
            let after_slash = &part[slash_idx + 1..];
            if is_valid_version(after_slash) {
                return after_slash.to_string();
            }
        }
        // Check if part itself looks like a version
        if is_valid_version(part) {
            return part.to_string();
        }
    }
    
    // Fallback: extract last sequence of digits and dots
    let version_chars: String = trimmed
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    
    if !version_chars.is_empty() && version_chars.contains('.') {
        return version_chars;
    }
    
    "unknown".to_string()
}

fn is_valid_version(s: &str) -> bool {
    // A valid version should start with digit and contain at least one dot
    s.chars().next().map_or(false, |c| c.is_ascii_digit())
        && s.contains('.')
        && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn resolve_opencode_path() -> Option<PathBuf> {
    // First, try to find in PATH
    if let Some(path) = find_in_path("opencode") {
        tracing::debug!("Found opencode in PATH: {:?}", path);
        return Some(path);
    }
    
    // Try fallback locations based on OS
    #[cfg(target_os = "windows")]
    {
        resolve_opencode_path_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        resolve_opencode_path_unix()
    }
}

#[cfg(target_os = "windows")]
fn resolve_opencode_path_windows() -> Option<PathBuf> {
    // Check npm global location
    if let Ok(app_data) = env::var("APPDATA") {
        let npm_opencode_cmd = PathBuf::from(&app_data).join("npm").join("opencode.cmd");
        if npm_opencode_cmd.exists() {
            tracing::debug!("Found opencode.cmd in APPDATA\\npm: {:?}", npm_opencode_cmd);
            return Some(npm_opencode_cmd);
        }
        let npm_opencode_exe = PathBuf::from(&app_data).join("npm").join("opencode.exe");
        if npm_opencode_exe.exists() {
            tracing::debug!("Found opencode.exe in APPDATA\\npm: {:?}", npm_opencode_exe);
            return Some(npm_opencode_exe);
        }
    }
    
    // Check pnpm location
    if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
        let pnpm_opencode_cmd = PathBuf::from(&local_app_data).join("pnpm").join("opencode.cmd");
        if pnpm_opencode_cmd.exists() {
            tracing::debug!("Found opencode.cmd in LOCALAPPDATA\\pnpm: {:?}", pnpm_opencode_cmd);
            return Some(pnpm_opencode_cmd);
        }
        let pnpm_opencode_exe = PathBuf::from(&local_app_data).join("pnpm").join("opencode.exe");
        if pnpm_opencode_exe.exists() {
            tracing::debug!("Found opencode.exe in LOCALAPPDATA\\pnpm: {:?}", pnpm_opencode_exe);
            return Some(pnpm_opencode_exe);
        }
    }
    
    // Check Yarn location
    if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
        let yarn_opencode = PathBuf::from(&local_app_data)
            .join("Yarn")
            .join("bin")
            .join("opencode.cmd");
        if yarn_opencode.exists() {
            tracing::debug!("Found opencode.cmd in Yarn bin: {:?}", yarn_opencode);
            return Some(yarn_opencode);
        }
    }
    
    // Scan NVM_HOME
    if let Ok(nvm_home) = env::var("NVM_HOME") {
        if let Some(path) = scan_nvm_directory(&nvm_home) {
            return Some(path);
        }
    }
    
    // Try common NVM locations
    if let Some(home) = dirs::home_dir() {
        let nvm_default = home.join(".nvm");
        if let Some(path) = scan_nvm_directory(&nvm_default) {
            return Some(path);
        }
    }
    
    None
}

#[cfg(not(target_os = "windows"))]
fn resolve_opencode_path_unix() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    
    // Common user bin locations
    let user_bins = [
        home.join(".local").join("bin").join("opencode"),
        home.join(".npm-global").join("bin").join("opencode"),
        home.join(".volta").join("bin").join("opencode"),
        home.join("bin").join("opencode"),
    ];
    
    for path in &user_bins {
        if path.exists() {
            tracing::debug!("Found opencode in user bin: {:?}", path);
            return Some(path.clone());
        }
    }
    
    // System-wide locations
    let system_bins = [
        PathBuf::from("/opt/homebrew/bin/opencode"),
        PathBuf::from("/usr/local/bin/opencode"),
        PathBuf::from("/usr/bin/opencode"),
    ];
    
    for path in &system_bins {
        if path.exists() {
            tracing::debug!("Found opencode in system bin: {:?}", path);
            return Some(path.clone());
        }
    }
    
    // Scan nvm directories
    let nvm_dirs = [
        home.join(".nvm").join("versions").join("node"),
    ];
    
    for nvm_dir in &nvm_dirs {
        if let Some(path) = scan_node_versions(nvm_dir) {
            return Some(path);
        }
    }
    
    // Scan fnm directories
    let fnm_dirs = [
        home.join(".fnm").join("node-versions"),
        home.join("Library").join("Application Support").join("fnm").join("node-versions"),
    ];
    
    for fnm_dir in &fnm_dirs {
        if let Some(path) = scan_fnm_versions(fnm_dir) {
            return Some(path);
        }
    }
    
    None
}

#[cfg(target_os = "windows")]
fn scan_nvm_directory(nvm_path: impl AsRef<std::path::Path>) -> Option<PathBuf> {
    let nvm_path = nvm_path.as_ref();
    if !nvm_path.exists() {
        return None;
    }
    
    let entries = fs::read_dir(nvm_path).ok()?;
    
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let opencode_cmd = path.join("opencode.cmd");
            if opencode_cmd.exists() {
                tracing::debug!("Found opencode.cmd in NVM: {:?}", opencode_cmd);
                return Some(opencode_cmd);
            }
            let opencode_exe = path.join("opencode.exe");
            if opencode_exe.exists() {
                tracing::debug!("Found opencode.exe in NVM: {:?}", opencode_exe);
                return Some(opencode_exe);
            }
        }
    }
    
    None
}

#[cfg(not(target_os = "windows"))]
fn scan_node_versions(versions_dir: impl AsRef<std::path::Path>) -> Option<PathBuf> {
    let versions_dir = versions_dir.as_ref();
    if !versions_dir.exists() {
        return None;
    }
    
    let entries = fs::read_dir(versions_dir).ok()?;
    
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let opencode = path.join("bin").join("opencode");
            if opencode.exists() {
                tracing::debug!("Found opencode in nvm: {:?}", opencode);
                return Some(opencode);
            }
        }
    }
    
    None
}

#[cfg(not(target_os = "windows"))]
fn scan_fnm_versions(versions_dir: impl AsRef<std::path::Path>) -> Option<PathBuf> {
    let versions_dir = versions_dir.as_ref();
    if !versions_dir.exists() {
        return None;
    }
    
    let entries = fs::read_dir(versions_dir).ok()?;
    
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let opencode = path.join("installation").join("bin").join("opencode");
            if opencode.exists() {
                tracing::debug!("Found opencode in fnm: {:?}", opencode);
                return Some(opencode);
            }
        }
    }
    
    None
}

fn find_in_path(executable: &str) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let extensions = ["exe", "cmd", "bat"];
        if let Ok(path_var) = env::var("PATH") {
            for dir in path_var.split(';') {
                for ext in &extensions {
                    let full_path = PathBuf::from(dir).join(format!("{}.{}", executable, ext));
                    if full_path.exists() {
                        return Some(full_path);
                    }
                }
            }
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(path_var) = env::var("PATH") {
            for dir in path_var.split(':') {
                let full_path = PathBuf::from(dir).join(executable);
                if full_path.exists() {
                    return Some(full_path);
                }
            }
        }
    }
    
    None
}

#[cfg(target_os = "windows")]
fn run_opencode_version(opencode_path: &PathBuf) -> Option<String> {
    let path_str = opencode_path.to_string_lossy();
    
    // Check if it's a .cmd or .bat file that needs cmd.exe
    let is_cmd = path_str.ends_with(".cmd") || path_str.ends_with(".bat");
    
    let output = if is_cmd {
        let mut cmd = Command::new("cmd.exe");
        cmd.arg("/C")
            .arg(opencode_path)
            .arg("--version")
            .creation_flags(CREATE_NO_WINDOW);
        cmd.output()
    } else {
        let mut cmd = Command::new(opencode_path);
        cmd.arg("--version")
            .creation_flags(CREATE_NO_WINDOW);
        cmd.output()
    };
    
    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Some tools output version to stderr
            let raw = if stdout.trim().is_empty() {
                stderr.to_string()
            } else {
                stdout.to_string()
            };
            
            tracing::debug!("opencode --version output: {}", raw.trim());
            Some(extract_version(&raw))
        }
        Ok(output) => {
            tracing::debug!("opencode --version failed with status: {:?}", output.status);
            None
        }
        Err(e) => {
            tracing::debug!("Failed to run opencode --version: {}", e);
            None
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn run_opencode_version(opencode_path: &PathBuf) -> Option<String> {
    let output = Command::new(opencode_path)
        .arg("--version")
        .output();
    
    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Some tools output version to stderr
            let raw = if stdout.trim().is_empty() {
                stderr.to_string()
            } else {
                stdout.to_string()
            };
            
            tracing::debug!("opencode --version output: {}", raw.trim());
            Some(extract_version(&raw))
        }
        Ok(output) => {
            tracing::debug!("opencode --version failed with status: {:?}", output.status);
            None
        }
        Err(e) => {
            tracing::debug!("Failed to run opencode --version: {}", e);
            None
        }
    }
}

pub fn check_opencode_installed() -> (bool, Option<String>) {
    tracing::debug!("Checking opencode installation...");
    
    let opencode_path = match resolve_opencode_path() {
        Some(path) => {
            tracing::debug!("Resolved opencode path: {:?}", path);
            path
        }
        None => {
            tracing::debug!("Could not resolve opencode path");
            return (false, None);
        }
    };
    
    match run_opencode_version(&opencode_path) {
        Some(version) => {
            tracing::debug!("opencode version detected: {}", version);
            (true, Some(version))
        }
        None => {
            tracing::debug!("Failed to get opencode version");
            (false, None)
        }
    }
}

fn get_provider_options<'a>(value: &'a Value, provider_name: &str) -> Option<&'a Value> {
    value.get("provider")
        .and_then(|p| p.get(provider_name))
        .and_then(|prov| prov.get("options"))
}

pub fn get_sync_status(proxy_url: &str) -> (bool, bool, Option<String>) {
    let Some((config_path, _, _)) = get_config_paths() else {
        return (false, false, None);
    };

    let mut is_synced = true;
    let mut has_backup = false;
    let mut current_base_url = None;

    let backup_path = config_path.with_file_name(
        format!("{}{}", OPENCODE_CONFIG_FILE, BACKUP_SUFFIX)
    );
    if backup_path.exists() {
        has_backup = true;
    }

    if !config_path.exists() {
        return (false, has_backup, None);
    }

    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return (false, has_backup, None),
    };

    let json: Value = serde_json::from_str(&content).unwrap_or_default();

    let normalized_proxy = proxy_url.trim_end_matches('/');

    let anthropic_opts = get_provider_options(&json, "anthropic");
    let anthropic_url = anthropic_opts
        .and_then(|o| o.get("baseURL"))
        .and_then(|v| v.as_str());
    let anthropic_key = anthropic_opts
        .and_then(|o| o.get("apiKey"))
        .and_then(|v| v.as_str());

    let kiro_opts = get_provider_options(&json, "google");
    let kiro_url = kiro_opts
        .and_then(|o| o.get("baseURL"))
        .and_then(|v| v.as_str());
    let kiro_key = kiro_opts
        .and_then(|o| o.get("apiKey"))
        .and_then(|v| v.as_str());

    if let (Some(url), Some(_key)) = (anthropic_url, anthropic_key) {
        current_base_url = Some(url.to_string());
        if url.trim_end_matches('/') != normalized_proxy {
            is_synced = false;
        }
    } else {
        is_synced = false;
    }

    if let (Some(url), Some(_key)) = (kiro_url, kiro_key) {
        if url.trim_end_matches('/') != normalized_proxy {
            is_synced = false;
        }
    } else {
        is_synced = false;
    }

    (is_synced, has_backup, current_base_url)
}

fn create_backup(path: &PathBuf) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let backup_path = path.with_file_name(format!(
        "{}{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        BACKUP_SUFFIX
    ));

    if backup_path.exists() {
        return Ok(());
    }

    fs::copy(path, &backup_path)
        .map_err(|e| format!("Failed to create backup: {}", e))?;

    Ok(())
}

fn ensure_object(value: &mut Value, key: &str) {
    let needs_reset = match value.get(key) {
        None => true,
        Some(v) if !v.is_object() => true,
        _ => false,
    };
    if needs_reset {
        value[key] = serde_json::json!({});
    }
}

fn ensure_provider_object(provider: &mut serde_json::Map<String, Value>, name: &str) {
    let needs_reset = match provider.get(name) {
        None => true,
        Some(v) if !v.is_object() => true,
        _ => false,
    };
    if needs_reset {
        provider.insert(name.to_string(), serde_json::json!({}));
    }
}

fn merge_provider_options(provider: &mut Value, base_url: &str, api_key: &str) {
    if provider.get("options").is_none() {
        provider["options"] = serde_json::json!({});
    }
    
    if let Some(options) = provider.get_mut("options").and_then(|o| o.as_object_mut()) {
        options.insert("baseURL".to_string(), Value::String(base_url.to_string()));
        options.insert("apiKey".to_string(), Value::String(api_key.to_string()));
    }
}

fn add_missing_models(provider: &mut Value, model_ids: &[&str]) {
    if provider.get("models").is_none() {
        provider["models"] = serde_json::json!({});
    }
    
    if let Some(models) = provider.get_mut("models").and_then(|m| m.as_object_mut()) {
        for &model_id in model_ids {
            if !models.contains_key(model_id) {
                models.insert(model_id.to_string(), serde_json::json!({ "name": model_id }));
            }
        }
    }
}

pub fn sync_opencode_config(
    proxy_url: &str,
    api_key: &str,
    sync_accounts: bool,
    models_to_sync: Option<Vec<String>>,
) -> Result<(), String> {
    let Some((config_path, _ag_config_path, ag_accounts_path)) = get_config_paths() else {
        return Err("Failed to get OpenCode config directory".to_string());
    };

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    create_backup(&config_path)?;

    let mut config: Value = if config_path.exists() {
        fs::read_to_string(&config_path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    if !config.is_object() {
        config = serde_json::json!({});
    }

    if config.get("$schema").is_none() {
        config["$schema"] = Value::String("https://opencode.ai/config.json".to_string());
    }

    let normalized_url = proxy_url.trim_end_matches('/').to_string();

    ensure_object(&mut config, "provider");

    if let Some(provider) = config.get_mut("provider").and_then(|p| p.as_object_mut()) {
        ensure_provider_object(provider, "anthropic");
        if let Some(anthropic) = provider.get_mut("anthropic") {
            merge_provider_options(anthropic, &normalized_url, api_key);
            if let Some(ref m_list) = models_to_sync {
                // 如果传入了模型列表，过滤出属于 anthropic 的模型进行同步 (或者全部同步，取决于策略)
                // 这里暂且采取：如果传入了列表，则按需更新，如果列表为空则不处理，如果列表中有匹配的前缀则优先
                let filtered: Vec<&str> = m_list.iter().map(|s| s.as_str()).filter(|m| m.contains("claude")).collect();
                if !filtered.is_empty() {
                    add_missing_models(anthropic, &filtered);
                } else {
                    add_missing_models(anthropic, ANTHROPIC_MODELS);
                }
            } else {
                add_missing_models(anthropic, ANTHROPIC_MODELS);
            }
        }

        ensure_provider_object(provider, "google");
        if let Some(kiro_provider) = provider.get_mut("google") {
            merge_provider_options(kiro_provider, &normalized_url, api_key);
            if let Some(ref m_list) = models_to_sync {
                let filtered: Vec<&str> = m_list.iter().map(|s| s.as_str()).filter(|m| m.contains("kiro")).collect();
                if !filtered.is_empty() {
                    add_missing_models(kiro_provider, &filtered);
                } else {
                    add_missing_models(kiro_provider, KIRO_MODELS);
                }
            } else {
                add_missing_models(kiro_provider, KIRO_MODELS);
            }
        }
    }

    let tmp_path = config_path.with_extension("tmp");
    fs::write(&tmp_path, serde_json::to_string_pretty(&config).unwrap())
        .map_err(|e| format!("Failed to write temp file: {}", e))?;
    fs::rename(&tmp_path, &config_path)
        .map_err(|e| format!("Failed to rename config file: {}", e))?;

    if sync_accounts {
        sync_accounts_file(&ag_accounts_path)?;
    }

    Ok(())
}

fn sync_accounts_file(accounts_path: &PathBuf) -> Result<(), String> {
    create_backup(accounts_path)?;

    let existing_content = if accounts_path.exists() {
        fs::read_to_string(accounts_path).ok()
    } else {
        None
    };

    let mut existing_rate_limits_by_email: HashMap<String, HashMap<String, i64>> = HashMap::new();
    
    if let Some(ref content) = existing_content {
        if let Ok(existing_json) = serde_json::from_str::<Value>(content) {
            if let Some(existing_accounts) = existing_json.get("accounts").and_then(|a| a.as_array()) {
                for acc in existing_accounts {
                    if let (Some(email), Some(rlt)) = (
                        acc.get("email").and_then(|e| e.as_str()),
                        acc.get("rateLimitResetTimes").and_then(|r| r.as_object())
                    ) {
                        let mut limits = HashMap::new();
                        for (key, val) in rlt.iter() {
                            if let Some(ts) = val.as_i64() {
                                limits.insert(key.clone(), ts);
                            }
                        }
                        if !limits.is_empty() {
                            existing_rate_limits_by_email.insert(email.to_string(), limits);
                        }
                    }
                }
            }
        }
    }

    let app_accounts = crate::modules::account::list_accounts()
        .map_err(|e| format!("Failed to list accounts: {}", e))?;

    let mut new_accounts: Vec<OpencodeAccount> = Vec::new();

    for acc in app_accounts {
        if acc.disabled || acc.proxy_disabled {
            continue;
        }

        let refresh_token = acc.token.refresh_token.clone();
        let project_id = acc.token.project_id.clone();
        
        let rate_limit_reset_times = existing_rate_limits_by_email
            .get(&acc.email)
            .cloned()
            .filter(|m| !m.is_empty());

        new_accounts.push(OpencodeAccount {
            email: acc.email,
            refresh_token,
            project_id,
            rate_limit_reset_times,
        });
    }

    let new_data = serde_json::json!({
        "accounts": new_accounts
    });

    let tmp_path = accounts_path.with_extension("tmp");
    fs::write(&tmp_path, serde_json::to_string_pretty(&new_data).unwrap())
        .map_err(|e| format!("Failed to write accounts temp file: {}", e))?;
    fs::rename(&tmp_path, accounts_path)
        .map_err(|e| format!("Failed to rename accounts file: {}", e))?;

    Ok(())
}

pub fn restore_opencode_config() -> Result<(), String> {
    let Some((config_path, _, accounts_path)) = get_config_paths() else {
        return Err("Failed to get OpenCode config directory".to_string());
    };

    let mut restored = false;

    let config_backup = config_path.with_file_name(format!(
        "{}{}", OPENCODE_CONFIG_FILE, BACKUP_SUFFIX
    ));
    if config_backup.exists() {
        fs::rename(&config_backup, &config_path)
            .map_err(|e| format!("Failed to restore config: {}", e))?;
        restored = true;
    }

    let accounts_backup = accounts_path.with_file_name(format!(
        "{}{}", KIRO_ACCOUNTS_FILE, BACKUP_SUFFIX
    ));
    if accounts_backup.exists() {
        fs::rename(&accounts_backup, &accounts_path)
            .map_err(|e| format!("Failed to restore accounts: {}", e))?;
        restored = true;
    }

    if restored {
        Ok(())
    } else {
        Err("No backup files found".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version_opencode_format() {
        let input = "opencode/1.2.3";
        assert_eq!(extract_version(input), "1.2.3");
    }

    #[test]
    fn test_extract_version_codex_cli_format() {
        let input = "codex-cli 0.86.0\n";
        assert_eq!(extract_version(input), "0.86.0");
    }

    #[test]
    fn test_extract_version_simple() {
        let input = "v2.0.1";
        assert_eq!(extract_version(input), "2.0.1");
    }

    #[test]
    fn test_extract_version_unknown() {
        let input = "some random text without version";
        assert_eq!(extract_version(input), "unknown");
    }
}

pub fn read_opencode_config_content(file_name: Option<String>) -> Result<String, String> {
    let Some((opencode_path, ag_config_path, ag_accounts_path)) = get_config_paths() else {
        return Err("Failed to get OpenCode config directory".to_string());
    };

    // Allowlist of permitted file names
    let allowed_files = [
        OPENCODE_CONFIG_FILE,
        KIRO_CONFIG_FILE,
        KIRO_ACCOUNTS_FILE,
    ];

    // Determine which file to read
    let target_path = match file_name.as_deref() {
        Some(name) if name == KIRO_CONFIG_FILE => ag_config_path,
        Some(name) if name == KIRO_ACCOUNTS_FILE => ag_accounts_path,
        Some(name) if name == OPENCODE_CONFIG_FILE => opencode_path,
        Some(name) => {
            return Err(format!(
                "Invalid file name: {}. Allowed: {:?}",
                name, allowed_files
            ))
        }
        None => opencode_path, // Default to opencode.json
    };

    if !target_path.exists() {
        return Err(format!("Config file does not exist: {:?}", target_path));
    }

    fs::read_to_string(&target_path)
        .map_err(|e| format!("Failed to read config: {}", e))
}

pub async fn get_opencode_sync_status(proxy_url: String) -> Result<OpencodeStatus, String> {
    let (installed, version) = check_opencode_installed();
    let (is_synced, has_backup, current_base_url) = if installed {
        get_sync_status(&proxy_url)
    } else {
        (false, false, None)
    };

    Ok(OpencodeStatus {
        installed,
        version,
        is_synced,
        has_backup,
        current_base_url,
        files: vec![
            OPENCODE_CONFIG_FILE.to_string(),
            KIRO_CONFIG_FILE.to_string(),
            KIRO_ACCOUNTS_FILE.to_string(),
        ],
    })
}

pub async fn execute_opencode_sync(
    proxy_url: String,
    api_key: String,
    sync_accounts: Option<bool>,
    models: Option<Vec<String>>,
) -> Result<(), String> {
    sync_opencode_config(&proxy_url, &api_key, sync_accounts.unwrap_or(false), models)
}

pub async fn execute_opencode_restore() -> Result<(), String> {
    restore_opencode_config()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct GetOpencodeConfigRequest {
    pub file_name: Option<String>,
}

#[allow(dead_code)]
pub async fn get_opencode_config_content(request: GetOpencodeConfigRequest) -> Result<String, String> {
    read_opencode_config_content(request.file_name)
}
