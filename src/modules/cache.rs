//! Kiro cache clearing module
//!
//! Provides functionality to clear Kiro application cache directories
//! to resolve login failures, version validation errors, and OAuth issues.

use crate::modules::logger;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Result of cache clearing operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearResult {
    /// Paths that were successfully cleared
    pub cleared_paths: Vec<String>,
    /// Total size freed in bytes
    pub total_size_freed: u64,
    /// Errors encountered during clearing
    pub errors: Vec<String>,
}

/// Get all known Kiro cache paths for the current platform
pub fn get_kiro_cache_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            // Primary cache location - HTTP storage (contains User-Agent cache)
            // This is the main cause of "version no longer supported" errors
            paths.push(home.join("Library/HTTPStorages/com.kiro-tools"));

            // Application caches
            paths.push(home.join("Library/Caches/com.kiro-tools"));

            // Alternative cache locations that may exist
            paths.push(home.join(".kiro_tools"));
            paths.push(home.join(".config/kiro_tools"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // LocalAppData cache
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let local_path = PathBuf::from(&local_app_data);
            paths.push(local_path.join("KiroTools\\Cache"));
            paths.push(local_path.join("KiroTools\\Cache"));
        }

        // AppData cache
        if let Ok(app_data) = std::env::var("APPDATA") {
            let app_path = PathBuf::from(&app_data);
            paths.push(app_path.join("KiroTools\\Cache"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs::home_dir() {
            // XDG cache directory
            paths.push(home.join(".cache/KiroTools"));
            paths.push(home.join(".cache/kiro-tools"));

            // Alternative locations
            paths.push(home.join(".kiro_tools"));
        }

        // XDG_CACHE_HOME if set
        if let Ok(xdg_cache) = std::env::var("XDG_CACHE_HOME") {
            let cache_path = PathBuf::from(&xdg_cache);
            paths.push(cache_path.join("KiroTools"));
            paths.push(cache_path.join("kiro-tools"));
        }
    }

    paths
}

/// Get only existing cache paths
pub fn get_existing_cache_paths() -> Vec<PathBuf> {
    get_kiro_cache_paths()
        .into_iter()
        .filter(|p| p.exists())
        .collect()
}

/// Calculate directory size recursively
fn get_dir_size(path: &PathBuf) -> u64 {
    let mut size = 0u64;

    if path.is_file() {
        if let Ok(metadata) = fs::metadata(path) {
            return metadata.len();
        }
        return 0;
    }

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if let Ok(metadata) = fs::metadata(&entry_path) {
                    size += metadata.len();
                }
            } else if entry_path.is_dir() {
                size += get_dir_size(&entry_path);
            }
        }
    }

    size
}

/// Clear a single directory and return size freed
fn clear_directory(path: &PathBuf) -> Result<u64, String> {
    if !path.exists() {
        return Ok(0);
    }

    let size = get_dir_size(path);

    // Remove directory contents
    fs::remove_dir_all(path).map_err(|e| format!("Failed to remove {}: {}", path.display(), e))?;

    Ok(size)
}

/// Clear Kiro application cache
///
/// # Arguments
/// * `custom_paths` - Optional custom paths to clear. If None, uses default platform paths.
///
/// # Returns
/// * `ClearResult` containing cleared paths, total size freed, and any errors
pub fn clear_kiro_cache(custom_paths: Option<Vec<String>>) -> Result<ClearResult, String> {
    let paths: Vec<PathBuf> = match custom_paths {
        Some(custom) => custom.into_iter().map(PathBuf::from).collect(),
        None => get_kiro_cache_paths(),
    };

    logger::log_info(&format!(
        "Starting Kiro cache clearing, {} potential paths",
        paths.len()
    ));

    let mut result = ClearResult {
        cleared_paths: Vec::new(),
        total_size_freed: 0,
        errors: Vec::new(),
    };

    for path in paths {
        if !path.exists() {
            logger::log_info(&format!(
                "Cache path does not exist, skipping: {}",
                path.display()
            ));
            continue;
        }

        logger::log_info(&format!("Clearing cache: {}", path.display()));

        match clear_directory(&path) {
            Ok(size) => {
                result
                    .cleared_paths
                    .push(path.to_string_lossy().to_string());
                result.total_size_freed += size;
                logger::log_info(&format!(
                    "Cleared {}: {:.2} MB freed",
                    path.display(),
                    size as f64 / 1024.0 / 1024.0
                ));
            }
            Err(e) => {
                logger::log_warn(&format!("Failed to clear {}: {}", path.display(), e));
                result.errors.push(e);
            }
        }
    }

    let total_mb = result.total_size_freed as f64 / 1024.0 / 1024.0;
    logger::log_info(&format!(
        "Kiro cache clearing completed: {} paths cleared, {:.2} MB freed, {} errors",
        result.cleared_paths.len(),
        total_mb,
        result.errors.len()
    ));

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cache_paths_not_empty() {
        let paths = get_kiro_cache_paths();
        assert!(!paths.is_empty(), "Should return at least one cache path");
    }

    #[test]
    fn test_clear_result_serialization() {
        let result = ClearResult {
            cleared_paths: vec!["/test/path".to_string()],
            total_size_freed: 1024,
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("cleared_paths"));
        assert!(json.contains("total_size_freed"));
    }
}
