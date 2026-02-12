// 模型名称映射 (Kiro upstream only)
// Dynamic model list fetched from Kiro /ListAvailableModels API with fallback.

use serde::Serialize;

use crate::proxy::upstream::model_cache::ModelCache;

#[derive(Debug, Clone, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub group: String,
    pub thinking: bool,
}

pub const FALLBACK_MODELS: &[&str] = &[
    "auto",
    "claude-sonnet-4",
    "claude-haiku-4.5",
    "claude-sonnet-4.5",
    "claude-opus-4.5",
    "claude-opus-4.6",
];

pub async fn fetch_models_from_kiro(
    access_token: &str,
    region: &str,
    profile_arn: Option<&str>,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let host = crate::auth::config::get_kiro_q_host(region);
    let url = format!("{}/ListAvailableModels", host);
    let fingerprint = crate::auth::config::get_machine_fingerprint();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {}", access_token).parse()?,
    );
    let ua = format!(
        "aws-sdk-js/1.0.27 ua/2.1 os/win32#10.0.19044 lang/js md/nodejs#22.21.1 api/codewhispererstreaming#1.0.27 m/E KiroIDE-0.7.45-{}",
        fingerprint
    );
    headers.insert(reqwest::header::USER_AGENT, ua.parse()?);
    headers.insert(
        "x-amz-user-agent",
        format!("aws-sdk-js/1.0.27 KiroIDE-0.7.45-{}", fingerprint).parse()?,
    );

    let client = reqwest::Client::new();
    let mut req = client
        .get(&url)
        .headers(headers)
        .query(&[("origin", "AI_EDITOR")]);
    if let Some(arn) = profile_arn {
        req = req.query(&[("profileArn", arn)]);
    }

    let resp = req
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(format!("ListAvailableModels HTTP {}", resp.status()).into());
    }

    let data: serde_json::Value = resp.json().await?;
    let models = data
        .get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("modelId").and_then(|id| id.as_str()).map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if models.is_empty() {
        return Err("ListAvailableModels returned empty list".into());
    }

    tracing::info!(
        "Fetched {} models from Kiro API: {:?}",
        models.len(),
        models
    );
    Ok(models)
}

pub async fn get_all_dynamic_models(
    model_cache: &ModelCache,
    _custom_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
) -> Vec<String> {
    let cached = model_cache
        .get_models(|| async { Ok(FALLBACK_MODELS.iter().map(|s| s.to_string()).collect()) })
        .await
        .unwrap_or_else(|_| FALLBACK_MODELS.iter().map(|s| s.to_string()).collect());

    let mut sorted: Vec<_> = cached.into_iter().collect();
    sorted.sort();
    sorted
}

fn model_display_name(id: &str) -> String {
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() >= 3 && parts[0] == "claude" {
        let family = parts[1];
        let version = parts[2..].join(".");
        format!("Claude {} {}", capitalize(family), version)
    } else if parts.len() == 2 && parts[0] == "claude" {
        format!("Claude {}", capitalize(parts[1]))
    } else {
        id.to_string()
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

pub async fn get_all_models_with_metadata(
    model_cache: &ModelCache,
    _custom_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
) -> Vec<ModelInfo> {
    let cached = model_cache
        .get_models(|| async { Ok(FALLBACK_MODELS.iter().map(|s| s.to_string()).collect()) })
        .await
        .unwrap_or_else(|_| FALLBACK_MODELS.iter().map(|s| s.to_string()).collect());

    let mut models: Vec<ModelInfo> = cached
        .into_iter()
        .map(|id| {
            let group = if id.starts_with("claude") {
                "Claude".to_string()
            } else {
                "Other".to_string()
            };
            ModelInfo {
                name: model_display_name(&id),
                group,
                thinking: id.contains("thinking"),
                id,
            }
        })
        .collect();

    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
}

pub fn normalize_to_standard_id(model_name: &str) -> Option<String> {
    let lower = model_name.to_lowercase();
    if lower.starts_with("claude") {
        Some("claude".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(
            normalize_to_standard_id("claude-opus-4-6-thinking"),
            Some("claude".to_string())
        );
        assert_eq!(
            normalize_to_standard_id("claude-sonnet-4-5"),
            Some("claude".to_string())
        );
        assert_eq!(normalize_to_standard_id("unknown-model"), None);
    }

    #[test]
    fn test_model_display_name() {
        assert_eq!(model_display_name("claude-sonnet-4.5"), "Claude Sonnet 4.5");
        assert_eq!(model_display_name("claude-haiku-4.5"), "Claude Haiku 4.5");
        assert_eq!(model_display_name("claude-opus-4.6"), "Claude Opus 4.6");
        assert_eq!(model_display_name("auto"), "auto");
    }

    #[test]
    fn test_fallback_models_no_thinking_variants() {
        for m in FALLBACK_MODELS {
            assert!(
                !m.contains("thinking"),
                "Fallback '{}' should not have thinking variant",
                m
            );
        }
    }
}
