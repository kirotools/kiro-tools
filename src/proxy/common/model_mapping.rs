// 模型名称映射 (Kiro upstream only)

use serde::Serialize;

/// Model metadata for frontend display
#[derive(Debug, Clone, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub group: String,
    pub thinking: bool,
}

/// Kiro-supported base models with display metadata
const KIRO_BASE_MODELS: &[(&str, &str, &str, bool)] = &[
    ("claude-haiku-4-5", "Claude Haiku 4.5", "Claude 4", false),
    ("claude-sonnet-4-5", "Claude Sonnet 4.5", "Claude 4", false),
    ("claude-sonnet-4-5-thinking", "Claude Sonnet 4.5 (Thinking)", "Claude 4", true),
    ("claude-opus-4-6", "Claude Opus 4.6", "Claude 4", false),
    ("claude-opus-4-6-thinking", "Claude Opus 4.6 (Thinking)", "Claude 4", true),
];

const KIRO_MODELS: &[&str] = &[
    "claude-haiku-4-5",
    "claude-sonnet-4-5",
    "claude-sonnet-4-5-thinking",
    "claude-opus-4-6",
    "claude-opus-4-6-thinking",
];

pub async fn get_all_dynamic_models(
    custom_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
) -> Vec<String> {
    use std::collections::HashSet;
    let mut model_ids: HashSet<String> = KIRO_MODELS.iter().map(|s| s.to_string()).collect();

    {
        let mapping = custom_mapping.read().await;
        for key in mapping.keys() {
            model_ids.insert(key.clone());
        }
    }

    let mut sorted_ids: Vec<_> = model_ids.into_iter().collect();
    sorted_ids.sort();
    sorted_ids
}

pub async fn get_all_models_with_metadata(
    custom_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
) -> Vec<ModelInfo> {
    use std::collections::HashSet;

    let mut models: Vec<ModelInfo> = KIRO_BASE_MODELS
        .iter()
        .map(|(id, name, group, thinking)| ModelInfo {
            id: id.to_string(),
            name: name.to_string(),
            group: group.to_string(),
            thinking: *thinking,
        })
        .collect();

    let known_ids: HashSet<&str> = KIRO_BASE_MODELS.iter().map(|(id, _, _, _)| *id).collect();

    {
        let mapping = custom_mapping.read().await;
        for key in mapping.keys() {
            if !known_ids.contains(key.as_str()) {
                models.push(ModelInfo {
                    id: key.clone(),
                    name: key.clone(),
                    group: "Custom".to_string(),
                    thinking: key.contains("thinking"),
                });
            }
        }
    }

    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
}

/// Normalize any physical model name to a standard protection ID for quota tracking.
/// Returns `None` if the model doesn't match any protected category.
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
        assert_eq!(normalize_to_standard_id("claude-opus-4-6-thinking"), Some("claude".to_string()));
        assert_eq!(normalize_to_standard_id("claude-sonnet-4-5"), Some("claude".to_string()));
        assert_eq!(normalize_to_standard_id("unknown-model"), None);
    }
}
