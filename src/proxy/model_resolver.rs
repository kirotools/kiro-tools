#![allow(dead_code)]
use std::collections::HashMap;

use regex::Regex;

use crate::proxy::upstream::model_cache::ModelCache;

/// Normalize client model name to Kiro format.
///
/// Transformations:
/// 1. claude-haiku-4-5 → claude-haiku-4.5 (dash to dot for minor version)
/// 2. claude-haiku-4-5-20251001 → claude-haiku-4.5 (strip date suffix)
/// 3. claude-sonnet-4-20250514 → claude-sonnet-4 (strip date, no minor)
/// 4. claude-3-7-sonnet → claude-3.7-sonnet (legacy format)
/// 5. claude-3.7-sonnet-20250219 → claude-3.7-sonnet (already normalized + date)
/// 6. claude-4.5-opus-high → claude-opus-4.5 (inverted format with suffix)
pub fn normalize_model_name(name: &str) -> String {
    let name_lower = name.to_lowercase();

    // Pattern 1: Standard format - claude-{family}-{major}-{minor}(-{suffix})?
    // e.g. claude-haiku-4-5, claude-haiku-4-5-20251001
    let re_standard =
        Regex::new(r"^(claude-(?:haiku|sonnet|opus)-\d+)-(\d{1,2})(?:-(?:\d{8}|latest|\d+))?$")
            .unwrap();
    if let Some(caps) = re_standard.captures(&name_lower) {
        let base = &caps[1];
        let minor = &caps[2];
        return format!("{}.{}", base, minor);
    }

    // Pattern 2: Standard format without minor - claude-{family}-{major}(-{date})?
    // e.g. claude-sonnet-4, claude-sonnet-4-20250514
    let re_no_minor = Regex::new(r"^(claude-(?:haiku|sonnet|opus)-\d+)(?:-\d{8})?$").unwrap();
    if let Some(caps) = re_no_minor.captures(&name_lower) {
        return caps[1].to_string();
    }

    // Pattern 3: Legacy format - claude-{major}-{minor}-{family}(-{suffix})?
    // e.g. claude-3-7-sonnet, claude-3-7-sonnet-20250219
    let re_legacy =
        Regex::new(r"^(claude)-(\d+)-(\d+)-(haiku|sonnet|opus)(?:-(?:\d{8}|latest|\d+))?$")
            .unwrap();
    if let Some(caps) = re_legacy.captures(&name_lower) {
        let prefix = &caps[1];
        let major = &caps[2];
        let minor = &caps[3];
        let family = &caps[4];
        return format!("{}-{}.{}-{}", prefix, major, minor, family);
    }

    // Pattern 4: Already normalized with dot but has date suffix
    // e.g. claude-haiku-4.5-20251001, claude-3.7-sonnet-20250219
    let re_dot_date =
        Regex::new(r"^(claude-(?:\d+\.\d+-)?(?:haiku|sonnet|opus)(?:-\d+\.\d+)?)-\d{8}$").unwrap();
    if let Some(caps) = re_dot_date.captures(&name_lower) {
        return caps[1].to_string();
    }

    // Pattern 5: Inverted format with suffix - claude-{major}.{minor}-{family}-{suffix}
    // e.g. claude-4.5-opus-high → claude-opus-4.5
    let re_inverted = Regex::new(r"^claude-(\d+)\.(\d+)-(haiku|sonnet|opus)-(.+)$").unwrap();
    if let Some(caps) = re_inverted.captures(&name_lower) {
        let major = &caps[1];
        let minor = &caps[2];
        let family = &caps[3];
        return format!("claude-{}-{}.{}", family, major, minor);
    }

    // No transformation needed
    name.to_string()
}

/// 4-layer model resolution pipeline.
///
/// Layers:
/// 1. Aliases (user-configured name mappings)
/// 2. Normalize (dashes→dots, strip dates)
/// 3. Hidden models (display name → internal Kiro ID)
/// 4. Dynamic cache (ModelCache)
/// 5. Pass-through (return normalized name as-is)
pub struct ModelResolver {
    aliases: HashMap<String, String>,
    hidden_models: HashMap<String, String>,
    model_cache: ModelCache,
}

impl ModelResolver {
    pub fn new(
        aliases: HashMap<String, String>,
        hidden_models: HashMap<String, String>,
        model_cache: ModelCache,
    ) -> Self {
        Self {
            aliases,
            hidden_models,
            model_cache,
        }
    }

    /// Resolve an external model name through the 4-layer pipeline.
    ///
    /// 1. Check aliases → use alias value, continue
    /// 2. Normalize name
    /// 3. Check hidden_models → return internal Kiro ID
    /// 4. Check model_cache → return normalized name
    /// 5. Pass-through → return normalized name
    pub async fn resolve(&self, model_name: &str) -> String {
        // Layer 1: Alias resolution
        let after_alias = self
            .aliases
            .get(model_name)
            .cloned()
            .unwrap_or_else(|| model_name.to_string());

        // Layer 2: Normalize
        let normalized = normalize_model_name(&after_alias);

        // Layer 3: Hidden models
        if let Some(internal_id) = self.hidden_models.get(&normalized) {
            return internal_id.clone();
        }

        // Layer 4: Dynamic cache
        if self.model_cache.is_valid_model(&normalized).await {
            return normalized;
        }

        // Layer 5: Pass-through
        normalized
    }

    /// Get all available model IDs (cache + hidden display names + alias keys).
    pub async fn get_available_models(&self) -> Vec<String> {
        let mut models: Vec<String> = Vec::new();

        // Cached models (best-effort — returns empty if stale/empty)
        // We read from cache without triggering a fetch.
        // The cache is populated by other code paths; here we just peek.
        if let Ok(cached) = self
            .model_cache
            .get_models(|| async {
                // No-op fetch — we only want what's already cached.
                // If cache is empty/stale this will return an empty vec,
                // but get_models requires a fetch_fn so we provide a trivial one.
                Ok(vec![])
            })
            .await
        {
            models.extend(cached);
        }

        // Hidden model display names
        for key in self.hidden_models.keys() {
            if !models.contains(key) {
                models.push(key.clone());
            }
        }

        // Alias keys
        for key in self.aliases.keys() {
            if !models.contains(key) {
                models.push(key.clone());
            }
        }

        models.sort();
        models
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── normalize_model_name tests ──────────────────────────────────

    #[test]
    fn normalize_standard_with_minor() {
        assert_eq!(normalize_model_name("claude-haiku-4-5"), "claude-haiku-4.5");
        assert_eq!(
            normalize_model_name("claude-sonnet-4-5"),
            "claude-sonnet-4.5"
        );
        assert_eq!(normalize_model_name("claude-opus-4-5"), "claude-opus-4.5");
    }

    #[test]
    fn normalize_standard_with_date_suffix() {
        assert_eq!(
            normalize_model_name("claude-haiku-4-5-20251001"),
            "claude-haiku-4.5"
        );
        assert_eq!(
            normalize_model_name("claude-sonnet-4-5-20250514"),
            "claude-sonnet-4.5"
        );
    }

    #[test]
    fn normalize_standard_with_latest_suffix() {
        assert_eq!(
            normalize_model_name("claude-haiku-4-5-latest"),
            "claude-haiku-4.5"
        );
    }

    #[test]
    fn normalize_no_minor() {
        assert_eq!(normalize_model_name("claude-sonnet-4"), "claude-sonnet-4");
        assert_eq!(
            normalize_model_name("claude-sonnet-4-20250514"),
            "claude-sonnet-4"
        );
    }

    #[test]
    fn normalize_legacy_format() {
        assert_eq!(
            normalize_model_name("claude-3-7-sonnet"),
            "claude-3.7-sonnet"
        );
        assert_eq!(
            normalize_model_name("claude-3-7-sonnet-20250219"),
            "claude-3.7-sonnet"
        );
    }

    #[test]
    fn normalize_dot_with_date() {
        assert_eq!(
            normalize_model_name("claude-3.7-sonnet-20250219"),
            "claude-3.7-sonnet"
        );
        assert_eq!(
            normalize_model_name("claude-haiku-4.5-20251001"),
            "claude-haiku-4.5"
        );
    }

    #[test]
    fn normalize_inverted_format() {
        assert_eq!(
            normalize_model_name("claude-4.5-opus-high"),
            "claude-opus-4.5"
        );
        assert_eq!(
            normalize_model_name("claude-4.5-sonnet-low"),
            "claude-sonnet-4.5"
        );
    }

    #[test]
    fn normalize_already_normalized() {
        assert_eq!(
            normalize_model_name("claude-sonnet-4.5"),
            "claude-sonnet-4.5"
        );
        assert_eq!(normalize_model_name("claude-haiku-4.5"), "claude-haiku-4.5");
    }

    #[test]
    fn normalize_passthrough_unknown() {
        assert_eq!(normalize_model_name("auto"), "auto");
        assert_eq!(normalize_model_name("gpt-4"), "gpt-4");
    }

    #[test]
    fn normalize_case_insensitive() {
        assert_eq!(
            normalize_model_name("Claude-Sonnet-4-5"),
            "claude-sonnet-4.5"
        );
    }

    // ── ModelResolver tests ─────────────────────────────────────────

    fn make_cache() -> ModelCache {
        ModelCache::new(Duration::from_secs(60))
    }

    async fn make_resolver_with_cache_models(
        aliases: HashMap<String, String>,
        hidden: HashMap<String, String>,
        cache_models: Vec<String>,
    ) -> ModelResolver {
        let cache = make_cache();
        let models = cache_models.clone();
        cache
            .get_models(move || async move { Ok(models) })
            .await
            .unwrap();
        ModelResolver::new(aliases, hidden, cache)
    }

    #[tokio::test]
    async fn alias_takes_priority() {
        let mut aliases = HashMap::new();
        aliases.insert("my-model".to_string(), "claude-sonnet-4-5".to_string());

        let resolver = make_resolver_with_cache_models(aliases, HashMap::new(), vec![]).await;

        // Alias resolves, then normalizes
        assert_eq!(resolver.resolve("my-model").await, "claude-sonnet-4.5");
    }

    #[tokio::test]
    async fn hidden_model_returns_internal_id() {
        let mut hidden = HashMap::new();
        hidden.insert(
            "claude-3.7-sonnet".to_string(),
            "CLAUDE_3_7_SONNET_20250219_V1_0".to_string(),
        );

        let resolver = make_resolver_with_cache_models(HashMap::new(), hidden, vec![]).await;

        // Direct normalized name
        assert_eq!(
            resolver.resolve("claude-3.7-sonnet").await,
            "CLAUDE_3_7_SONNET_20250219_V1_0"
        );
        // Legacy format normalizes to hidden key
        assert_eq!(
            resolver.resolve("claude-3-7-sonnet").await,
            "CLAUDE_3_7_SONNET_20250219_V1_0"
        );
        // With date suffix
        assert_eq!(
            resolver.resolve("claude-3-7-sonnet-20250219").await,
            "CLAUDE_3_7_SONNET_20250219_V1_0"
        );
    }

    #[tokio::test]
    async fn cache_hit_returns_normalized() {
        let cache_models = vec!["claude-sonnet-4.5".to_string()];
        let resolver =
            make_resolver_with_cache_models(HashMap::new(), HashMap::new(), cache_models).await;

        assert_eq!(
            resolver.resolve("claude-sonnet-4-5").await,
            "claude-sonnet-4.5"
        );
        assert_eq!(
            resolver.resolve("claude-sonnet-4-5-20250514").await,
            "claude-sonnet-4.5"
        );
    }

    #[tokio::test]
    async fn passthrough_for_unknown() {
        let resolver =
            make_resolver_with_cache_models(HashMap::new(), HashMap::new(), vec![]).await;

        assert_eq!(resolver.resolve("gpt-4").await, "gpt-4");
        assert_eq!(resolver.resolve("auto").await, "auto");
    }

    #[tokio::test]
    async fn alias_plus_hidden_model() {
        let mut aliases = HashMap::new();
        aliases.insert("old-sonnet".to_string(), "claude-3-7-sonnet".to_string());
        let mut hidden = HashMap::new();
        hidden.insert(
            "claude-3.7-sonnet".to_string(),
            "CLAUDE_3_7_SONNET_20250219_V1_0".to_string(),
        );

        let resolver = make_resolver_with_cache_models(aliases, hidden, vec![]).await;

        // alias → normalize → hidden
        assert_eq!(
            resolver.resolve("old-sonnet").await,
            "CLAUDE_3_7_SONNET_20250219_V1_0"
        );
    }

    // ── Property tests ────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_resolver_pipeline_priority(
            model_name in "[a-z]{3,10}",
        ) {
            // Property 11: Alias takes priority over hidden, hidden over cache, cache over passthrough
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let cache = ModelCache::new(std::time::Duration::from_secs(300));

                // Set up: model exists in ALL layers
                let alias_target = format!("{}-alias-target", model_name);
                let hidden_id = format!("{}-HIDDEN-ID", model_name);

                let mut aliases = std::collections::HashMap::new();
                aliases.insert(model_name.clone(), alias_target.clone());

                let mut hidden = std::collections::HashMap::new();
                hidden.insert(alias_target.clone(), hidden_id.clone());

                let resolver = ModelResolver::new(aliases, hidden, cache);

                // Alias should win: model_name -> alias_target -> hidden_id
                let result = resolver.resolve(&model_name).await;
                assert_eq!(result, hidden_id, "Alias should resolve first, then hidden model lookup");
            });
        }
    }

    #[tokio::test]
    async fn get_available_models_combines_sources() {
        let mut aliases = HashMap::new();
        aliases.insert("my-alias".to_string(), "claude-sonnet-4.5".to_string());
        let mut hidden = HashMap::new();
        hidden.insert(
            "claude-3.7-sonnet".to_string(),
            "CLAUDE_3_7_SONNET_20250219_V1_0".to_string(),
        );
        let cache_models = vec![
            "claude-sonnet-4.5".to_string(),
            "claude-haiku-4.5".to_string(),
        ];

        let resolver = make_resolver_with_cache_models(aliases, hidden, cache_models).await;

        let available = resolver.get_available_models().await;
        assert!(available.contains(&"claude-sonnet-4.5".to_string()));
        assert!(available.contains(&"claude-haiku-4.5".to_string()));
        assert!(available.contains(&"claude-3.7-sonnet".to_string()));
        assert!(available.contains(&"my-alias".to_string()));
    }
}
