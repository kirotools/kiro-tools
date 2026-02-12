#![allow(dead_code)]
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

struct CachedModels {
    models: Vec<String>,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedModels {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() > self.ttl
    }
}

/// Thread-safe model metadata cache with TTL.
#[derive(Clone)]
pub struct ModelCache {
    cache: Arc<RwLock<Option<CachedModels>>>,
    ttl: Duration,
}

impl ModelCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            ttl,
        }
    }

    /// Get cached models, or call `fetch_fn` if cache is empty/stale.
    /// `F` is an async function that fetches a fresh model list.
    pub async fn get_models<F, Fut>(
        &self,
        fetch_fn: F,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>>,
    {
        // 1. Read lock — check if cache exists and is not stale
        {
            let guard = self.cache.read().await;
            if let Some(ref cached) = *guard {
                if !cached.is_stale() {
                    return Ok(cached.models.clone());
                }
            }
        }

        // 2. Stale or empty — acquire write lock, double-check, then fetch
        let mut guard = self.cache.write().await;

        // Double-check after acquiring write lock (another task may have refreshed)
        if let Some(ref cached) = *guard {
            if !cached.is_stale() {
                return Ok(cached.models.clone());
            }
        }

        let models = fetch_fn().await?;

        *guard = Some(CachedModels {
            models: models.clone(),
            fetched_at: Instant::now(),
            ttl: self.ttl,
        });

        Ok(models)
    }

    /// Manually invalidate the cache.
    pub async fn invalidate(&self) {
        let mut guard = self.cache.write().await;
        *guard = None;
    }

    /// Check if a model exists in cache (best-effort).
    pub async fn is_valid_model(&self, model_id: &str) -> bool {
        let guard = self.cache.read().await;
        match *guard {
            Some(ref cached) if !cached.is_stale() => {
                cached.models.iter().any(|m| m == model_id)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn get_models_calls_fetch_fn_on_first_call() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cc = call_count.clone();

        let cache = ModelCache::new(Duration::from_secs(60));
        let result = cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["model-a".into(), "model-b".into()])
                }
            })
            .await
            .unwrap();

        assert_eq!(result, vec!["model-a", "model-b"]);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn get_models_returns_cached_within_ttl() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cache = ModelCache::new(Duration::from_secs(60));

        // First call — populates cache
        let cc = call_count.clone();
        cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["model-a".into()])
                }
            })
            .await
            .unwrap();

        // Second call — should use cache, not call fetch_fn
        let cc = call_count.clone();
        let result = cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["model-x".into()])
                }
            })
            .await
            .unwrap();

        assert_eq!(result, vec!["model-a"]);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn get_models_refetches_after_ttl_expires() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cache = ModelCache::new(Duration::from_millis(10));

        // First call
        let cc = call_count.clone();
        cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["old-model".into()])
                }
            })
            .await
            .unwrap();

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Second call — should refetch
        let cc = call_count.clone();
        let result = cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["new-model".into()])
                }
            })
            .await
            .unwrap();

        assert_eq!(result, vec!["new-model"]);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_clears_cache() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cache = ModelCache::new(Duration::from_secs(60));

        // Populate
        let cc = call_count.clone();
        cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["model-a".into()])
                }
            })
            .await
            .unwrap();

        // Invalidate
        cache.invalidate().await;

        // Next call should fetch again
        let cc = call_count.clone();
        let result = cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["model-b".into()])
                }
            })
            .await
            .unwrap();

        assert_eq!(result, vec!["model-b"]);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn is_valid_model_checks_cache() {
        let cache = ModelCache::new(Duration::from_secs(60));

        // Empty cache — always false
        assert!(!cache.is_valid_model("model-a").await);

        // Populate cache
        cache
            .get_models(|| async {
                Ok(vec!["model-a".into(), "model-b".into()])
            })
            .await
            .unwrap();

        assert!(cache.is_valid_model("model-a").await);
        assert!(cache.is_valid_model("model-b").await);
        assert!(!cache.is_valid_model("model-c").await);
    }

    /// Property 20: first call fetches, second within TTL returns cached,
    /// after TTL fetches again.
    #[tokio::test]
    async fn prop_cache_ttl_behavior() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let cache = ModelCache::new(Duration::from_millis(50));

        let cc = call_count.clone();
        let r1 = cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["m1".into()])
                }
            })
            .await
            .unwrap();
        assert_eq!(r1, vec!["m1"]);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        let cc = call_count.clone();
        let r2 = cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["m2".into()])
                }
            })
            .await
            .unwrap();
        assert_eq!(r2, vec!["m1"]);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(60)).await;

        let cc = call_count.clone();
        let r3 = cache
            .get_models(|| {
                let cc = cc.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    Ok(vec!["m3".into()])
                }
            })
            .await
            .unwrap();
        assert_eq!(r3, vec!["m3"]);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }
}
