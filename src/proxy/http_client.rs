#![allow(dead_code)]
// Configurable HTTP client builder
// Builds reqwest::Client with proxy, connection pool, and timeout settings

use std::time::Duration;

/// HTTP client configuration
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Optional proxy URL (http://, https://, socks5://)
    pub proxy_url: Option<String>,
    /// Max idle connections per host (default: 10)
    pub pool_max_idle_per_host: usize,
    /// Connection timeout (default: 30s)
    pub connect_timeout: Duration,
    /// Overall request timeout (default: 120s)
    pub request_timeout: Duration,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            proxy_url: None,
            pool_max_idle_per_host: 10,
            connect_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(120),
        }
    }
}

/// Build a configured reqwest::Client from the given config.
pub fn build_http_client(config: &HttpClientConfig) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout);

    if let Some(proxy_url) = &config.proxy_url {
        if !proxy_url.is_empty() {
            let proxy = reqwest::Proxy::all(proxy_url).expect("Invalid proxy URL");
            builder = builder.proxy(proxy);
        }
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HttpClientConfig::default();
        assert!(config.proxy_url.is_none());
        assert_eq!(config.pool_max_idle_per_host, 10);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.request_timeout, Duration::from_secs(120));
    }

    #[test]
    fn test_build_client_default() {
        let config = HttpClientConfig::default();
        let client = build_http_client(&config);
        assert!(client.is_ok());
    }
}
