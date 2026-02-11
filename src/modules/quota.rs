use serde::Deserialize;
use crate::models::QuotaData;

const KIRO_API_REGION: &str = "us-east-1";

const MAX_RETRIES: u32 = 3;

// ─── Kiro Usage Limits API types ──────────────────────────────────────

#[derive(Debug, Deserialize)]
struct KiroUsageLimits {
    #[serde(rename = "usageBreakdownList", default)]
    usage_breakdown_list: Vec<KiroUsageBreakdown>,
    #[serde(rename = "userInfo", default)]
    _user_info: KiroUserInfo,
    #[serde(rename = "subscriptionInfo", default)]
    subscription_info: KiroSubscriptionInfo,
    #[allow(dead_code)]
    #[serde(rename = "daysUntilReset", default)]
    days_until_reset: i32,
    #[serde(rename = "nextDateReset", default)]
    next_date_reset: f64,
}

#[derive(Debug, Deserialize, Default)]
struct KiroUsageBreakdown {
    #[serde(rename = "resourceType", default)]
    resource_type: String,
    #[serde(rename = "usageLimitWithPrecision", default)]
    usage_limit: f64,
    #[serde(rename = "currentUsageWithPrecision", default)]
    current_usage: f64,
    #[serde(rename = "nextDateReset", default)]
    next_date_reset: f64,
    #[allow(dead_code)]
    #[serde(rename = "freeTrialInfo")]
    free_trial_info: Option<KiroFreeTrialInfo>,
    #[serde(rename = "displayName", default)]
    display_name: String,
    #[allow(dead_code)]
    unit: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct KiroFreeTrialInfo {
    #[allow(dead_code)]
    #[serde(rename = "freeTrialStatus", default)]
    free_trial_status: String,
    #[allow(dead_code)]
    #[serde(rename = "usageLimitWithPrecision", default)]
    usage_limit: f64,
    #[allow(dead_code)]
    #[serde(rename = "currentUsageWithPrecision", default)]
    current_usage: f64,
}

#[derive(Debug, Deserialize, Default)]
struct KiroUserInfo {
    #[allow(dead_code)]
    #[serde(default)]
    email: String,
}

#[derive(Debug, Deserialize, Default)]
struct KiroSubscriptionInfo {
    #[serde(rename = "subscriptionTitle", default)]
    subscription_title: String,
    #[serde(rename = "type", default)]
    subscription_type: String,
}

/// Get shared HTTP Client (15s timeout)
async fn create_client(account_id: Option<&str>) -> reqwest::Client {
    if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 15).await
    } else {
        crate::utils::http::get_client()
    }
}

fn epoch_millis_to_rfc3339(millis: f64) -> String {
    if millis <= 0.0 {
        return String::new();
    }
    let secs = (millis / 1000.0) as i64;
    let nanos = ((millis % 1000.0) * 1_000_000.0) as u32;
    match chrono::DateTime::from_timestamp(secs, nanos) {
        Some(dt) => dt.to_rfc3339(),
        None => String::new(),
    }
}

pub async fn fetch_quota(access_token: &str, email: &str, account_id: Option<&str>) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    fetch_quota_with_cache(access_token, email, None, account_id).await
}

pub async fn fetch_quota_with_cache(
    access_token: &str,
    email: &str,
    _cached_project_id: Option<&str>,
    account_id: Option<&str>,
) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    use crate::error::AppError;

    let fingerprint = crate::auth::config::get_machine_fingerprint();
    let host = format!("codewhisperer.{}.amazonaws.com", KIRO_API_REGION);
    let url = format!(
        "https://{}/getUsageLimits?isEmailRequired=true&origin=AI_EDITOR&resourceType=AGENTIC_REQUEST",
        host
    );

    let client = create_client(account_id).await;
    let mut last_error: Option<AppError> = None;

    for attempt in 1..=MAX_RETRIES {
        let invocation_id = uuid::Uuid::new_v4().to_string();

        let result = client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header("x-amz-user-agent", format!("aws-sdk-js/1.0.0 KiroIDE-0.7.45-{}", fingerprint))
            .header(
                reqwest::header::USER_AGENT,
                format!(
                    "aws-sdk-js/1.0.0 ua/2.1 os/linux lang/js api/codewhispererruntime#1.0.0 m/E KiroIDE-0.7.45-{}",
                    fingerprint
                ),
            )
            .header("host", &host)
            .header("amz-sdk-invocation-id", &invocation_id)
            .header("amz-sdk-request", "attempt=1; max=1")
            .send()
            .await;

        match result {
            Ok(response) => {
                if let Err(_) = response.error_for_status_ref() {
                    let status = response.status();

                    if status == reqwest::StatusCode::FORBIDDEN {
                        crate::modules::logger::log_warn(
                            "Account unauthorized (403 Forbidden), marking as forbidden"
                        );
                        let mut q = QuotaData::new();
                        q.is_forbidden = true;
                        return Ok((q, None));
                    }

                    if attempt < MAX_RETRIES {
                        let text = response.text().await.unwrap_or_default();
                        crate::modules::logger::log_warn(&format!(
                            "API Error: {} - {} (Attempt {}/{})", status, text, attempt, MAX_RETRIES
                        ));
                        last_error = Some(AppError::Unknown(format!("HTTP {} - {}", status, text)));
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    } else {
                        let text = response.text().await.unwrap_or_default();
                        return Err(AppError::Unknown(format!("API Error: {} - {}", status, text)));
                    }
                }

                let usage_limits: KiroUsageLimits = response
                    .json()
                    .await
                    .map_err(AppError::Network)?;

                let mut quota_data = QuotaData::new();

                tracing::debug!(
                    "Kiro getUsageLimits returned {} breakdowns for {}",
                    usage_limits.usage_breakdown_list.len(),
                    email
                );

                for breakdown in &usage_limits.usage_breakdown_list {
                    let total = breakdown.usage_limit;
                    let used = breakdown.current_usage;
                    let available = if total > 0.0 { total - used } else { 0.0 };
                    let percentage = if total > 0.0 {
                        ((available / total) * 100.0) as i32
                    } else {
                        0
                    };

                    let reset_time = epoch_millis_to_rfc3339(breakdown.next_date_reset);

                    let name = if !breakdown.display_name.is_empty() {
                        format!("kiro-{}", breakdown.display_name.to_lowercase().replace(' ', "-"))
                    } else if !breakdown.resource_type.is_empty() {
                        format!("kiro-{}", breakdown.resource_type.to_lowercase().replace('_', "-"))
                    } else {
                        "kiro-credits".to_string()
                    };

                    quota_data.add_model_with_usage(name, percentage, reset_time, total, used);
                }

                if quota_data.models.is_empty() {
                    let reset_time = epoch_millis_to_rfc3339(usage_limits.next_date_reset);
                    quota_data.add_model("kiro-credits".to_string(), 0, reset_time);
                }

                if !usage_limits.subscription_info.subscription_type.is_empty() {
                    quota_data.subscription_tier = Some(usage_limits.subscription_info.subscription_type.clone());
                } else if !usage_limits.subscription_info.subscription_title.is_empty() {
                    quota_data.subscription_tier = Some(usage_limits.subscription_info.subscription_title.clone());
                }

                return Ok((quota_data, None));
            }
            Err(e) => {
                crate::modules::logger::log_warn(&format!(
                    "Request failed: {} (Attempt {}/{})", e, attempt, MAX_RETRIES
                ));
                last_error = Some(AppError::Network(e));
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| AppError::Unknown("Quota fetch failed".to_string())))
}

/// Internal fetch quota logic
#[allow(dead_code)]
pub async fn fetch_quota_inner(access_token: &str, email: &str) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    fetch_quota_with_cache(access_token, email, None, None).await
}

/// Batch fetch all account quotas (backup functionality)
#[allow(dead_code)]
pub async fn fetch_all_quotas(accounts: Vec<(String, String, String)>) -> Vec<(String, crate::error::AppResult<QuotaData>)> {
    let mut results = Vec::new();
    for (id, email, access_token) in accounts {
        let res = fetch_quota(&access_token, &email, Some(&id)).await;
        results.push((email, res.map(|(q, _)| q)));
    }
    results
}

/// Get a valid (refreshed if needed) access token for an account.
/// Returns (access_token, project_id_placeholder).
pub async fn get_valid_token_for_account(account: &crate::models::account::Account) -> Result<(String, String), String> {
    let mut account = account.clone();

    let new_token = crate::modules::oauth::ensure_fresh_token(&account.token, Some(&account.id)).await?;

    if new_token.access_token != account.token.access_token {
        account.token = new_token;
        if let Err(e) = crate::modules::account::save_account(&account) {
            crate::modules::logger::log_warn(&format!("Failed to save refreshed token: {}", e));
        } else {
            crate::modules::logger::log_info(&format!("Successfully refreshed and saved new token for {}", account.email));
        }
    }

    // Kiro doesn't need project_id, return empty string as placeholder
    Ok((account.token.access_token, String::new()))
}
