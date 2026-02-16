use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use regex::Regex;

/// Aggregated token statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatsAggregated {
    pub period: String, // e.g., "2024-01-15 14:00" for hourly, "2024-01-15" for daily
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub request_count: u64,
}

/// Per-account token statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountTokenStats {
    pub account_email: String,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub request_count: u64,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatsSummary {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub total_requests: u64,
    pub unique_accounts: u64,
}

/// Per-model token statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTokenStats {
    pub model: String,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub request_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTrendPoint {
    pub period: String,
    pub model_data: std::collections::HashMap<String, u64>,
}

/// Account trend data point (for stacked area chart)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountTrendPoint {
    pub period: String,
    pub account_data: std::collections::HashMap<String, u64>,
}

pub(crate) fn get_db_path() -> Result<PathBuf, String> {
    let data_dir = crate::modules::account::get_data_dir()?;
    Ok(data_dir.join("token_stats.db"))
}

fn connect_db() -> Result<Connection, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    // Enable WAL mode for better concurrency
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| e.to_string())?;
    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(|e| e.to_string())?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| e.to_string())?;

    Ok(conn)
}

pub fn normalize_model_for_stats(model: &str) -> String {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }

    let lower = trimmed.to_lowercase();
    if !lower.starts_with("claude") {
        return trimmed.to_string();
    }

    let re_standard_with_suffix =
        Regex::new(r"^(claude-(?:haiku|sonnet|opus)-\d+-\d{1,2})-(?:\d{8}|latest|\d+)$")
            .unwrap();
    if let Some(caps) = re_standard_with_suffix.captures(&lower) {
        return caps[1].to_string();
    }

    let re_standard_dot =
        Regex::new(r"^claude-(haiku|sonnet|opus)-(\d+)\.(\d{1,2})(?:-(?:\d{8}|latest|\d+))?$")
            .unwrap();
    if let Some(caps) = re_standard_dot.captures(&lower) {
        return format!("claude-{}-{}-{}", &caps[1], &caps[2], &caps[3]);
    }

    let re_no_minor_with_date =
        Regex::new(r"^(claude-(?:haiku|sonnet|opus)-\d+)-\d{8}$").unwrap();
    if let Some(caps) = re_no_minor_with_date.captures(&lower) {
        return caps[1].to_string();
    }

    let re_legacy_with_suffix =
        Regex::new(r"^(claude-\d+-\d+-(?:haiku|sonnet|opus))-(?:\d{8}|latest|\d+)$")
            .unwrap();
    if let Some(caps) = re_legacy_with_suffix.captures(&lower) {
        return caps[1].to_string();
    }

    let re_dot_with_date =
        Regex::new(r"^(claude-(?:\d+\.\d+-)?(?:haiku|sonnet|opus)(?:-\d+\.\d+)?)-\d{8}$")
            .unwrap();
    if let Some(caps) = re_dot_with_date.captures(&lower) {
        let base = caps[1].to_string();
        let re_family_dot =
            Regex::new(r"^claude-(haiku|sonnet|opus)-(\d+)\.(\d{1,2})$").unwrap();
        if let Some(m) = re_family_dot.captures(&base) {
            return format!("claude-{}-{}-{}", &m[1], &m[2], &m[3]);
        }
        let re_legacy_dot = Regex::new(r"^claude-(\d+)\.(\d+)-(haiku|sonnet|opus)$").unwrap();
        if let Some(m) = re_legacy_dot.captures(&base) {
            return format!("claude-{}-{}-{}", &m[1], &m[2], &m[3]);
        }
        return base;
    }

    let re_family_dot =
        Regex::new(r"^claude-(haiku|sonnet|opus)-(\d+)\.(\d{1,2})$").unwrap();
    if let Some(caps) = re_family_dot.captures(&lower) {
        return format!("claude-{}-{}-{}", &caps[1], &caps[2], &caps[3]);
    }

    let re_legacy_dot = Regex::new(r"^claude-(\d+)\.(\d+)-(haiku|sonnet|opus)$").unwrap();
    if let Some(caps) = re_legacy_dot.captures(&lower) {
        return format!("claude-{}-{}-{}", &caps[1], &caps[2], &caps[3]);
    }

    lower
}

fn normalize_existing_models(conn: &Connection) -> Result<(), String> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT model FROM token_usage")
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?;

    let mut distinct_models = Vec::new();
    for row in rows {
        distinct_models.push(row.map_err(|e| e.to_string())?);
    }

    for original in distinct_models {
        let normalized = normalize_model_for_stats(&original);
        if normalized != original {
            conn.execute(
                "UPDATE token_usage SET model = ?1 WHERE model = ?2",
                params![normalized, original],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

fn repair_mapped_models_from_proxy_logs(conn: &Connection) -> Result<usize, String> {
    let proxy_db_path = match crate::modules::proxy_db::get_proxy_db_path() {
        Ok(path) => path,
        Err(_) => return Ok(0),
    };

    if !proxy_db_path.exists() {
        return Ok(0);
    }

    let proxy_conn = match Connection::open(proxy_db_path) {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };

    let mut stmt = match proxy_conn.prepare(
        "SELECT timestamp, account_email, model, mapped_model,
                COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
                COALESCE(cache_creation_input_tokens, 0), COALESCE(cache_read_input_tokens, 0)
         FROM request_logs
         WHERE account_email IS NOT NULL
           AND model IS NOT NULL
           AND mapped_model IS NOT NULL
           AND mapped_model <> ''
           AND status >= 200 AND status < 400
           AND (COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0) + COALESCE(cache_creation_input_tokens, 0) + COALESCE(cache_read_input_tokens, 0)) > 0
         ORDER BY timestamp ASC",
    ) {
        Ok(s) => s,
        Err(_) => return Ok(0),
    };

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, u32>(4)?,
                row.get::<_, u32>(5)?,
                row.get::<_, u32>(6)?,
                row.get::<_, u32>(7)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    let mut updated_rows = 0usize;

    for row in rows {
        let (
            timestamp_ms,
            account_email,
            source_model_raw,
            mapped_model_raw,
            input_tokens,
            output_tokens,
            cache_creation_tokens,
            cache_read_tokens,
        ) = row.map_err(|e| e.to_string())?;

        let source_model = normalize_model_for_stats(&source_model_raw);
        let mapped_model = normalize_model_for_stats(&mapped_model_raw);

        if source_model == mapped_model {
            continue;
        }

        let timestamp_sec = timestamp_ms / 1000;

        let changed = conn
            .execute(
                "UPDATE token_usage
                 SET model = ?1
                 WHERE rowid IN (
                    SELECT rowid FROM token_usage
                    WHERE account_email = ?2
                      AND model = ?3
                      AND timestamp BETWEEN ?4 AND ?5
                      AND input_tokens = ?6
                      AND output_tokens = ?7
                      AND COALESCE(cache_creation_input_tokens, 0) = ?8
                      AND COALESCE(cache_read_input_tokens, 0) = ?9
                    LIMIT 1
                 )",
                params![
                    mapped_model,
                    account_email,
                    source_model,
                    timestamp_sec - 2,
                    timestamp_sec + 2,
                    input_tokens,
                    output_tokens,
                    cache_creation_tokens,
                    cache_read_tokens,
                ],
            )
            .map_err(|e| e.to_string())?;

        updated_rows += changed;
    }

    Ok(updated_rows)
}

/// Initialize the token stats database
pub fn init_db() -> Result<(), String> {
    let conn = connect_db()?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS token_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            account_email TEXT NOT NULL,
            model TEXT NOT NULL,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            cache_creation_input_tokens INTEGER DEFAULT 0,
            cache_read_input_tokens INTEGER DEFAULT 0
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    let _ = conn.execute(
        "ALTER TABLE token_usage ADD COLUMN cache_creation_input_tokens INTEGER DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE token_usage ADD COLUMN cache_read_input_tokens INTEGER DEFAULT 0",
        [],
    );

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_token_timestamp ON token_usage (timestamp DESC)",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_token_account ON token_usage (account_email)",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_token_model ON token_usage (model)",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS token_stats_hourly (
            hour_bucket TEXT NOT NULL,
            account_email TEXT NOT NULL,
            total_input_tokens INTEGER NOT NULL DEFAULT 0,
            total_output_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            cache_creation_input_tokens INTEGER DEFAULT 0,
            cache_read_input_tokens INTEGER DEFAULT 0,
            request_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (hour_bucket, account_email)
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    let _ = conn.execute(
        "ALTER TABLE token_stats_hourly ADD COLUMN cache_creation_input_tokens INTEGER DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE token_stats_hourly ADD COLUMN cache_read_input_tokens INTEGER DEFAULT 0",
        [],
    );

    normalize_existing_models(&conn)?;
    let _ = repair_mapped_models_from_proxy_logs(&conn)?;

    Ok(())
}

/// Record token usage from a request
pub fn record_usage(
    account_email: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_tokens: u32,
    cache_read_tokens: u32,
) -> Result<(), String> {
    let conn = connect_db()?;
    let timestamp = chrono::Utc::now().timestamp();
    let total_tokens = input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens;
    let normalized_model = normalize_model_for_stats(model);

    conn.execute(
        "INSERT INTO token_usage (timestamp, account_email, model, input_tokens, output_tokens, total_tokens, cache_creation_input_tokens, cache_read_input_tokens)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![timestamp, account_email, normalized_model, input_tokens, output_tokens, total_tokens, cache_creation_tokens, cache_read_tokens],
    ).map_err(|e| e.to_string())?;

    let hour_bucket = chrono::Utc::now().format("%Y-%m-%d %H:00").to_string();
    conn.execute(
        "INSERT INTO token_stats_hourly (hour_bucket, account_email, total_input_tokens, total_output_tokens, total_tokens, cache_creation_input_tokens, cache_read_input_tokens, request_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
         ON CONFLICT(hour_bucket, account_email) DO UPDATE SET
            total_input_tokens = total_input_tokens + ?3,
            total_output_tokens = total_output_tokens + ?4,
            total_tokens = total_tokens + ?5,
            cache_creation_input_tokens = cache_creation_input_tokens + ?6,
            cache_read_input_tokens = cache_read_input_tokens + ?7,
            request_count = request_count + 1",
        params![hour_bucket, account_email, input_tokens, output_tokens, total_tokens, cache_creation_tokens, cache_read_tokens],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

/// Get hourly aggregated stats for a time range
pub fn get_hourly_stats(hours: i64) -> Result<Vec<TokenStatsAggregated>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (hours * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour_bucket,
                SUM(input_tokens) as input, 
                SUM(output_tokens) as output,
                SUM(total_tokens) as total,
                COUNT(*) as count
         FROM token_usage 
         WHERE timestamp >= ?1
         GROUP BY hour_bucket
         ORDER BY hour_bucket ASC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok(TokenStatsAggregated {
                period: row.get(0)?,
                total_input_tokens: row.get(1)?,
                total_output_tokens: row.get(2)?,
                total_tokens: row.get(3)?,
                request_count: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| e.to_string())?);
    }
    Ok(result)
}

/// Get daily aggregated stats for a time range
pub fn get_daily_stats(days: i64) -> Result<Vec<TokenStatsAggregated>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (days * 24 * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch')) as day_bucket,
                SUM(input_tokens) as input, 
                SUM(output_tokens) as output,
                SUM(total_tokens) as total,
                COUNT(*) as count
         FROM token_usage 
         WHERE timestamp >= ?1
         GROUP BY day_bucket
         ORDER BY day_bucket ASC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok(TokenStatsAggregated {
                period: row.get(0)?,
                total_input_tokens: row.get(1)?,
                total_output_tokens: row.get(2)?,
                total_tokens: row.get(3)?,
                request_count: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| e.to_string())?);
    }
    Ok(result)
}

/// Get weekly aggregated stats
pub fn get_weekly_stats(weeks: i64) -> Result<Vec<TokenStatsAggregated>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now() - chrono::Duration::weeks(weeks);
    let cutoff_timestamp = cutoff.timestamp();

    let mut stmt = conn
        .prepare(
            "SELECT strftime('%Y-W%W', datetime(timestamp, 'unixepoch')) as week_bucket,
                SUM(input_tokens) as input, 
                SUM(output_tokens) as output,
                SUM(total_tokens) as total,
                COUNT(*) as count
         FROM token_usage 
         WHERE timestamp >= ?1
         GROUP BY week_bucket
         ORDER BY week_bucket ASC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([cutoff_timestamp], |row| {
            Ok(TokenStatsAggregated {
                period: row.get(0)?,
                total_input_tokens: row.get(1)?,
                total_output_tokens: row.get(2)?,
                total_tokens: row.get(3)?,
                request_count: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| e.to_string())?);
    }
    Ok(result)
}

/// Get per-account statistics for a time range
pub fn get_account_stats(hours: i64) -> Result<Vec<AccountTokenStats>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (hours * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT account_email,
                SUM(input_tokens) as input, 
                SUM(output_tokens) as output,
                SUM(total_tokens) as total,
                COUNT(*) as count
         FROM token_usage 
         WHERE timestamp >= ?1
         GROUP BY account_email
         ORDER BY total DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok(AccountTokenStats {
                account_email: row.get(0)?,
                total_input_tokens: row.get(1)?,
                total_output_tokens: row.get(2)?,
                total_tokens: row.get(3)?,
                request_count: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| e.to_string())?);
    }
    Ok(result)
}

/// Get summary statistics for a time range
pub fn get_summary_stats(hours: i64) -> Result<TokenStatsSummary, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (hours * 3600);

    let (total_input, total_output, total, requests): (u64, u64, u64, u64) = conn
        .query_row(
            "SELECT COALESCE(SUM(input_tokens), 0),
                COALESCE(SUM(output_tokens), 0),
                COALESCE(SUM(total_tokens), 0),
                COUNT(*)
         FROM token_usage 
         WHERE timestamp >= ?1",
            [cutoff],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|e| e.to_string())?;

    let unique_accounts: u64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT account_email) FROM token_usage WHERE timestamp >= ?1",
            [cutoff],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;

    Ok(TokenStatsSummary {
        total_input_tokens: total_input,
        total_output_tokens: total_output,
        total_tokens: total,
        total_requests: requests,
        unique_accounts,
    })
}

pub fn get_model_stats(hours: i64) -> Result<Vec<ModelTokenStats>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (hours * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT model,
                SUM(input_tokens) as input,
                SUM(output_tokens) as output,
                SUM(total_tokens) as total,
                COUNT(*) as count
         FROM token_usage
         WHERE timestamp >= ?1
         GROUP BY model
         ORDER BY total DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok(ModelTokenStats {
                model: row.get(0)?,
                total_input_tokens: row.get(1)?,
                total_output_tokens: row.get(2)?,
                total_tokens: row.get(3)?,
                request_count: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| e.to_string())?);
    }
    Ok(result)
}

pub fn get_model_trend_hourly(hours: i64) -> Result<Vec<ModelTrendPoint>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (hours * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour_bucket,
                model,
                SUM(total_tokens) as total
         FROM token_usage
         WHERE timestamp >= ?1
         GROUP BY hour_bucket, model
         ORDER BY hour_bucket ASC",
        )
        .map_err(|e| e.to_string())?;

    let mut trend_map: std::collections::BTreeMap<String, std::collections::HashMap<String, u64>> =
        std::collections::BTreeMap::new();

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for row in rows {
        let (period, model, total) = row.map_err(|e| e.to_string())?;
        trend_map.entry(period).or_default().insert(model, total);
    }

    Ok(trend_map
        .into_iter()
        .map(|(period, model_data)| ModelTrendPoint { period, model_data })
        .collect())
}

pub fn get_model_trend_daily(days: i64) -> Result<Vec<ModelTrendPoint>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (days * 24 * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch')) as day_bucket,
                model,
                SUM(total_tokens) as total
         FROM token_usage
         WHERE timestamp >= ?1
         GROUP BY day_bucket, model
         ORDER BY day_bucket ASC",
        )
        .map_err(|e| e.to_string())?;

    let mut trend_map: std::collections::BTreeMap<String, std::collections::HashMap<String, u64>> =
        std::collections::BTreeMap::new();

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for row in rows {
        let (period, model, total) = row.map_err(|e| e.to_string())?;
        trend_map.entry(period).or_default().insert(model, total);
    }

    Ok(trend_map
        .into_iter()
        .map(|(period, model_data)| ModelTrendPoint { period, model_data })
        .collect())
}

pub fn get_account_trend_hourly(hours: i64) -> Result<Vec<AccountTrendPoint>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (hours * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour_bucket,
                account_email,
                SUM(total_tokens) as total
         FROM token_usage
         WHERE timestamp >= ?1
         GROUP BY hour_bucket, account_email
         ORDER BY hour_bucket ASC",
        )
        .map_err(|e| e.to_string())?;

    let mut trend_map: std::collections::BTreeMap<String, std::collections::HashMap<String, u64>> =
        std::collections::BTreeMap::new();

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for row in rows {
        let (period, account, total) = row.map_err(|e| e.to_string())?;
        trend_map.entry(period).or_default().insert(account, total);
    }

    Ok(trend_map
        .into_iter()
        .map(|(period, account_data)| AccountTrendPoint {
            period,
            account_data,
        })
        .collect())
}

pub fn get_account_trend_daily(days: i64) -> Result<Vec<AccountTrendPoint>, String> {
    let conn = connect_db()?;
    let cutoff = chrono::Utc::now().timestamp() - (days * 24 * 3600);

    let mut stmt = conn
        .prepare(
            "SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch')) as day_bucket,
                account_email,
                SUM(total_tokens) as total
         FROM token_usage
         WHERE timestamp >= ?1
         GROUP BY day_bucket, account_email
         ORDER BY day_bucket ASC",
        )
        .map_err(|e| e.to_string())?;

    let mut trend_map: std::collections::BTreeMap<String, std::collections::HashMap<String, u64>> =
        std::collections::BTreeMap::new();

    let rows = stmt
        .query_map([cutoff], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for row in rows {
        let (period, account, total) = row.map_err(|e| e.to_string())?;
        trend_map.entry(period).or_default().insert(account, total);
    }

    Ok(trend_map
        .into_iter()
        .map(|(period, account_data)| AccountTrendPoint {
            period,
            account_data,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_query() {
        // This would need a test database setup
        // For now, just verify the module compiles
        assert!(true);
    }
}
