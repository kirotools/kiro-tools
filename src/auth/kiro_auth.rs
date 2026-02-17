use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use rusqlite::Connection;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use super::config::{
    get_aws_sso_oidc_url, get_kiro_api_host, get_kiro_q_host, get_kiro_refresh_url,
    get_machine_fingerprint, SQLITE_REGISTRATION_KEYS, SQLITE_TOKEN_KEYS,
    TOKEN_REFRESH_THRESHOLD,
};
use super::types::{
    AuthError, AuthType, AwsSsoOidcRefreshResponse, DeviceRegistration,
    EnterpriseDeviceRegistration, FileCredentials, KiroDesktopRefreshResponse, SqliteTokenData,
};

struct Inner {
    refresh_token: Option<String>,
    access_token: Option<String>,
    profile_arn: Option<String>,
    region: String,
    creds_file: Option<String>,
    sqlite_db: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Option<Vec<String>>,
    sso_region: Option<String>,
    client_id_hash: Option<String>,
    sqlite_token_key: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    auth_type: AuthType,
    refresh_url: String,
    api_host: String,
    q_host: String,
    fingerprint: String,
    http_client: Client,
}

pub struct KiroAuthManager {
    inner: Mutex<Inner>,
}

impl Inner {
    fn detect_auth_type(&mut self) {
        if self.client_id.is_some() && self.client_secret.is_some() {
            self.auth_type = AuthType::AwsSsoOidc;
            info!("Detected auth type: AWS SSO OIDC (kiro-cli)");
        } else {
            self.auth_type = AuthType::KiroDesktop;
            info!("Detected auth type: Kiro Desktop");
        }
    }

    fn load_credentials_from_sqlite(&mut self, db_path: &str) {
        let path = match shellexpand_path(db_path) {
            Some(p) => p,
            None => { warn!("SQLite database path expansion failed: {}", db_path); return; }
        };
        if !path.exists() { warn!("SQLite database not found: {}", db_path); return; }

        let conn = match Connection::open(&path) {
            Ok(c) => c,
            Err(e) => { error!("SQLite error opening database: {}", e); return; }
        };

        for key in SQLITE_TOKEN_KEYS {
            match conn.query_row("SELECT value FROM auth_kv WHERE key = ?1", [key], |row| row.get::<_, String>(0)) {
                Ok(value) => {
                    self.sqlite_token_key = Some(key.to_string());
                    debug!("Loaded credentials from SQLite key: {}", key);
                    match serde_json::from_str::<SqliteTokenData>(&value) {
                        Ok(data) => {
                            if data.access_token.is_some() { self.access_token = data.access_token; }
                            if data.refresh_token.is_some() { self.refresh_token = data.refresh_token; }
                            if data.profile_arn.is_some() { self.profile_arn = data.profile_arn; }
                            if let Some(ref region) = data.region {
                                self.sso_region = Some(region.clone());
                                debug!("SSO region from SQLite: {} (API stays at {})", region, self.region);
                            }
                            if data.scopes.is_some() { self.scopes = data.scopes; }
                            if let Some(ref expires_str) = data.expires_at {
                                match parse_expires_at(expires_str) {
                                    Ok(dt) => self.expires_at = Some(dt),
                                    Err(e) => warn!("Failed to parse expires_at from SQLite: {}", e),
                                }
                            }
                        }
                        Err(e) => error!("JSON decode error in SQLite data: {}", e),
                    }
                    break;
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                Err(e) => { error!("SQLite error querying key {}: {}", key, e); continue; }
            }
        }

        for key in SQLITE_REGISTRATION_KEYS {
            match conn.query_row("SELECT value FROM auth_kv WHERE key = ?1", [key], |row| row.get::<_, String>(0)) {
                Ok(value) => {
                    debug!("Loaded device registration from SQLite key: {}", key);
                    match serde_json::from_str::<DeviceRegistration>(&value) {
                        Ok(reg) => {
                            if reg.client_id.is_some() { self.client_id = reg.client_id; }
                            if reg.client_secret.is_some() { self.client_secret = reg.client_secret; }
                            if reg.region.is_some() && self.sso_region.is_none() {
                                self.sso_region = reg.region;
                                debug!("SSO region from device-registration: {:?}", self.sso_region);
                            }
                        }
                        Err(e) => error!("JSON decode error in device registration: {}", e),
                    }
                    break;
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                Err(e) => { error!("SQLite error querying registration key {}: {}", key, e); continue; }
            }
        }
        info!("Credentials loaded from SQLite database: {}", db_path);
    }

    fn load_credentials_from_file(&mut self, file_path: &str) {
        let path = match shellexpand_path(file_path) {
            Some(p) => p,
            None => { warn!("Credentials file path expansion failed: {}", file_path); return; }
        };
        if !path.exists() { warn!("Credentials file not found: {}", file_path); return; }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => { error!("Error reading credentials file: {}", e); return; }
        };
        
        let data: FileCredentials = match serde_json::from_str::<FileCredentials>(&content) {
            Ok(d) => d,
            Err(_) => {
                match serde_json::from_str::<Vec<FileCredentials>>(&content) {
                    Ok(mut arr) if !arr.is_empty() => {
                        debug!("Credentials file is array format, using first element");
                        arr.remove(0)
                    }
                    Ok(_) => {
                        error!("Credentials file is empty array");
                        return;
                    }
                    Err(e) => {
                        error!("Error parsing credentials file: {}", e);
                        return;
                    }
                }
            }
        };

        if data.refresh_token.is_some() { self.refresh_token = data.refresh_token; }
        if data.access_token.is_some() { self.access_token = data.access_token; }
        if data.profile_arn.is_some() { self.profile_arn = data.profile_arn; }
        if let Some(ref region) = data.region {
            self.region = region.clone();
            self.refresh_url = get_kiro_refresh_url(&self.region);
            self.api_host = get_kiro_api_host(&self.region);
            self.q_host = get_kiro_q_host(&self.region);
            info!("Region updated from credentials file: region={}, api_host={}, q_host={}", self.region, self.api_host, self.q_host);
        }

        if let Some(ref hash) = data.client_id_hash {
            self.client_id_hash = Some(hash.clone());
            self.load_enterprise_device_registration(hash);
        }
        if data.client_id.is_some() { self.client_id = data.client_id; }
        if data.client_secret.is_some() { self.client_secret = data.client_secret; }

        if let Some(ref expires_str) = data.expires_at {
            match parse_expires_at(expires_str) {
                Ok(dt) => self.expires_at = Some(dt),
                Err(e) => warn!("Failed to parse expiresAt: {}", e),
            }
        }
        info!("Credentials loaded from {}", file_path);
    }

    fn load_enterprise_device_registration(&mut self, client_id_hash: &str) {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => { warn!("Could not determine home directory for enterprise device registration"); return; }
        };
        let device_reg_path = home.join(".aws").join("sso").join("cache").join(format!("{}.json", client_id_hash));
        if !device_reg_path.exists() {
            warn!("Enterprise device registration file not found: {}", device_reg_path.display());
            return;
        }
        let content = match std::fs::read_to_string(&device_reg_path) {
            Ok(c) => c,
            Err(e) => { error!("Error reading enterprise device registration: {}", e); return; }
        };
        match serde_json::from_str::<EnterpriseDeviceRegistration>(&content) {
            Ok(reg) => {
                if reg.client_id.is_some() { self.client_id = reg.client_id; }
                if reg.client_secret.is_some() { self.client_secret = reg.client_secret; }
                info!("Enterprise device registration loaded from {}", device_reg_path.display());
            }
            Err(e) => error!("Error parsing enterprise device registration: {}", e),
        }
    }

    fn save_credentials_to_file(&self) {
        let file_path = match self.creds_file {
            Some(ref f) => f,
            None => return,
        };
        let path = match shellexpand_path(file_path) {
            Some(p) => p,
            None => return,
        };

        let mut existing_data: Value = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => serde_json::from_str(&content).unwrap_or(Value::Object(Default::default())),
                Err(_) => Value::Object(Default::default()),
            }
        } else {
            Value::Object(Default::default())
        };

        if let Value::Object(ref mut map) = existing_data {
            if let Some(ref token) = self.access_token {
                map.insert("accessToken".to_string(), Value::String(token.clone()));
            }
            if let Some(ref token) = self.refresh_token {
                map.insert("refreshToken".to_string(), Value::String(token.clone()));
            }
            if let Some(ref dt) = self.expires_at {
                map.insert("expiresAt".to_string(), Value::String(dt.to_rfc3339()));
            }
            if let Some(ref arn) = self.profile_arn {
                map.insert("profileArn".to_string(), Value::String(arn.clone()));
            }
        }

        match serde_json::to_string_pretty(&existing_data) {
            Ok(json_str) => match std::fs::write(&path, json_str) {
                Ok(_) => debug!("Credentials saved to {}", file_path),
                Err(e) => error!("Error writing credentials file: {}", e),
            },
            Err(e) => error!("Error serializing credentials: {}", e),
        }
    }

    fn save_credentials_to_sqlite(&self) {
        let db_path = match self.sqlite_db {
            Some(ref d) => d,
            None => return,
        };
        let path = match shellexpand_path(db_path) {
            Some(p) => p,
            None => return,
        };
        if !path.exists() { warn!("SQLite database not found for writing: {}", db_path); return; }

        let conn = match Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
            Ok(c) => c,
            Err(e) => { error!("SQLite error opening database for writing: {}", e); return; }
        };

        let mut token_data = serde_json::Map::new();
        if let Some(ref at) = self.access_token {
            token_data.insert("access_token".to_string(), Value::String(at.clone()));
        }
        if let Some(ref rt) = self.refresh_token {
            token_data.insert("refresh_token".to_string(), Value::String(rt.clone()));
        }
        if let Some(ref dt) = self.expires_at {
            token_data.insert("expires_at".to_string(), Value::String(dt.to_rfc3339()));
        }
        let region = self.sso_region.as_deref().unwrap_or(&self.region);
        token_data.insert("region".to_string(), Value::String(region.to_string()));
        if let Some(ref scopes) = self.scopes {
            let scopes_val: Vec<Value> = scopes.iter().map(|s| Value::String(s.clone())).collect();
            token_data.insert("scopes".to_string(), Value::Array(scopes_val));
        }

        let token_json = match serde_json::to_string(&Value::Object(token_data)) {
            Ok(j) => j,
            Err(e) => { error!("Error serializing token data for SQLite: {}", e); return; }
        };

        if let Some(ref key) = self.sqlite_token_key {
            match conn.execute("UPDATE auth_kv SET value = ?1 WHERE key = ?2", rusqlite::params![token_json, key]) {
                Ok(count) if count > 0 => { debug!("Credentials saved to SQLite key: {}", key); return; }
                Ok(_) => warn!("Failed to update SQLite key: {}, trying fallback", key),
                Err(e) => warn!("SQLite error updating key {}: {}", key, e),
            }
        }

        for key in SQLITE_TOKEN_KEYS {
            match conn.execute("UPDATE auth_kv SET value = ?1 WHERE key = ?2", rusqlite::params![token_json, key]) {
                Ok(count) if count > 0 => { debug!("Credentials saved to SQLite key: {} (fallback)", key); return; }
                Ok(_) => continue,
                Err(e) => { error!("SQLite error updating fallback key {}: {}", key, e); continue; }
            }
        }
        warn!("Failed to save credentials to SQLite: no matching keys found");
    }

    fn is_token_expiring_soon(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(expires) => expires <= Utc::now() + Duration::seconds(TOKEN_REFRESH_THRESHOLD),
        }
    }

    fn is_token_expired(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(expires) => Utc::now() >= expires,
        }
    }

    async fn refresh_token_request(&mut self) -> Result<(), AuthError> {
        match self.auth_type {
            AuthType::AwsSsoOidc => self.refresh_token_aws_sso_oidc().await,
            AuthType::KiroDesktop => self.refresh_token_kiro_desktop().await,
        }
    }

    async fn refresh_token_kiro_desktop(&mut self) -> Result<(), AuthError> {
        let refresh_token = self.refresh_token.as_ref().ok_or(AuthError::MissingRefreshToken)?.clone();
        info!("Refreshing Kiro token via Kiro Desktop Auth...");

        let payload = serde_json::json!({ "refreshToken": refresh_token });
        let user_agent = format!("KiroIDE-0.7.45-{}", self.fingerprint);

        let response = self.http_client
            .post(&self.refresh_url)
            .header("Content-Type", "application/json")
            .header("User-Agent", &user_agent)
            .json(&payload)
            .send().await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(AuthError::HttpStatus { status: status.as_u16(), body });
        }

        let data: KiroDesktopRefreshResponse = response.json().await?;
        let new_access_token = data.access_token.ok_or(AuthError::MissingAccessToken)?;
        let expires_in = data.expires_in.unwrap_or(3600);

        self.access_token = Some(new_access_token);
        if let Some(rt) = data.refresh_token { self.refresh_token = Some(rt); }
        if let Some(arn) = data.profile_arn { self.profile_arn = Some(arn); }
        self.expires_at = Some(Utc::now() + Duration::seconds(expires_in - 60));

        info!("Token refreshed via Kiro Desktop Auth, expires: {}", self.expires_at.map(|d| d.to_rfc3339()).unwrap_or_default());

        if self.sqlite_db.is_some() { self.save_credentials_to_sqlite(); }
        else { self.save_credentials_to_file(); }
        Ok(())
    }

    async fn refresh_token_aws_sso_oidc(&mut self) -> Result<(), AuthError> {
        match self.do_aws_sso_oidc_refresh().await {
            Ok(()) => Ok(()),
            Err(AuthError::HttpStatus { status: 400, body }) => {
                if self.sqlite_db.is_some() {
                    warn!("Token refresh failed with 400, reloading credentials from SQLite and retrying...");
                    if let Some(ref db_path) = self.sqlite_db.clone() {
                        self.load_credentials_from_sqlite(db_path);
                    }
                    self.do_aws_sso_oidc_refresh().await
                } else {
                    Err(AuthError::HttpStatus { status: 400, body })
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn do_aws_sso_oidc_refresh(&mut self) -> Result<(), AuthError> {
        let refresh_token = self.refresh_token.as_ref().ok_or(AuthError::MissingRefreshToken)?.clone();
        let client_id = self.client_id.as_ref().ok_or(AuthError::MissingClientId)?.clone();
        let client_secret = self.client_secret.as_ref().ok_or(AuthError::MissingClientSecret)?.clone();

        info!("Refreshing Kiro token via AWS SSO OIDC...");
        let sso_region = self.sso_region.as_deref().unwrap_or(&self.region);
        let url = get_aws_sso_oidc_url(sso_region);

        let payload = serde_json::json!({
            "grantType": "refresh_token",
            "clientId": client_id,
            "clientSecret": client_secret,
            "refreshToken": refresh_token,
        });

        debug!("AWS SSO OIDC refresh request: url={}, sso_region={}, api_region={}, client_id={}...",
            url, sso_region, self.region, &client_id[..client_id.len().min(8)]);

        let response = self.http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!("AWS SSO OIDC refresh failed: status={}, body={}", status.as_u16(), body);
            return Err(AuthError::HttpStatus { status: status.as_u16(), body });
        }

        let result: AwsSsoOidcRefreshResponse = response.json().await?;
        let new_access_token = result.access_token.ok_or(AuthError::MissingAccessToken)?;
        let expires_in = result.expires_in.unwrap_or(3600);

        self.access_token = Some(new_access_token);
        if let Some(rt) = result.refresh_token { self.refresh_token = Some(rt); }
        self.expires_at = Some(Utc::now() + Duration::seconds(expires_in - 60));

        info!("Token refreshed via AWS SSO OIDC, expires: {}", self.expires_at.map(|d| d.to_rfc3339()).unwrap_or_default());

        if self.sqlite_db.is_some() { self.save_credentials_to_sqlite(); }
        else { self.save_credentials_to_file(); }
        Ok(())
    }
}

impl KiroAuthManager {
    pub fn new(
        refresh_token: Option<String>,
        profile_arn: Option<String>,
        region: Option<String>,
        creds_file: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        sqlite_db: Option<String>,
    ) -> Self {
        let region = region.unwrap_or_else(|| "us-east-1".to_string());
        let refresh_url = get_kiro_refresh_url(&region);
        let api_host = get_kiro_api_host(&region);
        let q_host = get_kiro_q_host(&region);
        let fingerprint = get_machine_fingerprint();

        info!("Auth manager initialized: region={}, api_host={}, q_host={}", region, api_host, q_host);

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        let mut inner = Inner {
            refresh_token, access_token: None, profile_arn, region,
            creds_file: creds_file.clone(), sqlite_db: sqlite_db.clone(),
            client_id, client_secret, scopes: None, sso_region: None,
            client_id_hash: None, sqlite_token_key: None, expires_at: None,
            auth_type: AuthType::KiroDesktop, refresh_url, api_host, q_host,
            fingerprint, http_client,
        };

        if let Some(ref db_path) = sqlite_db {
            inner.load_credentials_from_sqlite(db_path);
        } else if let Some(ref file_path) = creds_file {
            inner.load_credentials_from_file(file_path);
        }
        inner.detect_auth_type();

        Self { inner: Mutex::new(inner) }
    }

    pub async fn get_access_token(&self) -> Result<String, AuthError> {
        let mut inner = self.inner.lock().await;

        if inner.access_token.is_some() && !inner.is_token_expiring_soon() {
            return Ok(inner.access_token.clone().unwrap());
        }

        // SQLite mode: reload from DB before refresh (kiro-cli may have updated)
        if inner.sqlite_db.is_some() && inner.is_token_expiring_soon() {
            debug!("SQLite mode: reloading credentials before refresh attempt");
            if let Some(ref db_path) = inner.sqlite_db.clone() {
                inner.load_credentials_from_sqlite(db_path);
            }
            if inner.access_token.is_some() && !inner.is_token_expiring_soon() {
                debug!("SQLite reload provided fresh token, no refresh needed");
                return Ok(inner.access_token.clone().unwrap());
            }
        }

        // Creds file mode: reload from file before refresh (Kiro IDE may have updated)
        if inner.creds_file.is_some() && inner.sqlite_db.is_none() && inner.is_token_expiring_soon() {
            debug!("Creds file mode: reloading credentials before refresh attempt");
            if let Some(ref file_path) = inner.creds_file.clone() {
                inner.load_credentials_from_file(file_path);
            }
            if inner.access_token.is_some() && !inner.is_token_expiring_soon() {
                debug!("Creds file reload provided fresh token, no refresh needed");
                return Ok(inner.access_token.clone().unwrap());
            }
        }

        match inner.refresh_token_request().await {
            Ok(()) => {}
            Err(AuthError::HttpStatus { status: 400, body: _ }) if inner.sqlite_db.is_some() => {
                warn!("Token refresh failed with 400 after SQLite reload. \
                       This may happen if kiro-cli refreshed tokens in memory without persisting.");
                if inner.access_token.is_some() && !inner.is_token_expired() {
                    warn!("Using existing access_token until it expires. \
                           Run 'kiro-cli login' when convenient to refresh credentials.");
                    return Ok(inner.access_token.clone().unwrap());
                } else {
                    return Err(AuthError::TokenExpiredRefreshFailed);
                }
            }
            Err(AuthError::HttpStatus { status: 401, .. }) if inner.creds_file.is_some() => {
                warn!("Token refresh failed with 401, reloading from creds file and retrying...");
                if let Some(ref file_path) = inner.creds_file.clone() {
                    inner.load_credentials_from_file(file_path);
                }
                if inner.refresh_token.is_some() {
                    inner.refresh_token_request().await?;
                } else {
                    return Err(AuthError::TokenExpiredRefreshFailed);
                }
            }
            Err(e) => {
                if inner.access_token.is_some() && !inner.is_token_expired() {
                    warn!("Token refresh failed, using existing access_token until it expires");
                    return Ok(inner.access_token.clone().unwrap());
                }
                return Err(e);
            }
        }

        inner.access_token.clone().ok_or(AuthError::TokenUnavailable)
    }

    pub async fn force_refresh(&self) -> Result<String, AuthError> {
        let mut inner = self.inner.lock().await;
        inner.refresh_token_request().await?;
        inner.access_token.clone().ok_or(AuthError::TokenUnavailable)
    }

    pub fn profile_arn_sync(&self) -> Option<String> {
        // For sync contexts only — tries to lock without blocking.
        // Callers in async context should use the async version.
        self.inner.try_lock().ok().and_then(|g| g.profile_arn.clone())
    }

    pub async fn profile_arn(&self) -> Option<String> {
        self.inner.lock().await.profile_arn.clone()
    }

    pub async fn region(&self) -> String {
        self.inner.lock().await.region.clone()
    }

    pub async fn api_host(&self) -> String {
        self.inner.lock().await.api_host.clone()
    }

    pub async fn q_host(&self) -> String {
        self.inner.lock().await.q_host.clone()
    }

    pub async fn fingerprint(&self) -> String {
        self.inner.lock().await.fingerprint.clone()
    }

    pub async fn auth_type(&self) -> AuthType {
        self.inner.lock().await.auth_type
    }

    /// Synchronous auth_type accessor for non-async contexts.
    pub fn auth_type_sync(&self) -> Option<AuthType> {
        self.inner.try_lock().ok().map(|g| g.auth_type)
    }

    pub async fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.inner.lock().await.expires_at
    }

    pub async fn current_refresh_token(&self) -> Option<String> {
        self.inner.lock().await.refresh_token.clone()
    }
}

fn shellexpand_path(path: &str) -> Option<PathBuf> {
    if path.starts_with('~') {
        dirs::home_dir().map(|home| home.join(path.trim_start_matches("~/")))
    } else {
        Some(PathBuf::from(path))
    }
}

fn parse_expires_at(s: &str) -> Result<DateTime<Utc>, AuthError> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(dt.and_utc());
    }
    Err(AuthError::DateParse(format!("Cannot parse date: {}", s)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;
    use std::io::Write;

    fn write_temp_json(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn create_test_sqlite(token_key: &str, token_json: &str, reg_key: Option<&str>, reg_json: Option<&str>) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)", []).unwrap();
        conn.execute("INSERT INTO auth_kv (key, value) VALUES (?1, ?2)", rusqlite::params![token_key, token_json]).unwrap();
        if let (Some(rk), Some(rj)) = (reg_key, reg_json) {
            conn.execute("INSERT INTO auth_kv (key, value) VALUES (?1, ?2)", rusqlite::params![rk, rj]).unwrap();
        }
        f
    }

    fn make_inner(rt: Option<&str>, cid: Option<&str>, cs: Option<&str>) -> Inner {
        Inner {
            refresh_token: rt.map(String::from),
            access_token: None,
            profile_arn: None,
            region: "us-east-1".into(),
            creds_file: None,
            sqlite_db: None,
            client_id: cid.map(String::from),
            client_secret: cs.map(String::from),
            scopes: None,
            sso_region: None,
            client_id_hash: None,
            sqlite_token_key: None,
            expires_at: None,
            auth_type: AuthType::KiroDesktop,
            refresh_url: get_kiro_refresh_url("us-east-1"),
            api_host: get_kiro_api_host("us-east-1"),
            q_host: get_kiro_q_host("us-east-1"),
            fingerprint: get_machine_fingerprint(),
            http_client: Client::new(),
        }
    }

    // --- Construction ---

    #[tokio::test]
    async fn test_new_default_region() {
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, None);
        assert_eq!(mgr.region().await, "us-east-1");
        assert_eq!(mgr.auth_type().await, AuthType::KiroDesktop);
        assert!(mgr.profile_arn().await.is_none());
    }

    #[tokio::test]
    async fn test_new_with_params() {
        let mgr = KiroAuthManager::new(
            Some("rt_123".into()), Some("arn:aws:test".into()),
            Some("eu-west-1".into()), None, None, None, None,
        );
        assert_eq!(mgr.region().await, "eu-west-1");
        assert_eq!(mgr.profile_arn().await.as_deref(), Some("arn:aws:test"));
        assert_eq!(mgr.auth_type().await, AuthType::KiroDesktop);
        assert_eq!(mgr.api_host().await, "https://codewhisperer.eu-west-1.amazonaws.com");
        assert_eq!(mgr.q_host().await, "https://q.eu-west-1.amazonaws.com");
    }

    #[tokio::test]
    async fn test_new_with_client_id_secret_detects_sso_oidc() {
        let mgr = KiroAuthManager::new(Some("rt".into()), None, None, None, Some("cid".into()), Some("cs".into()), None);
        assert_eq!(mgr.auth_type().await, AuthType::AwsSsoOidc);
    }

    // --- Auth type detection ---

    #[test]
    fn test_detect_auth_type_kiro_desktop() {
        let mut inner = make_inner(Some("rt"), None, None);
        inner.detect_auth_type();
        assert_eq!(inner.auth_type, AuthType::KiroDesktop);
    }

    #[test]
    fn test_detect_auth_type_sso_oidc() {
        let mut inner = make_inner(Some("rt"), Some("cid"), Some("cs"));
        inner.detect_auth_type();
        assert_eq!(inner.auth_type, AuthType::AwsSsoOidc);
    }

    #[test]
    fn test_detect_auth_type_partial_client_stays_desktop() {
        let mut inner = make_inner(Some("rt"), Some("cid"), None);
        inner.detect_auth_type();
        assert_eq!(inner.auth_type, AuthType::KiroDesktop);
    }

    // --- Token expiry checks ---

    #[test]
    fn test_is_token_expiring_soon_no_expiry() {
        let inner = make_inner(None, None, None);
        assert!(inner.is_token_expiring_soon());
    }

    #[test]
    fn test_is_token_expiring_soon_future() {
        let mut inner = make_inner(None, None, None);
        inner.expires_at = Some(Utc::now() + Duration::hours(1));
        assert!(!inner.is_token_expiring_soon());
    }

    #[test]
    fn test_is_token_expiring_soon_within_threshold() {
        let mut inner = make_inner(None, None, None);
        inner.expires_at = Some(Utc::now() + Duration::minutes(5));
        assert!(inner.is_token_expiring_soon());
    }

    #[test]
    fn test_is_token_expired_no_expiry() {
        let inner = make_inner(None, None, None);
        assert!(inner.is_token_expired());
    }

    #[test]
    fn test_is_token_expired_future() {
        let mut inner = make_inner(None, None, None);
        inner.expires_at = Some(Utc::now() + Duration::hours(1));
        assert!(!inner.is_token_expired());
    }

    #[test]
    fn test_is_token_expired_past() {
        let mut inner = make_inner(None, None, None);
        inner.expires_at = Some(Utc::now() - Duration::minutes(5));
        assert!(inner.is_token_expired());
    }

    // --- Credential loading from JSON ---

    #[tokio::test]
    async fn test_load_credentials_from_file_basic() {
        let json = r#"{"refreshToken":"rt_file","accessToken":"at_file","profileArn":"arn:aws:file","region":"ap-southeast-1","expiresAt":"2099-12-31T23:59:59Z"}"#;
        let f = write_temp_json(json);
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, Some(path), None, None, None);
        assert_eq!(mgr.region().await, "ap-southeast-1");
        assert_eq!(mgr.profile_arn().await.as_deref(), Some("arn:aws:file"));
        assert_eq!(mgr.api_host().await, "https://codewhisperer.ap-southeast-1.amazonaws.com");
        assert!(mgr.expires_at().await.is_some());
    }

    #[tokio::test]
    async fn test_load_credentials_from_file_with_client_id_hash() {
        let json = r#"{"refreshToken":"rt_ent","accessToken":"at_ent","region":"us-east-1","clientIdHash":"abc123hash","expiresAt":"2099-12-31T23:59:59Z"}"#;
        let f = write_temp_json(json);
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, Some(path), None, None, None);
        let inner = mgr.inner.lock().await;
        assert_eq!(inner.client_id_hash.as_deref(), Some("abc123hash"));
        assert_eq!(inner.auth_type, AuthType::KiroDesktop);
    }

    #[tokio::test]
    async fn test_load_credentials_from_file_with_inline_client() {
        let json = r#"{"refreshToken":"rt_inline","clientId":"cid_inline","clientSecret":"cs_inline","expiresAt":"2099-12-31T23:59:59Z"}"#;
        let f = write_temp_json(json);
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, Some(path), None, None, None);
        assert_eq!(mgr.auth_type().await, AuthType::AwsSsoOidc);
    }

    #[tokio::test]
    async fn test_load_credentials_from_nonexistent_file() {
        let mgr = KiroAuthManager::new(Some("rt_fallback".into()), None, None, Some("/tmp/nonexistent_kiro_creds_12345.json".into()), None, None, None);
        assert_eq!(mgr.auth_type().await, AuthType::KiroDesktop);
    }

    // --- Credential loading from SQLite ---

    #[tokio::test]
    async fn test_load_credentials_from_sqlite_social() {
        let token_json = r#"{"access_token":"at_sq","refresh_token":"rt_sq","profile_arn":"arn:sq","region":"us-west-2","expires_at":"2099-12-31T23:59:59Z"}"#;
        let f = create_test_sqlite("kirocli:social:token", token_json, None, None);
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, Some(path));
        assert_eq!(mgr.auth_type().await, AuthType::KiroDesktop);
        assert_eq!(mgr.profile_arn().await.as_deref(), Some("arn:sq"));
        let inner = mgr.inner.lock().await;
        assert_eq!(inner.sso_region.as_deref(), Some("us-west-2"));
        assert_eq!(inner.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_load_credentials_from_sqlite_with_registration() {
        let token_json = r#"{"access_token":"at_oidc","refresh_token":"rt_oidc","region":"ap-southeast-1","expires_at":"2099-12-31T23:59:59Z"}"#;
        let reg_json = r#"{"client_id":"cid_sq","client_secret":"cs_sq","region":"ap-southeast-1"}"#;
        let f = create_test_sqlite("kirocli:odic:token", token_json, Some("kirocli:odic:device-registration"), Some(reg_json));
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, Some(path));
        assert_eq!(mgr.auth_type().await, AuthType::AwsSsoOidc);
        let inner = mgr.inner.lock().await;
        assert_eq!(inner.sso_region.as_deref(), Some("ap-southeast-1"));
    }

    #[tokio::test]
    async fn test_load_credentials_from_sqlite_priority_order() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)", []).unwrap();
        conn.execute("INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params!["kirocli:social:token", r#"{"access_token":"at_social","refresh_token":"rt_social"}"#]).unwrap();
        conn.execute("INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params!["kirocli:odic:token", r#"{"access_token":"at_oidc","refresh_token":"rt_oidc"}"#]).unwrap();
        drop(conn);
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, Some(path));
        let inner = mgr.inner.lock().await;
        assert_eq!(inner.sqlite_token_key.as_deref(), Some("kirocli:social:token"));
    }

    // --- Credential saving ---

    #[tokio::test]
    async fn test_save_credentials_to_file() {
        let json = r#"{"refreshToken":"rt_orig","accessToken":"at_orig","extra":"preserved"}"#;
        let f = write_temp_json(json);
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, Some(path.clone()), None, None, None);
        {
            let mut inner = mgr.inner.lock().await;
            inner.access_token = Some("at_new".into());
            inner.refresh_token = Some("rt_new".into());
            inner.expires_at = Some(Utc::now() + Duration::hours(1));
            inner.save_credentials_to_file();
        }
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["accessToken"], "at_new");
        assert_eq!(saved["refreshToken"], "rt_new");
        assert_eq!(saved["extra"], "preserved");
        assert!(saved["expiresAt"].is_string());
    }

    #[tokio::test]
    async fn test_save_credentials_to_sqlite() {
        let token_json = r#"{"access_token":"at_old","refresh_token":"rt_old"}"#;
        let f = create_test_sqlite("kirocli:social:token", token_json, None, None);
        let path = f.path().to_str().unwrap().to_string();
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, Some(path));
        {
            let mut inner = mgr.inner.lock().await;
            inner.access_token = Some("at_updated".into());
            inner.refresh_token = Some("rt_updated".into());
            inner.expires_at = Some(Utc::now() + Duration::hours(1));
            inner.save_credentials_to_sqlite();
        }
        let conn = Connection::open(f.path()).unwrap();
        let saved: String = conn.query_row("SELECT value FROM auth_kv WHERE key = ?1", ["kirocli:social:token"], |row| row.get(0)).unwrap();
        let saved_data: Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(saved_data["access_token"], "at_updated");
        assert_eq!(saved_data["refresh_token"], "rt_updated");
    }

    // --- Error cases ---

    #[tokio::test]
    async fn test_load_nonexistent_sqlite() {
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, Some("/tmp/nonexistent_kiro_db_99999.sqlite3".into()));
        assert_eq!(mgr.auth_type().await, AuthType::KiroDesktop);
    }

    #[test]
    fn test_parse_expires_at_rfc3339() {
        let dt = parse_expires_at("2026-02-10T19:54:16Z").unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 2);
    }

    #[test]
    fn test_parse_expires_at_with_offset() {
        let dt = parse_expires_at("2026-02-10T19:54:16+00:00").unwrap();
        assert_eq!(dt.year(), 2026);
    }

    #[test]
    fn test_parse_expires_at_naive() {
        let dt = parse_expires_at("2026-02-10T19:54:16").unwrap();
        assert_eq!(dt.year(), 2026);
    }

    #[test]
    fn test_parse_expires_at_invalid() {
        assert!(parse_expires_at("not-a-date").is_err());
    }

    #[test]
    fn test_shellexpand_path_absolute() {
        let p = shellexpand_path("/tmp/test.json").unwrap();
        assert_eq!(p, PathBuf::from("/tmp/test.json"));
    }

    #[test]
    fn test_shellexpand_path_tilde() {
        let p = shellexpand_path("~/test.json").unwrap();
        assert!(p.to_str().unwrap().contains("test.json"));
        assert!(!p.to_str().unwrap().starts_with('~'));
    }

    #[tokio::test]
    async fn test_fingerprint_is_stable() {
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, None);
        assert_eq!(mgr.fingerprint().await.len(), 64);
    }

    // --- Async token tests ---

    #[tokio::test]
    async fn test_get_access_token_no_token_no_refresh() {
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, None);
        let result = mgr.get_access_token().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_access_token_valid_token_not_expiring() {
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, None);
        {
            let mut inner = mgr.inner.lock().await;
            inner.access_token = Some("valid_token".into());
            inner.expires_at = Some(Utc::now() + Duration::hours(1));
        }
        let result = mgr.get_access_token().await;
        assert_eq!(result.unwrap(), "valid_token");
    }

    #[tokio::test]
    async fn test_get_access_token_uses_unexpired_token_when_refresh_fails() {
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, None);
        {
            let mut inner = mgr.inner.lock().await;
            inner.access_token = Some("still_valid_token".into());
            inner.expires_at = Some(Utc::now() + Duration::seconds(60));
        }

        let result = mgr.get_access_token().await;
        assert_eq!(result.unwrap(), "still_valid_token");
    }

    #[tokio::test]
    async fn test_force_refresh_no_refresh_token() {
        let mgr = KiroAuthManager::new(None, None, None, None, None, None, None);
        let result = mgr.force_refresh().await;
        assert!(result.is_err());
    }
}
