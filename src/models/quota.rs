use serde::{Deserialize, Serialize};

/// 模型配额信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelQuota {
    pub name: String,
    pub percentage: i32, // 剩余百分比 0-100
    #[serde(default)]
    pub reset_time: String,
    #[serde(default)]
    pub usage_limit: Option<f64>,
    #[serde(default)]
    pub current_usage: Option<f64>,
}

/// 配额数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaData {
    pub models: Vec<ModelQuota>,
    #[serde(default)]
    pub last_updated: i64,
    #[serde(default)]
    pub is_forbidden: bool,
    /// 订阅等级 (FREE/PRO/PRO+/POWER)
    #[serde(default)]
    pub subscription_tier: Option<String>,
}

impl QuotaData {
    pub fn new() -> Self {
        Self {
            models: Vec::new(),
            last_updated: chrono::Utc::now().timestamp(),
            is_forbidden: false,
            subscription_tier: None,
        }
    }

    pub fn add_model(&mut self, name: String, percentage: i32, reset_time: String) {
        self.models.push(ModelQuota {
            name,
            percentage,
            reset_time,
            usage_limit: None,
            current_usage: None,
        });
    }

    pub fn add_model_with_usage(
        &mut self,
        name: String,
        percentage: i32,
        reset_time: String,
        usage_limit: f64,
        current_usage: f64,
    ) {
        self.models.push(ModelQuota {
            name,
            percentage,
            reset_time,
            usage_limit: Some(usage_limit),
            current_usage: Some(current_usage),
        });
    }
}

impl Default for QuotaData {
    fn default() -> Self {
        Self::new()
    }
}
