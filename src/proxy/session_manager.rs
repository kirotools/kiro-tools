use crate::proxy::mappers::claude::models::{ClaudeRequest, MessageContent};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
pub struct SessionManager;

impl SessionManager {
    /// 根据 Claude 请求生成稳定的会话指纹 (Session Fingerprint)
    ///
    /// 设计理念:
    /// - 只哈希第一条用户消息内容,不混入模型名称或时间戳
    /// - 确保同一对话的所有轮次使用相同的 session_id
    /// - 最大化 prompt caching 的命中率
    ///
    /// 优先级:
    /// 1. metadata.user_id (客户端显式提供)
    /// 2. 第一条用户消息的 SHA256 哈希
    #[allow(dead_code)]
    pub fn extract_session_id(request: &ClaudeRequest) -> String {
        // 1. 优先使用 metadata 中的 user_id
        if let Some(metadata) = &request.metadata {
            if let Some(user_id) = &metadata.user_id {
                if !user_id.is_empty() && !user_id.contains("session-") {
                    tracing::debug!("[SessionManager] Using explicit user_id: {}", user_id);
                    return user_id.clone();
                }
            }
        }

        // 2. 备选方案：基于第一条用户消息的 SHA256 哈希
        let mut hasher = Sha256::new();

        let mut content_found = false;
        for msg in &request.messages {
            if msg.role != "user" {
                continue;
            }

            let text = match &msg.content {
                MessageContent::String(s) => s.clone(),
                MessageContent::Array(blocks) => blocks
                    .iter()
                    .filter_map(|block| match block {
                        crate::proxy::mappers::claude::models::ContentBlock::Text { text } => {
                            Some(text.as_str())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            };

            let clean_text = text.trim();
            // [FIX #1732] 降低准入门槛 (10 -> 3)，确保即使是短消息也会生成稳定的会话锚点
            // 同时排除包含系统标志的消息，防止因为协议注入导致的 ID 漂移
            if clean_text.len() >= 3
                && !clean_text.contains("<system-reminder>")
                && !clean_text.contains("[System")
            {
                hasher.update(clean_text.as_bytes());
                content_found = true;
                break; // 始终锚定第一条有效用户消息
            }
        }

        if !content_found {
            // 如果没找到有意义的内容，退化为对最后一条消息进行哈希
            if let Some(last_msg) = request.messages.last() {
                hasher.update(format!("{:?}", last_msg.content).as_bytes());
            }
        }

        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-{}", &hash[..16]);

        tracing::debug!(
            "[SessionManager] Generated session_id: {} (content_found: {}, model: {})",
            sid,
            content_found,
            request.model
        );
        sid
    }
}
