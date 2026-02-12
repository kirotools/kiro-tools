// Claude 数据模型
// Claude 协议相关数据模型

use serde::{Deserialize, Serialize};

/// Claude API 请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(default)]
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ThinkingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// Output configuration for effort level (Claude API v2.0.67+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_config: Option<OutputConfig>,
    // [NEW] Image generation parameters (for Anthropic protocol compatibility)
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub quality: Option<String>,
}

/// Thinking 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinkingConfig {
    #[serde(rename = "type")]
    pub type_: String, // "enabled"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u32>,
}

/// System Prompt
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    String(String),
    Array(Vec<SystemBlock>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: String,
}

/// Message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: MessageContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    String(String),
    Array(Vec<ContentBlock>),
}

/// Content Block (Claude)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },

    #[serde(rename = "thinking")]
    Thinking {
        thinking: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },

    #[serde(rename = "image")]
    Image {
        source: ImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },

    #[serde(rename = "document")]
    Document {
        source: DocumentSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },

    #[serde(rename = "redacted_thinking")]
    RedactedThinking { data: String },

    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },

    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: serde_json::Value, // Changed from String to Value to support Array of Blocks
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },

    #[serde(rename = "server_tool_use")]
    ServerToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },

    #[serde(rename = "web_search_tool_result")]
    WebSearchToolResult {
        tool_use_id: String,
        content: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub media_type: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSource {
    #[serde(rename = "type")]
    pub source_type: String, // "base64"
    pub media_type: String, // e.g. "application/pdf"
    pub data: String,       // base64 data
}

/// Tool - supports both client tools (with input_schema) and server tools (like web_search)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Tool type - for server tools like "web_search_20250305"
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// Tool name - "web_search" for server tools, custom name for client tools
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input schema - required for client tools, absent for server tools
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

impl Tool {
    #[allow(dead_code)]
    pub fn is_web_search(&self) -> bool {
        // Check by type (preferred for server tools)
        if let Some(ref t) = self.type_ {
            if t.starts_with("web_search") {
                return true;
            }
        }
        // Check by name (fallback)
        if let Some(ref n) = self.name {
            if n == "web_search" {
                return true;
            }
        }
        false
    }

    /// Get the effective tool name
    #[allow(dead_code)]
    pub fn get_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            // For server tools, derive name from type
            if let Some(ref t) = self.type_ {
                if t.starts_with("web_search") {
                    return "web_search".to_string();
                }
            }
            "unknown".to_string()
        })
    }
}

/// Metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// Output Configuration (Claude API v2.0.67+)
/// Controls effort level for model reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Effort level: "high", "medium", "low"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
}

/// Claude API 响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ClaudeResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub role: String,
    pub model: String,
    pub content: Vec<ContentBlock>,
    pub stop_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequence: Option<String>,
    pub usage: Usage,
}

/// Usage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tool_use: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property 15: ContentBlock::Text serde roundtrip.
        #[test]
        fn prop_content_block_text_roundtrip(text in "[a-zA-Z0-9 ]{0,100}") {
            let block = ContentBlock::Text { text: text.clone() };
            let json = serde_json::to_string(&block).unwrap();
            let back: ContentBlock = serde_json::from_str(&json).unwrap();
            match back {
                ContentBlock::Text { text: t } => prop_assert_eq!(t, text),
                _ => prop_assert!(false, "wrong variant"),
            }
        }

        #[test]
        fn prop_content_block_thinking_roundtrip(
            thinking in "[a-zA-Z0-9 ]{0,100}",
        ) {
            let block = ContentBlock::Thinking {
                thinking: thinking.clone(),
                signature: Some("sig123".into()),
                cache_control: None,
            };
            let json = serde_json::to_string(&block).unwrap();
            let back: ContentBlock = serde_json::from_str(&json).unwrap();
            match back {
                ContentBlock::Thinking { thinking: t, signature: s, .. } => {
                    prop_assert_eq!(t, thinking);
                    prop_assert_eq!(s.unwrap(), "sig123");
                }
                _ => prop_assert!(false, "wrong variant"),
            }
        }

        #[test]
        fn prop_content_block_tool_use_roundtrip(
            name in "[a-zA-Z][a-zA-Z0-9_]{0,20}",
            key in "[a-zA-Z]{1,10}",
            val in "[a-zA-Z0-9]{0,20}",
        ) {
            let block = ContentBlock::ToolUse {
                id: "toolu_abc123".into(),
                name: name.clone(),
                input: serde_json::json!({key.clone(): val.clone()}),
                signature: None,
                cache_control: None,
            };
            let json = serde_json::to_string(&block).unwrap();
            let back: ContentBlock = serde_json::from_str(&json).unwrap();
            match back {
                ContentBlock::ToolUse { id, name: n, input, .. } => {
                    prop_assert_eq!(id, "toolu_abc123");
                    prop_assert_eq!(n, name);
                    prop_assert_eq!(input[&key].as_str().unwrap(), val.as_str());
                }
                _ => prop_assert!(false, "wrong variant"),
            }
        }

        #[test]
        fn prop_content_block_tool_result_roundtrip(
            tool_use_id in "[a-zA-Z0-9_]{1,30}",
            content_str in "[a-zA-Z0-9 ]{0,50}",
        ) {
            let block = ContentBlock::ToolResult {
                tool_use_id: tool_use_id.clone(),
                content: serde_json::Value::String(content_str.clone()),
                is_error: Some(false),
            };
            let json = serde_json::to_string(&block).unwrap();
            let back: ContentBlock = serde_json::from_str(&json).unwrap();
            match back {
                ContentBlock::ToolResult { tool_use_id: tid, content, is_error } => {
                    prop_assert_eq!(tid, tool_use_id);
                    prop_assert_eq!(content.as_str().unwrap(), content_str.as_str());
                    prop_assert_eq!(is_error, Some(false));
                }
                _ => prop_assert!(false, "wrong variant"),
            }
        }

        #[test]
        fn prop_content_block_redacted_thinking_roundtrip(data in "[a-zA-Z0-9]{0,50}") {
            let block = ContentBlock::RedactedThinking { data: data.clone() };
            let json = serde_json::to_string(&block).unwrap();
            let back: ContentBlock = serde_json::from_str(&json).unwrap();
            match back {
                ContentBlock::RedactedThinking { data: d } => prop_assert_eq!(d, data),
                _ => prop_assert!(false, "wrong variant"),
            }
        }
    }
}
