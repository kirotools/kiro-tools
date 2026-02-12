#![allow(dead_code)]
// Token counting with Claude correction factor
// Uses char/4 heuristic with 1.15x correction for Claude tokenization patterns

use crate::proxy::mappers::claude::models::{
    ClaudeRequest, ContentBlock, MessageContent, SystemPrompt,
};

/// Claude tokenizes ~15% more than GPT-4 (cl100k_base) based on empirical observation
pub const CLAUDE_CORRECTION_FACTOR: f64 = 1.15;

/// Per-message overhead tokens (role markers, separators)
pub const MESSAGE_OVERHEAD_TOKENS: u32 = 4;

/// Estimate token count for a text string.
/// Uses char_count / 4 * correction_factor as a fast approximation.
pub fn count_tokens(text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let base = (text.len() / 4).max(1);
    (base as f64 * CLAUDE_CORRECTION_FACTOR).round() as u32
}

/// Count tokens for a single message's content, including per-message overhead.
pub fn count_message_tokens(content: &MessageContent) -> u32 {
    let content_tokens = match content {
        MessageContent::String(s) => count_tokens(s),
        MessageContent::Array(blocks) => {
            let mut total = 0u32;
            for block in blocks {
                total += match block {
                    ContentBlock::Text { text } => count_tokens(text),
                    ContentBlock::Thinking { thinking, .. } => count_tokens(thinking),
                    ContentBlock::Image { .. } => 100, // Image blocks use ~100 tokens
                    ContentBlock::Document { .. } => 200, // Documents use more
                    ContentBlock::ToolUse { input, .. } => count_tokens(&input.to_string()),
                    ContentBlock::ToolResult { content, .. } => count_tokens(&content.to_string()),
                    _ => 10, // Other block types: small overhead
                };
            }
            total
        }
    };
    content_tokens + MESSAGE_OVERHEAD_TOKENS
}

/// Count tokens for tool definitions.
pub fn count_tools_tokens(tools: &[crate::proxy::mappers::claude::models::Tool]) -> u32 {
    let mut total = 0u32;
    for tool in tools {
        if let Some(name) = &tool.name {
            total += count_tokens(name);
        }
        if let Some(desc) = &tool.description {
            total += count_tokens(desc);
        }
        if let Some(schema) = &tool.input_schema {
            total += count_tokens(&schema.to_string());
        }
        total += MESSAGE_OVERHEAD_TOKENS; // Per-tool overhead
    }
    total
}

/// Estimate total request tokens (system + messages + tools + overhead).
pub fn estimate_request_tokens(request: &ClaudeRequest) -> u32 {
    let mut total: u32 = 0;

    // System prompt tokens
    if let Some(system) = &request.system {
        match system {
            SystemPrompt::String(s) => total += count_tokens(s),
            SystemPrompt::Array(blocks) => {
                for block in blocks {
                    total += count_tokens(&block.text);
                }
            }
        }
    }

    // Message tokens (with per-message overhead)
    for msg in &request.messages {
        total += count_message_tokens(&msg.content);
    }

    // Tool definition tokens
    if let Some(tools) = &request.tools {
        total += count_tools_tokens(tools);
    }

    // Final overhead (response priming)
    total += 3;

    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::mappers::claude::models::Message;

    #[test]
    fn test_count_tokens_empty() {
        assert_eq!(count_tokens(""), 0);
    }

    #[test]
    fn test_count_tokens_short() {
        // "hello" = 5 chars, 5/4 = 1, 1 * 1.15 = 1
        let tokens = count_tokens("hello");
        assert!(tokens >= 1);
    }

    #[test]
    fn test_count_tokens_correction_factor() {
        // 400 chars -> 100 base -> 115 with correction
        let text = "a".repeat(400);
        let tokens = count_tokens(&text);
        assert_eq!(tokens, 115);
    }

    #[test]
    fn test_message_overhead_included() {
        let content = MessageContent::String("test".to_string());
        let tokens = count_message_tokens(&content);
        assert!(tokens >= MESSAGE_OVERHEAD_TOKENS);
    }

    use proptest::prelude::*;

    proptest! {
        /// Property 16: count_tokens >= len/4, approximately len/4 * 1.15.
        #[test]
        fn prop_token_count_claude_correction(text in "[a-zA-Z0-9 ]{0,200}") {
            let tokens = count_tokens(&text);
            if text.is_empty() {
                prop_assert_eq!(tokens, 0);
            } else {
                let base = (text.len() / 4).max(1);
                let expected = (base as f64 * CLAUDE_CORRECTION_FACTOR).round() as u32;
                prop_assert_eq!(tokens, expected);
                prop_assert!(tokens >= (text.len() / 4) as u32);
            }
        }

        /// Property 17: estimate_request_tokens >= sum of message tokens + overhead.
        #[test]
        fn prop_estimate_request_tokens_lower_bound(
            sys in "[a-zA-Z0-9 ]{0,50}",
            msg_text in "[a-zA-Z0-9 ]{0,50}",
        ) {
            let request = ClaudeRequest {
                model: "test".into(),
                messages: vec![Message {
                    role: "user".into(),
                    content: MessageContent::String(msg_text.clone()),
                }],
                system: Some(SystemPrompt::String(sys.clone())),
                tools: None,
                stream: false,
                max_tokens: None,
                temperature: None,
                top_p: None,
                top_k: None,
                thinking: None,
                metadata: None,
                output_config: None,
                size: None,
                quality: None,
            };

            let total = estimate_request_tokens(&request);
            let sys_tokens = count_tokens(&sys);
            let msg_tokens = count_message_tokens(&MessageContent::String(msg_text));

            prop_assert!(
                total >= sys_tokens + msg_tokens + 3,
                "total {} < sys {} + msg {} + 3",
                total, sys_tokens, msg_tokens
            );
        }
    }
}
