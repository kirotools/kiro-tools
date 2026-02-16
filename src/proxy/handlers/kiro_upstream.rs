// Kiro Upstream Handler
// Converts Anthropic /v1/messages requests to Kiro generateAssistantResponse API format,
// sends to AWS Q endpoint, parses AWS event stream response, and converts back to Anthropic SSE.

use axum::{
    body::Body,
    http::{header, StatusCode},
    response::Response,
};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use crate::auth::config::{get_kiro_q_host, get_machine_fingerprint};
use crate::proxy::common::errors::{error_response, AnthropicErrorType};
use crate::proxy::errors::kiro_errors::map_kiro_error;
use crate::proxy::errors::network_errors::classify_network_error;
use crate::proxy::mappers::claude::models::{
    ClaudeRequest, ContentBlock, Message, MessageContent, SystemPrompt,
};
use crate::proxy::token_manager::ConcurrencySlot;
use crate::proxy::upstream::thinking_parser::{ThinkingParser, ThinkingEvent};
use crate::proxy::upstream::parsers::parse_bracket_tool_calls;
use crate::proxy::upstream::retry::parse_retry_delay;

// ===== Kiro Headers =====

fn get_kiro_headers(token: &str, fingerprint: &str) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {}", token).parse().unwrap(),
    );
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );

    let ua = format!(
        "aws-sdk-js/1.0.27 ua/2.1 os/win32#10.0.19044 lang/js md/nodejs#22.21.1 api/codewhispererstreaming#1.0.27 m/E KiroIDE-0.7.45-{}",
        fingerprint
    );
    headers.insert(reqwest::header::USER_AGENT, ua.parse().unwrap());
    headers.insert(
        "x-amz-user-agent",
        format!("aws-sdk-js/1.0.27 KiroIDE-0.7.45-{}", fingerprint)
            .parse()
            .unwrap(),
    );
    headers.insert(
        "x-amzn-codewhisperer-optout",
        "true".parse().unwrap(),
    );
    headers.insert(
        "x-amzn-kiro-agent-mode",
        "vibe".parse().unwrap(),
    );
    headers.insert(
        "amz-sdk-invocation-id",
        uuid::Uuid::new_v4().to_string().parse().unwrap(),
    );
    headers.insert(
        "amz-sdk-request",
        "attempt=1; max=3".parse().unwrap(),
    );

    headers
}

// ===== Anthropic → Kiro Payload Conversion =====

/// Extract plain text from MessageContent
fn extract_text(content: &MessageContent) -> String {
    match content {
        MessageContent::String(s) => s.clone(),
        MessageContent::Array(blocks) => {
            let mut parts = Vec::new();
            for block in blocks {
                match block {
                    ContentBlock::Text { text } => parts.push(text.clone()),
                    ContentBlock::Thinking { thinking, .. } => {
                        if !thinking.is_empty() {
                            parts.push(thinking.clone());
                        }
                    }
                    ContentBlock::Image { source, .. } => {
                        parts.push(format!("[Image: {}]", source.media_type));
                    }
                    _ => {}
                }
            }
            parts.join("\n")
        }
    }
}

/// Extract images from content blocks, converting to Kiro format.
/// Kiro format: [{"format": "jpeg", "source": {"bytes": "base64..."}}]
fn extract_images(content: &MessageContent) -> Vec<Value> {
    let mut images = Vec::new();
    if let MessageContent::Array(blocks) = content {
        for block in blocks {
            if let ContentBlock::Image { source, .. } = block {
                let mut data = source.data.clone();
                let mut media_type = source.media_type.clone();

                // Strip data URL prefix if present (e.g., "data:image/jpeg;base64,...")
                if data.starts_with("data:") {
                    if let Some(comma_pos) = data.find(',') {
                        let header = &data[..comma_pos];
                        let media_part = header.split(';').next().unwrap_or("");
                        let extracted = media_part.strip_prefix("data:").unwrap_or("");
                        if !extracted.is_empty() {
                            media_type = extracted.to_string();
                        }
                        data = data[comma_pos + 1..].to_string();
                    }
                }

                let format_str = media_type.split('/').last().unwrap_or(&media_type).to_string();
                images.push(json!({
                    "format": format_str,
                    "source": { "bytes": data }
                }));
            }
        }
    }
    images
}

/// Extract tool uses from assistant message content blocks
fn extract_tool_uses(content: &MessageContent) -> Vec<Value> {
    let mut tool_uses = Vec::new();
    if let MessageContent::Array(blocks) = content {
        for block in blocks {
            if let ContentBlock::ToolUse { id, name, input, .. } = block {
                tool_uses.push(json!({
                    "toolUseId": id,
                    "name": name,
                    "input": input
                }));
            }
        }
    }
    tool_uses
}

/// Extract tool results from user message content blocks
fn extract_tool_results(content: &MessageContent) -> Vec<Value> {
    let mut results = Vec::new();
    if let MessageContent::Array(blocks) = content {
        for block in blocks {
            if let ContentBlock::ToolResult {
                tool_use_id,
                content: result_content,
                is_error,
            } = block
            {
                let text = match result_content {
                    Value::String(s) => s.clone(),
                    Value::Array(arr) => {
                        arr.iter()
                            .filter_map(|item| item.get("text").and_then(|t| t.as_str()))
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                    other => other.to_string(),
                };
                let status = if is_error.unwrap_or(false) {
                    "error"
                } else {
                    "success"
                };
                results.push(json!({
                    "toolUseId": tool_use_id,
                    "content": [{"text": text}],
                    "status": status
                }));
            }
        }
    }
    results
}

// ===== JSON Schema & Tool Name Sanitization =====
// Ported from kiro-gateway converters_core.py

/// Maximum allowed tool name length per Kiro/AWS Q API.
const TOOL_NAME_MAX_LENGTH: usize = 64;

/// Threshold for "long description" — descriptions longer than this get moved to system prompt.
const LONG_DESC_THRESHOLD: usize = 8000;

/// Sanitize a JSON schema to remove fields that Kiro/AWS Q API doesn't support.
/// Removes `additionalProperties` and empty `required: []` recursively.
/// Ported from kiro-gateway converters_core.py sanitize_json_schema().
fn sanitize_json_schema(schema: &mut Value) {
    if let Some(obj) = schema.as_object_mut() {
        // Remove additionalProperties (Kiro API doesn't support it)
        obj.remove("additionalProperties");

        // Remove empty required: [] (causes validation errors)
        if let Some(req) = obj.get("required") {
            if req.as_array().map(|a| a.is_empty()).unwrap_or(false) {
                obj.remove("required");
            }
        }

        // Recursively sanitize nested schemas
        // properties
        if let Some(props) = obj.get_mut("properties") {
            if let Some(props_obj) = props.as_object_mut() {
                for (_, prop_schema) in props_obj.iter_mut() {
                    sanitize_json_schema(prop_schema);
                }
            }
        }

        // items (for array types)
        if let Some(items) = obj.get_mut("items") {
            sanitize_json_schema(items);
        }

        // anyOf / oneOf / allOf
        for key in &["anyOf", "oneOf", "allOf"] {
            if let Some(variants) = obj.get_mut(*key) {
                if let Some(arr) = variants.as_array_mut() {
                    for variant in arr.iter_mut() {
                        sanitize_json_schema(variant);
                    }
                }
            }
        }
    }
}

/// Sanitize a tool name: strip leading '$', truncate to TOOL_NAME_MAX_LENGTH.
/// Returns None if the name is empty after sanitization.
fn sanitize_tool_name(name: &str) -> Option<String> {
    let cleaned = name.strip_prefix('$').unwrap_or(name);
    if cleaned.is_empty() {
        return None;
    }
    if cleaned.len() > TOOL_NAME_MAX_LENGTH {
        Some(cleaned[..TOOL_NAME_MAX_LENGTH].to_string())
    } else {
        Some(cleaned.to_string())
    }
}

/// Validate tool names. Returns Err with details if any name is invalid (> 64 chars).
fn validate_tool_names(tools: &[crate::proxy::mappers::claude::models::Tool]) -> Result<(), String> {
    for tool in tools {
        if let Some(name) = &tool.name {
            let cleaned = name.strip_prefix('$').unwrap_or(name);
            if cleaned.len() > TOOL_NAME_MAX_LENGTH {
                return Err(format!(
                    "Tool name '{}...' exceeds {} character limit ({} chars). Shorten the tool name.",
                    &cleaned[..40.min(cleaned.len())],
                    TOOL_NAME_MAX_LENGTH,
                    cleaned.len()
                ));
            }
        }
    }
    Ok(())
}

/// Process tools with long descriptions: move long descriptions to system prompt,
/// leave a short reference in the tool spec.
/// Returns (modified_tools_descriptions, system_prompt_addition).
/// Ported from kiro-gateway converters_core.py process_tools_with_long_descriptions().
fn process_long_tool_descriptions(tools: &[crate::proxy::mappers::claude::models::Tool]) -> (Vec<(String, String)>, String) {
    let mut overrides: Vec<(String, String)> = Vec::new(); // (name, short_desc)
    let mut system_additions: Vec<String> = Vec::new();

    for tool in tools {
        let name = tool.name.as_deref().unwrap_or("");
        let desc = tool.description.as_deref().unwrap_or("");

        if desc.len() > LONG_DESC_THRESHOLD {
            // Move full description to system prompt
            system_additions.push(format!(
                "## Tool: {}\n\n{}",
                name, desc
            ));
            // Leave short reference in tool spec
            overrides.push((
                name.to_string(),
                format!(
                    "See full documentation in system prompt under '## Tool: {}'. Summary: {}",
                    name,
                    if desc.len() > 200 { &desc[..200] } else { desc }
                ),
            ));
        }
    }

    let system_text = if system_additions.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n---\n# Tool Documentation\n\nThe following tools have detailed documentation that was moved here to save space:\n\n{}",
            system_additions.join("\n\n")
        )
    };

    (overrides, system_text)
}

/// Build tool specifications from Anthropic tools definition.
/// Applies schema sanitization, name sanitization, and description truncation.
fn build_tool_specifications(
    tools: &[crate::proxy::mappers::claude::models::Tool],
    max_desc_length: usize,
    desc_overrides: &[(String, String)],
) -> Vec<Value> {
    tools
        .iter()
        .filter_map(|tool| {
            let raw_name = tool.name.as_deref()?;
            let name = sanitize_tool_name(raw_name)?;

            // Check for description override (from long desc → system prompt)
            let description = if let Some((_, short_desc)) = desc_overrides.iter().find(|(n, _)| n == raw_name) {
                short_desc.clone()
            } else {
                let desc = tool.description.as_deref().unwrap_or("");
                if desc.trim().is_empty() {
                    format!("Tool: {}", name)
                } else if max_desc_length > 0 && desc.len() > max_desc_length {
                    desc[..max_desc_length].to_string()
                } else {
                    desc.to_string()
                }
            };

            let mut schema = tool.input_schema.clone().unwrap_or(json!({}));
            sanitize_json_schema(&mut schema);

            Some(json!({
                "toolSpecification": {
                    "name": name,
                    "description": description,
                    "inputSchema": {
                        "json": schema
                    }
                }
            }))
        })
        .collect()
}

fn has_unsupported_server_tools(request: &ClaudeRequest) -> bool {
    request
        .tools
        .as_ref()
        .map(|tools| tools.iter().any(|tool| tool.is_web_search()))
        .unwrap_or(false)
}

/// Merge consecutive same-role messages into alternating user/assistant pairs
fn merge_to_alternating(messages: &[Message]) -> Vec<(String, String, Vec<Value>, Vec<Value>, Vec<Value>)> {
    let mut merged: Vec<(String, String, Vec<Value>, Vec<Value>, Vec<Value>)> = Vec::new();

    for msg in messages {
        let text = extract_text(&msg.content);
        let tool_uses = extract_tool_uses(&msg.content);
        let tool_results = extract_tool_results(&msg.content);
        let images = extract_images(&msg.content);

        if let Some(last) = merged.last_mut() {
            if last.0 == msg.role {
                if !text.is_empty() {
                    if !last.1.is_empty() {
                        last.1.push('\n');
                    }
                    last.1.push_str(&text);
                }
                last.2.extend(tool_uses);
                last.3.extend(tool_results);
                last.4.extend(images);
                continue;
            }
        }
        merged.push((msg.role.clone(), text, tool_uses, tool_results, images));
    }

    merged
}

fn merge_adjacent_messages(messages: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    if messages.is_empty() {
        return messages;
    }

    let mut merged: Vec<serde_json::Value> = Vec::new();

    for msg in messages {
        if merged.is_empty() {
            merged.push(msg);
            continue;
        }

        let last = merged.last_mut().unwrap();

        let last_role = if last.get("userInputMessage").is_some() {
            "user"
        } else if last.get("assistantResponseMessage").is_some() {
            "assistant"
        } else {
            ""
        };
        let msg_role = if msg.get("userInputMessage").is_some() {
            "user"
        } else if msg.get("assistantResponseMessage").is_some() {
            "assistant"
        } else {
            ""
        };

        if last_role == msg_role && !last_role.is_empty() {
            let (last_key, content_key) = if last_role == "user" {
                ("userInputMessage", "content")
            } else {
                ("assistantResponseMessage", "content")
            };

            let last_content = last
                .get(last_key)
                .and_then(|m| m.get(content_key))
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let msg_content = msg
                .get(last_key)
                .and_then(|m| m.get(content_key))
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(inner) = last.get_mut(last_key) {
                if let Some(content) = inner.get_mut(content_key) {
                    *content = serde_json::Value::String(format!("{}\n{}", last_content, msg_content));
                }
            }

            tracing::debug!("Merged adjacent {} messages in history", last_role);
        } else {
            merged.push(msg);
        }
    }

    merged
}

/// Normalize model name to Kiro format.
/// Strips date suffixes, converts dashes to dots for minor versions.
/// e.g. "claude-sonnet-4-20250514" → "claude-sonnet-4"
///      "claude-haiku-4-5-20251001" → "claude-haiku-4.5"
///      "claude-3-7-sonnet-20250219" → "claude-3.7-sonnet"
fn normalize_model_name(name: &str) -> String {
    let name_lower = name.to_lowercase();

    // Hidden models mapping (display name → internal Kiro ID)
    let hidden_models: std::collections::HashMap<&str, &str> = [
        ("claude-3.7-sonnet", "CLAUDE_3_7_SONNET_20250219_V1_0"),
    ]
    .iter()
    .cloned()
    .collect();

    // Pattern 1: Standard format - claude-{family}-{major}-{minor}(-{suffix})?
    // e.g. claude-haiku-4-5, claude-haiku-4-5-20251001
    let re_standard =
        regex::Regex::new(r"^(claude-(?:haiku|sonnet|opus)-\d+)-(\d{1,2})(?:-(?:\d{8}|latest|\d+))?$")
            .unwrap();
    if let Some(caps) = re_standard.captures(&name_lower) {
        let base = &caps[1];
        let minor = &caps[2];
        let normalized = format!("{}.{}", base, minor);
        if let Some(internal) = hidden_models.get(normalized.as_str()) {
            return internal.to_string();
        }
        return normalized;
    }

    // Pattern 2: Standard format without minor - claude-{family}-{major}(-{date})?
    // e.g. claude-sonnet-4, claude-sonnet-4-20250514
    let re_no_minor =
        regex::Regex::new(r"^(claude-(?:haiku|sonnet|opus)-\d+)(?:-\d{8})?$").unwrap();
    if let Some(caps) = re_no_minor.captures(&name_lower) {
        let normalized = caps[1].to_string();
        if let Some(internal) = hidden_models.get(normalized.as_str()) {
            return internal.to_string();
        }
        return normalized;
    }

    // Pattern 3: Legacy format - claude-{major}-{minor}-{family}(-{suffix})?
    // e.g. claude-3-7-sonnet, claude-3-7-sonnet-20250219
    let re_legacy =
        regex::Regex::new(r"^(claude)-(\d+)-(\d+)-(haiku|sonnet|opus)(?:-(?:\d{8}|latest|\d+))?$")
            .unwrap();
    if let Some(caps) = re_legacy.captures(&name_lower) {
        let prefix = &caps[1];
        let major = &caps[2];
        let minor = &caps[3];
        let family = &caps[4];
        let normalized = format!("{}-{}.{}-{}", prefix, major, minor, family);
        if let Some(internal) = hidden_models.get(normalized.as_str()) {
            return internal.to_string();
        }
        return normalized;
    }

    // Pattern 4: Already normalized with dot but has date suffix
    let re_dot_date =
        regex::Regex::new(r"^(claude-(?:\d+\.\d+-)?(?:haiku|sonnet|opus)(?:-\d+\.\d+)?)-\d{8}$")
            .unwrap();
    if let Some(caps) = re_dot_date.captures(&name_lower) {
        let normalized = caps[1].to_string();
        if let Some(internal) = hidden_models.get(normalized.as_str()) {
            return internal.to_string();
        }
        return normalized;
    }

    // Pattern 5: Inverted format with suffix - claude-{major}.{minor}-{family}-{suffix}
    // e.g. claude-4.5-opus-high → claude-opus-4.5
    let re_inverted =
        regex::Regex::new(r"^claude-(\d+)\.(\d+)-(haiku|sonnet|opus)-(.+)$").unwrap();
    if let Some(caps) = re_inverted.captures(&name_lower) {
        let major = &caps[1];
        let minor = &caps[2];
        let family = &caps[3];
        let normalized = format!("claude-{}-{}.{}", family, major, minor);
        if let Some(internal) = hidden_models.get(normalized.as_str()) {
            return internal.to_string();
        }
        return normalized;
    }

    // Check hidden models for already-normalized input
    if let Some(internal) = hidden_models.get(name_lower.as_str()) {
        return internal.to_string();
    }

    // No transformation needed
    name.to_string()
}

/// Convert tool_use and tool_result content blocks to text representations.
/// Used when the request has NO tools defined — Kiro API rejects toolResults without tool specs.
fn strip_all_tool_content(messages: &[Message]) -> Vec<Message> {
    messages
        .iter()
        .map(|msg| {
            let new_content = match &msg.content {
                MessageContent::String(s) => MessageContent::String(s.clone()),
                MessageContent::Array(blocks) => {
                    let new_blocks: Vec<ContentBlock> = blocks
                        .iter()
                        .map(|block| match block {
                            ContentBlock::ToolUse {
                                name, input, id, ..
                            } => ContentBlock::Text {
                                text: format!(
                                    "[Tool Call: {}({})] (id: {})",
                                    name,
                                    serde_json::to_string(input).unwrap_or_default(),
                                    id
                                ),
                            },
                            ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            } => {
                                let text = match content {
                                    Value::String(s) => s.clone(),
                                    Value::Array(arr) => arr
                                        .iter()
                                        .filter_map(|item| {
                                            item.get("text").and_then(|t| t.as_str())
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n"),
                                    other => other.to_string(),
                                };
                                let error_tag = if is_error.unwrap_or(false) {
                                    " [error]"
                                } else {
                                    ""
                                };
                                ContentBlock::Text {
                                    text: format!(
                                        "[Tool Result ({}): {}{}]",
                                        tool_use_id, text, error_tag
                                    ),
                                }
                            }
                            other => other.clone(),
                        })
                        .collect();
                    MessageContent::Array(new_blocks)
                }
            };
            Message {
                role: msg.role.clone(),
                content: new_content,
            }
        })
        .collect()
}

/// Ensure that every user message containing tool_result blocks is preceded by an
/// assistant message with tool_use blocks. Orphaned tool_results are converted to text.
fn ensure_assistant_before_tool_results(messages: &[Message]) -> Vec<Message> {
    let mut result: Vec<Message> = Vec::new();

    for (i, msg) in messages.iter().enumerate() {
        let has_tool_results = match &msg.content {
            MessageContent::Array(blocks) => blocks.iter().any(|b| {
                matches!(b, ContentBlock::ToolResult { .. })
            }),
            _ => false,
        };

        if !has_tool_results {
            result.push(msg.clone());
            continue;
        }

        let prev_has_tool_use = if i > 0 {
            let prev = &messages[i - 1];
            prev.role == "assistant"
                && match &prev.content {
                    MessageContent::Array(blocks) => {
                        blocks.iter().any(|b| matches!(b, ContentBlock::ToolUse { .. }))
                    }
                    _ => false,
                }
        } else {
            false
        };

        if prev_has_tool_use {
            result.push(msg.clone());
        } else {
            let new_content = match &msg.content {
                MessageContent::Array(blocks) => {
                    let new_blocks: Vec<ContentBlock> = blocks
                        .iter()
                        .map(|block| match block {
                            ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            } => {
                                let text = match content {
                                    Value::String(s) => s.clone(),
                                    Value::Array(arr) => arr
                                        .iter()
                                        .filter_map(|item| {
                                            item.get("text").and_then(|t| t.as_str())
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n"),
                                    other => other.to_string(),
                                };
                                let error_tag = if is_error.unwrap_or(false) {
                                    " [error]"
                                } else {
                                    ""
                                };
                                ContentBlock::Text {
                                    text: format!(
                                        "[Tool Result ({}): {}{}]",
                                        tool_use_id, text, error_tag
                                    ),
                                }
                            }
                            other => other.clone(),
                        })
                        .collect();
                    MessageContent::Array(new_blocks)
                }
                other => other.clone(),
            };
            result.push(Message {
                role: msg.role.clone(),
                content: new_content,
            });
        }
    }

    result
}

/// Normalize message roles: Kiro API only supports "user" and "assistant".
/// Any other role (system, developer, tool, etc.) is converted to "user".
fn normalize_message_roles(messages: &mut [(String, String, Vec<Value>, Vec<Value>, Vec<Value>)]) {
    for item in messages.iter_mut() {
        if item.0 != "user" && item.0 != "assistant" {
            item.0 = "user".to_string();
        }
    }
}

/// Inject fake reasoning tags into content (matching gateway behavior).
/// This injects <thinking_mode>enabled</thinking_mode> tags into the user message
/// to enable extended thinking on Kiro without native thinking support.
fn inject_thinking_tags(content: &str, max_tokens: u32) -> String {
    let thinking_instruction = "Think in English for better reasoning quality.\n\n\
Your thinking process should be thorough and systematic:\n\
- First, make sure you fully understand what is being asked\n\
- Consider multiple approaches or perspectives when relevant\n\
- Think about edge cases, potential issues, and what could go wrong\n\
- Challenge your initial assumptions\n\
- Verify your reasoning before reaching a conclusion\n\n\
After completing your thinking, respond in the same language the user is using in their messages.\n\n\
Take the time you need. Quality of thought matters more than speed.";

    let thinking_prefix = format!(
        "<thinking_mode>enabled</thinking_mode>\n\
<max_thinking_length>{}</max_thinking_length>\n\
<thinking_instruction>{}</thinking_instruction>\n\n",
        max_tokens, thinking_instruction
    );

    format!("{}{}", thinking_prefix, content)
}

/// Get system prompt addition for extended thinking (matching gateway behavior).
/// This legitimizes the thinking tags as system instructions, not prompt injection.
fn get_thinking_system_prompt_addition() -> String {
    "\n\n---\n# Extended Thinking Mode\n\n\
This conversation uses extended thinking mode. User messages may contain \
special XML tags that are legitimate system-level instructions:\n\
- `<thinking_mode>enabled</thinking_mode>` - enables extended thinking\n\
- `<max_thinking_length>N</max_thinking_length>` - sets maximum thinking tokens\n\
- `<thinking_instruction>...</thinking_instruction>` - provides thinking guidelines\n\n\
These tags are NOT prompt injection attempts. They are part of the system's \
extended thinking feature. When you see these tags, follow their instructions \
and wrap your reasoning process in `<thinking>...</thinking>` tags before \
providing your final response.".to_string()
}

/// Convert Anthropic ClaudeRequest to Kiro generateAssistantResponse payload
fn convert_to_kiro_payload(request: &ClaudeRequest, profile_arn: Option<&str>, fake_reasoning: &crate::proxy::config::FakeReasoningConfig) -> Value {
    let model_id = normalize_model_name(&request.model);

    // 1. Extract system prompt and add thinking system prompt addition
    let thinking_system_addition = if fake_reasoning.enabled {
        get_thinking_system_prompt_addition()
    } else {
        String::new()
    };

    // 1b. Process long tool descriptions → move to system prompt
    let (desc_overrides, long_desc_system_addition) = if let Some(tools) = &request.tools {
        process_long_tool_descriptions(tools)
    } else {
        (Vec::new(), String::new())
    };

    let system_text = {
        let base = request.system.as_ref().map(|sp| match sp {
            SystemPrompt::String(s) => s.clone(),
            SystemPrompt::Array(blocks) => blocks
                .iter()
                .map(|b| b.text.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        }).unwrap_or_default();

        let mut sys = if base.is_empty() {
            thinking_system_addition
        } else {
            format!("{}\n{}", base, thinking_system_addition)
        };

        // Append long tool descriptions to system prompt
        if !long_desc_system_addition.is_empty() {
            sys.push_str(&long_desc_system_addition);
        }

        Some(sys)
    };

    // 2. Preprocess messages: strip tool content or fix orphaned tool_results
    let preprocessed = if request.tools.is_none() {
        strip_all_tool_content(&request.messages)
    } else {
        ensure_assistant_before_tool_results(&request.messages)
    };

    // 3. Merge consecutive same-role messages
    let merged = merge_to_alternating(&preprocessed);
    if merged.is_empty() {
        let conversation_id = uuid::Uuid::new_v4().to_string();
        return json!({
            "conversationState": {
                "chatTriggerType": "MANUAL",
                "conversationId": conversation_id,
                "currentMessage": {
                    "userInputMessage": {
                        "content": "Continue",
                        "modelId": model_id,
                        "origin": "AI_EDITOR"
                    }
                }
            }
        });
    }

    // 3. Ensure first message is user
    let mut processed = merged;
    if processed[0].0 != "user" {
        processed.insert(0, ("user".to_string(), "(empty)".to_string(), vec![], vec![], vec![]));
    }

    // 4. Normalize roles (system/developer/tool → user)
    normalize_message_roles(&mut processed);

    let mut alternated: Vec<(String, String, Vec<Value>, Vec<Value>, Vec<Value>)> = vec![processed.remove(0)];
    for item in processed {
        if let Some(last) = alternated.last() {
            if last.0 == item.0 {
                if item.0 == "user" {
                    alternated.push(("assistant".to_string(), "(empty)".to_string(), vec![], vec![], vec![]));
                } else {
                    alternated.push(("user".to_string(), "(empty)".to_string(), vec![], vec![], vec![]));
                }
            }
        }
        alternated.push(item);
    }
    let mut processed = alternated;

    // 5. Prepend system prompt to first user message text
    if let Some(sys) = &system_text {
        if let Some(first) = processed.first_mut() {
            if first.0 == "user" {
                if first.1.is_empty() {
                    first.1 = sys.clone();
                } else {
                    first.1 = format!("{}\n\n{}", sys, first.1);
                }
            }
        }
    }

    // 6. Handle last message being assistant — move to history, add "Continue" user msg
    if processed.last().map(|l| l.0.as_str()) == Some("assistant") {
        let last_assistant = processed.pop().unwrap();
        // Re-add as history
        processed.push(last_assistant);
        processed.push(("user".to_string(), "Continue".to_string(), vec![], vec![], vec![]));
    }

    // 7. Split into history (all but last) and currentMessage (last)
    let last = processed.pop().unwrap();
    let history_items = processed;

    // 8. Build history array — with userInputMessageContext.toolResults for user messages
    let mut history = Vec::new();
    for (role, text, tool_uses, tool_results, images) in &history_items {
        if role == "user" {
            let content = if text.is_empty() { "(empty)" } else { text.as_str() };
            let mut user_input = json!({
                "content": content,
                "modelId": &model_id,
                "origin": "AI_EDITOR"
            });

            if !images.is_empty() {
                user_input["images"] = json!(images);
            }

            if !tool_results.is_empty() {
                user_input["userInputMessageContext"] = json!({
                    "toolResults": tool_results
                });
            }

            history.push(json!({ "userInputMessage": user_input }));
        } else if role == "assistant" {
            let content = if text.is_empty() { "(empty)" } else { text.as_str() };
            let mut assistant_msg = json!({ "content": content });
            if !tool_uses.is_empty() {
                assistant_msg["toolUses"] = json!(tool_uses);
            }
            history.push(json!({ "assistantResponseMessage": assistant_msg }));
        }
    }

    // 9. Build currentMessage - inject thinking tags only when fake reasoning is enabled
    let (_, current_text, _current_tool_uses, current_tool_results, current_images) = last;
    let current_content = if current_text.is_empty() {
        "Continue".to_string()
    } else if fake_reasoning.enabled {
        let max_thinking_tokens = request.thinking.as_ref()
            .and_then(|t| t.budget_tokens)
            .unwrap_or(fake_reasoning.max_tokens);
        inject_thinking_tags(&current_text, max_thinking_tokens)
    } else {
        current_text.clone()
    };

    let mut user_input_message = json!({
        "content": current_content,
        "modelId": &model_id,
        "origin": "AI_EDITOR"
    });

    if !current_images.is_empty() {
        user_input_message["images"] = json!(current_images);
    }

    // Build userInputMessageContext (tools + toolResults)
    let mut user_input_context = serde_json::Map::new();

    // Add tool specifications under "tools" key (NOT "toolSpecification")
    if let Some(tools) = &request.tools {
        let specs = build_tool_specifications(tools, TOOL_DESCRIPTION_MAX_LENGTH, &desc_overrides);
        if !specs.is_empty() {
            user_input_context.insert("tools".to_string(), json!(specs));
        }
    }

    // Add tool results if present
    if !current_tool_results.is_empty() {
        user_input_context.insert("toolResults".to_string(), json!(current_tool_results));
    }

    if !user_input_context.is_empty() {
        user_input_message["userInputMessageContext"] = Value::Object(user_input_context);
    }

    let current_message = json!({ "userInputMessage": user_input_message });

    // 10. Assemble final payload — conversationId required, no customizationArn, no profileArn
    let conversation_id = uuid::Uuid::new_v4().to_string();

    let mut conversation_state = json!({
        "chatTriggerType": "MANUAL",
        "conversationId": conversation_id,
        "currentMessage": current_message
    });

    let history = merge_adjacent_messages(history);

    if !history.is_empty() {
        conversation_state["history"] = json!(history);
    }

    let mut payload = json!({ "conversationState": conversation_state });

    if let Some(arn) = profile_arn {
        payload["profileArn"] = json!(arn);
    }

    // Slim payload if it exceeds size limits
    slim_kiro_payload(&mut payload);

    payload
}

/// Slim a Kiro payload to fit within the AWS Q request body limit (~128 KB).
///
/// The function addresses ALL oversized components, not just history:
///
/// Phase 1: Truncate oversized tool results (currentMessage.toolResults)
///          - Each tool result text is capped at MAX_TOOL_RESULT_CHARS
///          - This is often the biggest contributor (single tool result can be 70+ KB)
/// Phase 2: Truncate tool descriptions (currentMessage.tools[].description)
///          - Capped at SLIM_TOOL_DESC_MAX chars (shorter than build-time limit)
/// Phase 3: Trim conversation history
///          a. Message count limit (MAX_HISTORY_MESSAGES)
///          b. Progressively remove oldest messages until payload fits
/// Phase 4: As last resort, truncate large text in individual history messages
fn payload_size(payload: &Value) -> usize {
    serde_json::to_string(payload).map(|s| s.len()).unwrap_or(0)
}

fn slim_kiro_payload(payload: &mut Value) {
    let initial_size = payload_size(payload);
    if initial_size <= MAX_PAYLOAD_CHARS {
        return; // Already within budget
    }

    let mut actions: Vec<String> = Vec::new();

    // ===== Phase 1: Truncate tool results =====
    let tool_results_truncated = truncate_tool_results(payload, MAX_TOOL_RESULT_CHARS);
    if tool_results_truncated > 0 {
        actions.push(format!("truncated {} tool results", tool_results_truncated));
    }
    if payload_size(payload) <= MAX_PAYLOAD_CHARS {
        log_slim_result(initial_size, payload_size(payload), &actions);
        return;
    }

    // ===== Phase 2: Truncate tool descriptions =====
    let descs_truncated = truncate_tool_descriptions(payload, SLIM_TOOL_DESC_MAX);
    if descs_truncated > 0 {
        actions.push(format!("truncated {} tool descriptions", descs_truncated));
    }
    if payload_size(payload) <= MAX_PAYLOAD_CHARS {
        log_slim_result(initial_size, payload_size(payload), &actions);
        return;
    }

    // ===== Phase 3: Trim history =====
    let history_removed = trim_history(payload);
    if history_removed > 0 {
        actions.push(format!("removed {} history messages", history_removed));
    }

    // Repair orphan toolResults that can appear after history trimming.
    // If a user toolResult references a toolUseId that no longer exists in
    // preserved assistant history, Kiro may reject payload as malformed.
    let orphan_fixed = repair_orphan_tool_results_in_history(payload);
    if orphan_fixed > 0 {
        actions.push(format!("repaired {} orphan tool results", orphan_fixed));
    }

    if payload_size(payload) <= MAX_PAYLOAD_CHARS {
        log_slim_result(initial_size, payload_size(payload), &actions);
        return;
    }

    // ===== Phase 4: Truncate large text in remaining history messages =====
    let msgs_truncated = truncate_large_history_messages(payload, MAX_HISTORY_MSG_CHARS);
    if msgs_truncated > 0 {
        actions.push(format!("truncated {} large history messages", msgs_truncated));
    }

    log_slim_result(initial_size, payload_size(payload), &actions);
}

fn log_slim_result(initial: usize, final_size: usize, actions: &[String]) {
    let saved = initial.saturating_sub(final_size);
    let status = if final_size <= MAX_PAYLOAD_CHARS { "OK" } else { "STILL OVER" };
    warn!(
        "[Kiro] Payload slimmed [{}]: ~{} KB → ~{} KB (saved ~{} KB) | Actions: {}",
        status,
        initial / 1024,
        final_size / 1024,
        saved / 1024,
        actions.join(", ")
    );
}

/// Truncate each tool result's text content to max_chars.
/// Returns the number of results truncated.
fn truncate_tool_results(payload: &mut Value, max_chars: usize) -> usize {
    let results = match payload
        .pointer_mut("/conversationState/currentMessage/userInputMessage/userInputMessageContext/toolResults")
        .and_then(|v| v.as_array_mut())
    {
        Some(r) => r,
        None => return 0,
    };

    let mut count = 0;
    for result in results.iter_mut() {
        // Tool results can have content as string or array of {text: "..."}
        if let Some(content) = result.get_mut("content") {
            if let Some(arr) = content.as_array_mut() {
                for item in arr.iter_mut() {
                    if let Some(text) = item.get_mut("text").and_then(|t| t.as_str()).map(|s| s.to_string()) {
                        if text.len() > max_chars {
                            let truncated = format!(
                                "{}...\n\n[Content truncated: {} chars removed to fit API limits]",
                                &text[..max_chars],
                                text.len() - max_chars
                            );
                            item["text"] = json!(truncated);
                            count += 1;
                        }
                    }
                }
            } else if let Some(text) = content.as_str().map(|s| s.to_string()) {
                if text.len() > max_chars {
                    let truncated = format!(
                        "{}...\n\n[Content truncated: {} chars removed to fit API limits]",
                        &text[..max_chars],
                        text.len() - max_chars
                    );
                    *content = json!(truncated);
                    count += 1;
                }
            }
        }
    }

    // Also truncate tool results in history messages
    if let Some(history) = payload
        .pointer_mut("/conversationState/history")
        .and_then(|v| v.as_array_mut())
    {
        for msg in history.iter_mut() {
            // Check userInputMessage.userInputMessageContext.toolResults
            if let Some(results) = msg
                .pointer_mut("/userInputMessage/userInputMessageContext/toolResults")
                .and_then(|v| v.as_array_mut())
            {
                for result in results.iter_mut() {
                    if let Some(content) = result.get_mut("content") {
                        if let Some(arr) = content.as_array_mut() {
                            for item in arr.iter_mut() {
                                if let Some(text) = item.get_mut("text").and_then(|t| t.as_str()).map(|s| s.to_string()) {
                                    if text.len() > max_chars {
                                        let truncated = format!(
                                            "{}...\n\n[Content truncated: {} chars removed]",
                                            &text[..max_chars],
                                            text.len() - max_chars
                                        );
                                        item["text"] = json!(truncated);
                                        count += 1;
                                    }
                                }
                            }
                        } else if let Some(text) = content.as_str().map(|s| s.to_string()) {
                            if text.len() > max_chars {
                                let truncated = format!(
                                    "{}...\n\n[Content truncated: {} chars removed]",
                                    &text[..max_chars],
                                    text.len() - max_chars
                                );
                                *content = json!(truncated);
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    count
}

/// Truncate tool descriptions to max_chars.
/// Returns the number of descriptions truncated.
fn truncate_tool_descriptions(payload: &mut Value, max_chars: usize) -> usize {
    let tools = match payload
        .pointer_mut("/conversationState/currentMessage/userInputMessage/userInputMessageContext/tools")
        .and_then(|v| v.as_array_mut())
    {
        Some(t) => t,
        None => return 0,
    };

    let mut count = 0;
    for tool in tools.iter_mut() {
        if let Some(desc) = tool
            .pointer_mut("/toolSpecification/description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string())
        {
            if desc.len() > max_chars {
                tool["toolSpecification"]["description"] = json!(&desc[..max_chars]);
                count += 1;
            }
        }
    }
    count
}

/// Trim history messages: enforce count limit and remove oldest until payload fits.
/// Returns the number of messages removed.
fn trim_history(payload: &mut Value) -> usize {
    // Need total and history measurements
    let total_payload_size = serde_json::to_string(&*payload)
        .map(|s| s.len())
        .unwrap_or(0);

    let history = match payload
        .pointer_mut("/conversationState/history")
        .and_then(|v| v.as_array_mut())
    {
        Some(h) if h.len() > 2 => h,
        _ => return 0,
    };

    let original_len = history.len();
    let history_size = serde_json::to_string(history as &Vec<Value>)
        .map(|s| s.len())
        .unwrap_or(0);
    let non_history_overhead = total_payload_size.saturating_sub(history_size);
    let history_budget = MAX_PAYLOAD_CHARS.saturating_sub(non_history_overhead);

    // Enforce message count limit
    if history.len() > MAX_HISTORY_MESSAGES {
        let keep_front = 2;
        let keep_back = MAX_HISTORY_MESSAGES.saturating_sub(4);
        let remove_count = history.len().saturating_sub(keep_front + keep_back);
        if remove_count > 0 {
            history.drain(keep_front..keep_front + remove_count);
        }
    }

    // Progressively remove oldest until within budget
    let mut current_size = serde_json::to_string(history as &Vec<Value>)
        .map(|s| s.len())
        .unwrap_or(0);
    let keep_front = 2;
    while current_size > history_budget && history.len() > 4 {
        let remove = std::cmp::min(2, history.len() - 4);
        history.drain(keep_front..keep_front + remove);
        current_size = serde_json::to_string(history as &Vec<Value>)
            .map(|s| s.len())
            .unwrap_or(0);
    }

    let removed = original_len - history.len();
    if removed > 0 {
        // Insert synthetic summary at splice point
        let summary_msg = json!({
            "assistantResponseMessage": {
                "content": format!(
                    "[System: {} earlier messages were omitted to fit context window limits.]",
                    removed
                )
            }
        });
        let insert_pos = std::cmp::min(2, history.len());
        history.insert(insert_pos, summary_msg);

        if insert_pos + 1 < history.len() {
            let next_is_assistant = history[insert_pos + 1]
                .get("assistantResponseMessage")
                .is_some();
            if next_is_assistant {
                history.insert(
                    insert_pos + 1,
                    json!({
                        "userInputMessage": {
                            "content": "Continue",
                            "modelId": "claude-sonnet-4-20250514",
                            "origin": "AI_EDITOR"
                        }
                    }),
                );
            }
        }
    }
    removed
}

/// Truncate large text content within individual history messages.
/// Returns the number of messages truncated.
fn truncate_large_history_messages(payload: &mut Value, max_chars: usize) -> usize {
    let history = match payload
        .pointer_mut("/conversationState/history")
        .and_then(|v| v.as_array_mut())
    {
        Some(h) => h,
        _ => return 0,
    };

    let mut count = 0;
    for msg in history.iter_mut() {
        // Truncate user message content
        if let Some(content) = msg
            .pointer_mut("/userInputMessage/content")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
        {
            if content.len() > max_chars {
                msg["userInputMessage"]["content"] = json!(format!(
                    "{}...\n[truncated {} chars]",
                    &content[..max_chars],
                    content.len() - max_chars
                ));
                count += 1;
            }
        }
        // Truncate assistant message content
        if let Some(content) = msg
            .pointer_mut("/assistantResponseMessage/content")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
        {
            if content.len() > max_chars {
                msg["assistantResponseMessage"]["content"] = json!(format!(
                    "{}...\n[truncated {} chars]",
                    &content[..max_chars],
                    content.len() - max_chars
                ));
                count += 1;
            }
        }
    }
    count
}

/// Repair orphan tool results in history after trimming.
///
/// When history is trimmed, an assistant message containing `toolUses` can be
/// removed while a following user message still contains `toolResults` that
/// reference those removed toolUseIds. Kiro may reject this as malformed.
///
/// Strategy:
/// - Keep toolResults whose toolUseId exists in preserved assistant history.
/// - Convert orphan toolResults into plain text appended to user content.
/// - Remove empty toolResults/userInputMessageContext objects.
///
/// Returns number of orphan tool results repaired.
fn repair_orphan_tool_results_in_history(payload: &mut Value) -> usize {
    use std::collections::HashSet;

    let history = match payload
        .pointer_mut("/conversationState/history")
        .and_then(|v| v.as_array_mut())
    {
        Some(h) => h,
        None => return 0,
    };

    let mut seen_tool_use_ids: HashSet<String> = HashSet::new();
    let mut repaired_count = 0usize;

    for msg in history.iter_mut() {
        // Track toolUses from assistant messages
        if let Some(tool_uses) = msg
            .pointer("/assistantResponseMessage/toolUses")
            .and_then(|v| v.as_array())
        {
            for tool_use in tool_uses {
                if let Some(id) = tool_use.get("toolUseId").and_then(|v| v.as_str()) {
                    seen_tool_use_ids.insert(id.to_string());
                }
            }
        }

        // Repair orphan toolResults in user messages
        let Some(tool_results) = msg
            .pointer_mut("/userInputMessage/userInputMessageContext/toolResults")
            .and_then(|v| v.as_array_mut())
        else {
            continue;
        };

        let mut kept: Vec<Value> = Vec::new();
        let mut orphan_texts: Vec<String> = Vec::new();

        for result in tool_results.iter() {
            let tool_use_id = result
                .get("toolUseId")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if !tool_use_id.is_empty() && seen_tool_use_ids.contains(tool_use_id) {
                kept.push(result.clone());
                continue;
            }

            repaired_count += 1;

            let content_text = if let Some(content_arr) = result.get("content").and_then(|v| v.as_array()) {
                content_arr
                    .iter()
                    .filter_map(|c| c.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else if let Some(content_str) = result.get("content").and_then(|v| v.as_str()) {
                content_str.to_string()
            } else {
                result.to_string()
            };

            orphan_texts.push(format!(
                "[Recovered orphan tool_result for {}]\n{}",
                if tool_use_id.is_empty() { "unknown_tool_use_id" } else { tool_use_id },
                content_text
            ));
        }

        *tool_results = kept;

        if !orphan_texts.is_empty() {
            if let Some(user_input) = msg.get_mut("userInputMessage").and_then(|v| v.as_object_mut()) {
                let existing_content = user_input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let appended = orphan_texts.join("\n\n");
                let new_content = if existing_content.is_empty() || existing_content == "(empty)" {
                    appended
                } else {
                    format!("{}\n\n{}", existing_content, appended)
                };
                user_input.insert("content".to_string(), json!(new_content));

                // Remove empty toolResults / userInputMessageContext
                if let Some(ctx) = user_input
                    .get_mut("userInputMessageContext")
                    .and_then(|v| v.as_object_mut())
                {
                    if ctx
                        .get("toolResults")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.is_empty())
                        .unwrap_or(false)
                    {
                        ctx.remove("toolResults");
                    }
                    if ctx.is_empty() {
                        user_input.remove("userInputMessageContext");
                    }
                }
            }
        }
    }

    if repaired_count > 0 {
        warn!(
            "[Kiro] Repaired {} orphan toolResults in slimmed history",
            repaired_count
        );
    }

    repaired_count
}

// ===== AWS Event Stream Parser =====

/// Parsed event from Kiro's AWS event stream
#[derive(Debug)]
enum KiroEvent {
    TextDelta(String),
    ToolUseStart { name: String, tool_use_id: String },
    ToolInputDelta(String),
    ToolUseStop,
    Usage { input_tokens: u32, output_tokens: u32 },
    ContextUsage(f64),
    Unknown(#[allow(dead_code)] Value),
}

/// Parse JSON objects from an AWS event stream binary buffer.
/// AWS event stream embeds JSON payloads in binary frames.
/// We scan for JSON objects by matching braces.
///
/// Returns (events, consumed_bytes) — caller should drain consumed_bytes from the buffer
/// to preserve any incomplete JSON fragment at the tail for the next chunk.

fn parse_events_from_buffer(buffer: &[u8]) -> (Vec<KiroEvent>, usize) {
    // AWS event stream is a binary framing protocol. The raw bytes contain binary frame
    // headers/trailers with embedded JSON payloads. We cannot naively scan for '{' because
    // binary frame bytes may contain random '{' / '}' that confuse brace-matching.
    //
    // Strategy (matching Python kiro-gateway's AwsEventStreamParser):
    // 1. Strip non-UTF8 bytes (equivalent to Python's decode('utf-8', errors='ignore'))
    // 2. Search for known JSON pattern prefixes only
    // 3. Use brace-matching to extract complete JSON objects
    // 4. Track byte positions in the ORIGINAL buffer for correct draining

    // Known JSON event patterns from Kiro API (same as Python reference)
    const PATTERNS: &[&str] = &[
        "{\"content\":",
        "{\"name\":",
        "{\"input\":",
        "{\"stop\":",
        "{\"followupPrompt\":",
        "{\"usage\":",
        "{\"contextUsagePercentage\":",
    ];

    let mut events = Vec::new();

    // Build a "clean" UTF-8 string by skipping invalid bytes, while maintaining
    // a mapping from clean-string char index back to original buffer byte position.
    // This is equivalent to Python's `chunk.decode('utf-8', errors='ignore')`.
    let mut clean = String::new();
    let mut byte_map: Vec<usize> = Vec::new(); // byte_map[i] = original buffer position of clean[i]-th byte

    let mut i = 0;
    while i < buffer.len() {
        // Try to decode a valid UTF-8 character starting at position i
        let remaining = &buffer[i..];
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                // All remaining bytes are valid UTF-8
                for _byte in valid.bytes() {
                    byte_map.push(i);
                    i += 1;
                }
                clean.push_str(valid);
                break;
            }
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                if valid_up_to > 0 {
                    let valid_str = unsafe { std::str::from_utf8_unchecked(&remaining[..valid_up_to]) };
                    for _ in 0..valid_up_to {
                        byte_map.push(i);
                        i += 1;
                    }
                    clean.push_str(valid_str);
                }
                // Skip the invalid byte(s)
                match e.error_len() {
                    Some(len) => i += len,
                    None => break, // Incomplete sequence at end
                }
            }
        }
    }

    // Now search for known patterns in the clean string and extract JSON objects
    let mut search_pos = 0;
    let mut last_consumed_original_pos = 0;

    while search_pos < clean.len() {
        // Find the earliest known pattern
        let mut earliest_pos: Option<usize> = None;

        for pattern in PATTERNS {
            if let Some(pos) = clean[search_pos..].find(pattern) {
                let abs_pos = search_pos + pos;
                match earliest_pos {
                    None => earliest_pos = Some(abs_pos),
                    Some(ep) if abs_pos < ep => earliest_pos = Some(abs_pos),
                    _ => {}
                }
            }
        }

        let json_start = match earliest_pos {
            Some(pos) => pos,
            None => break, // No more patterns found
        };

        // Brace-match from json_start to find complete JSON object
        let chars: Vec<char> = clean[json_start..].chars().collect();
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escape_next = false;
        let mut json_end_char_offset: Option<usize> = None;

        for (ci, &ch) in chars.iter().enumerate() {
            if escape_next {
                escape_next = false;
                continue;
            }
            match ch {
                '\\' if in_string => escape_next = true,
                '"' => in_string = !in_string,
                '{' if !in_string => depth += 1,
                '}' if !in_string => {
                    depth -= 1;
                    if depth == 0 {
                        json_end_char_offset = Some(ci);
                        break;
                    }
                }
                _ => {}
            }
        }

        match json_end_char_offset {
            Some(end_offset) => {
                // Collect the JSON string
                let json_str: String = chars[..=end_offset].iter().collect();
                let json_byte_len_in_clean = json_str.len(); // byte length in clean string

                if let Ok(val) = serde_json::from_str::<Value>(&json_str) {
                    events.push(classify_kiro_event(val));
                }

                // Advance past this JSON in the clean string
                let end_clean_byte_pos = json_start + json_byte_len_in_clean;
                search_pos = end_clean_byte_pos;

                // Map back to original buffer position for draining
                if end_clean_byte_pos < byte_map.len() {
                    // The original byte position right after the last byte of this JSON
                    last_consumed_original_pos = byte_map[end_clean_byte_pos - 1] + 1;
                } else if !byte_map.is_empty() {
                    // We consumed up to the end of the clean string
                    last_consumed_original_pos = byte_map[byte_map.len() - 1] + 1;
                }
            }
            None => {
                // Incomplete JSON — stop here, preserve from current position
                break;
            }
        }
    }

    // If no events were found but we scanned past non-JSON binary data,
    // still advance past it so the buffer doesn't grow unbounded.
    // But only drain up to the start of the first unmatched pattern (or all if no patterns).
    if events.is_empty() && !clean.is_empty() {
        // Check if there's any pattern start in the remaining buffer
        let mut has_partial_pattern = false;
        for pattern in PATTERNS {
            // Check if any prefix of a pattern appears at the end of clean
            let pat_bytes = pattern.as_bytes();
            for prefix_len in 1..=pat_bytes.len().min(clean.len()) {
                if clean.as_bytes()[clean.len() - prefix_len..] == pat_bytes[..prefix_len] {
                    has_partial_pattern = true;
                    break;
                }
            }
            if has_partial_pattern {
                break;
            }
        }
        if !has_partial_pattern && !byte_map.is_empty() {
            // Safe to drain everything — no partial JSON pattern at the end
            last_consumed_original_pos = byte_map[byte_map.len() - 1] + 1;
        }
    }

    let consumed = last_consumed_original_pos.min(buffer.len());
    (events, consumed)
}


/// Classify a parsed JSON value into a KiroEvent

fn classify_kiro_event(val: Value) -> KiroEvent {
    // Check for stop signal
    if val.get("stop").and_then(|v| v.as_bool()).unwrap_or(false) {
        return KiroEvent::ToolUseStop;
    }

    // Check for usage
    if let Some(usage) = val.get("usage") {
        let input = usage
            .get("inputTokens")
            .or_else(|| usage.get("input_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let output = usage
            .get("outputTokens")
            .or_else(|| usage.get("output_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        return KiroEvent::Usage {
            input_tokens: input,
            output_tokens: output,
        };
    }

    // Check for context usage percentage
    if let Some(pct) = val.get("contextUsagePercentage").and_then(|v| v.as_f64()) {
        return KiroEvent::ContextUsage(pct);
    }

    // Check for tool input delta BEFORE tool use start.
    // Kiro API sends tool input deltas with "input" field, and they may also carry
    // "name" and "toolUseId". We must check for "input" first to avoid misclassifying
    // input deltas as tool use starts.
    if let Some(input) = val.get("input").and_then(|v| v.as_str()) {
        return KiroEvent::ToolInputDelta(input.to_string());
    }

    // Check for tool use start (has name + toolUseId, but NO "input" field)
    if let (Some(name), Some(tool_use_id)) = (
        val.get("name").and_then(|v| v.as_str()),
        val.get("toolUseId").and_then(|v| v.as_str()),
    ) {
        return KiroEvent::ToolUseStart {
            name: name.to_string(),
            tool_use_id: tool_use_id.to_string(),
        };
    }

    // Check for text content delta
    if let Some(content) = val.get("content").and_then(|v| v.as_str()) {
        return KiroEvent::TextDelta(content.to_string());
    }

    KiroEvent::Unknown(val)
}


// ===== Token Estimation =====
// Approximate token counting using char/4 heuristic with Claude correction factor.
// Claude tokenizes ~15% more than GPT-4 (cl100k_base) based on empirical observation.
// This matches the Python gateway's fallback when tiktoken is unavailable.

const CLAUDE_CORRECTION_FACTOR: f64 = 1.15;

const TOOL_DESCRIPTION_MAX_LENGTH: usize = 10000;

/// Maximum **total** payload size in bytes before history slimming kicks in.
/// AWS Q generateAssistantResponse has an undocumented request body limit (~128 KB).
/// We use 120 KB as the threshold, measuring the ENTIRE serialized payload
/// (history + tools + currentMessage + wrapper), not just the history portion.
const MAX_PAYLOAD_CHARS: usize = 120_000;

/// Maximum number of history messages to keep when slimming.
/// Even within size limits, extremely long histories can cause issues.
const MAX_HISTORY_MESSAGES: usize = 100;

/// Maximum chars per individual tool result content when slimming.
/// Tool results (e.g., file reads, bash output) can be 30-70 KB each.
const MAX_TOOL_RESULT_CHARS: usize = 8_000;

/// Stricter tool description length used during slim (vs TOOL_DESCRIPTION_MAX_LENGTH at build time).
/// At build time we allow 10,000 chars, but during slim we cut to 3,000 to reclaim space.
const SLIM_TOOL_DESC_MAX: usize = 3_000;

/// Maximum chars per individual history message text content during slim.
/// Prevents single messages from dominating the budget.
const MAX_HISTORY_MSG_CHARS: usize = 6_000;

/// First-token timeout: how long to wait for the first chunk before retrying.
/// Gateway uses 15-30s; 30s is a good balance for avoiding false timeouts.
const FIRST_TOKEN_TIMEOUT_SECS: u64 = 30;
/// Maximum number of transparent retries on first-token timeout.
/// Gateway uses 3 retries with shorter timeout instead of 1 retry with long timeout.
const FIRST_TOKEN_MAX_RETRIES: u32 = 3;

fn estimate_tokens(text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let base = (text.len() / 4).max(1);
    (base as f64 * CLAUDE_CORRECTION_FACTOR) as u32
}

fn estimate_request_tokens(request: &ClaudeRequest) -> u32 {
    let mut total: u32 = 0;

    if let Some(system) = &request.system {
        match system {
            SystemPrompt::String(s) => total += estimate_tokens(s),
            SystemPrompt::Array(blocks) => {
                for block in blocks {
                    total += estimate_tokens(&block.text);
                }
            }
        }
    }

    for msg in &request.messages {
        total += 4;
        match &msg.content {
            MessageContent::String(s) => total += estimate_tokens(s),
            MessageContent::Array(blocks) => {
                for block in blocks {
                    match block {
                        ContentBlock::Text { text } => total += estimate_tokens(text),
                        ContentBlock::Image { .. } => total += 100,
                        _ => total += 10,
                    }
                }
            }
        }
    }

    total += 3;
    total
}

// ===== Kiro Events → Anthropic SSE Conversion =====
// Matches Python kiro-gateway's streaming_anthropic.py behavior:
// - Tool calls are accumulated in the parser layer and emitted as complete blocks
// - stop_reason is "tool_use" when tool calls are present, "end_turn" otherwise

/// Accumulated tool call from Kiro stream events
struct PendingToolCall {
    name: String,
    tool_use_id: String,
    input_buffer: String,
}

/// State machine for converting Kiro events to Anthropic SSE
struct AnthropicSseBuilder {
    message_id: String,
    model: String,
    content_index: usize,
    in_text_block: bool,
    total_input_tokens: u32,
    total_output_tokens: u32,
    estimated_input_tokens: u32,
    output_char_count: usize,
    has_sent_message_start: bool,
    // Tool call accumulation (matches gateway's AwsEventStreamParser behavior)
    current_tool: Option<PendingToolCall>,
    completed_tools: Vec<PendingToolCall>,
    has_tool_calls: bool,
    thinking_parser: ThinkingParser,
    accumulated_text: String,
    thinking_block_index: Option<usize>,
    /// When true, thinking events are silently dropped (not emitted as SSE blocks)
    strip_thinking: bool,
}

impl AnthropicSseBuilder {
    fn new(model: &str, estimated_input_tokens: u32, strip_thinking: bool, open_tags: &[String]) -> Self {
        let thinking_parser = if open_tags.is_empty() {
            ThinkingParser::new()
        } else {
            ThinkingParser::with_tags(open_tags)
        };
        Self {
            message_id: format!("msg_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..24].to_string()),
            model: model.to_string(),
            content_index: 0,
            in_text_block: false,
            total_input_tokens: 0,
            total_output_tokens: 0,
            estimated_input_tokens,
            output_char_count: 0,
            has_sent_message_start: false,
            current_tool: None,
            completed_tools: Vec::new(),
            has_tool_calls: false,
            thinking_parser,
            accumulated_text: String::new(),
            thinking_block_index: None,
            strip_thinking,
        }
    }

    fn format_sse(event: &str, data: &Value) -> String {
        format!("event: {}\ndata: {}\n\n", event, serde_json::to_string(data).unwrap_or_default())
    }

    fn message_start(&mut self) -> String {
        if self.has_sent_message_start {
            return String::new();
        }
        self.has_sent_message_start = true;
        Self::format_sse(
            "message_start",
            &json!({
                "type": "message_start",
                "message": {
                    "id": self.message_id,
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": self.model,
                    "stop_reason": null,
                    "stop_sequence": null,
                    "usage": {
                        "input_tokens": self.estimated_input_tokens,
                        "output_tokens": 0
                    }
                }
            }),
        )
    }

    fn close_text_block(&mut self) -> String {
        let mut out = String::new();
        if self.in_text_block {
            out.push_str(&Self::format_sse(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": self.content_index}),
            ));
            self.content_index += 1;
            self.in_text_block = false;
        }
        out
    }

    /// Finalize current tool call and move to completed list
    fn finalize_current_tool(&mut self) {
        if let Some(tool) = self.current_tool.take() {
            self.completed_tools.push(tool);
        }
    }

    /// Emit all completed tool calls as Anthropic SSE blocks.
    /// Called during finalize() after the stream ends, matching gateway behavior
    /// where tool calls are emitted after all stream events are processed.
    fn emit_tool_blocks(&mut self) -> String {
        let mut out = String::new();
        let tools: Vec<PendingToolCall> = self.completed_tools.drain(..).collect();
        if !tools.is_empty() {
            self.has_tool_calls = true;
        }
        for tool in tools {
            // Parse accumulated input JSON, fall back to empty object
            let input_obj: Value = if tool.input_buffer.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&tool.input_buffer).unwrap_or(json!({}))
            };

            // content_block_start
            out.push_str(&Self::format_sse(
                "content_block_start",
                &json!({
                    "type": "content_block_start",
                    "index": self.content_index,
                    "content_block": {
                        "type": "tool_use",
                        "id": tool.tool_use_id,
                        "name": tool.name,
                        "input": {}
                    }
                }),
            ));

            // input_json_delta with complete input
            let input_json_str = serde_json::to_string(&input_obj).unwrap_or_else(|_| "{}".to_string());
            out.push_str(&Self::format_sse(
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": self.content_index,
                    "delta": {"type": "input_json_delta", "partial_json": input_json_str}
                }),
            ));

            // content_block_stop
            out.push_str(&Self::format_sse(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": self.content_index}),
            ));

            self.content_index += 1;
        }
        out
    }

    fn process_event(&mut self, event: KiroEvent) -> String {
        let mut out = String::new();

        // Ensure message_start is sent first
        out.push_str(&self.message_start());

        match event {
            KiroEvent::TextDelta(text) => {
                let events = self.thinking_parser.feed(&text);
                for tp_event in events {
                    match tp_event {
                        ThinkingEvent::ThinkingStart => {
                            if self.strip_thinking {
                                // Strip mode: silently drop thinking blocks
                                continue;
                            }
                            out.push_str(&self.close_text_block());
                            let sig = format!("sig_{}", uuid::Uuid::new_v4().simple());
                            out.push_str(&Self::format_sse(
                                "content_block_start",
                                &json!({
                                    "type": "content_block_start",
                                    "index": self.content_index,
                                    "content_block": {
                                        "type": "thinking",
                                        "thinking": "",
                                        "signature": sig
                                    }
                                }),
                            ));
                            self.thinking_block_index = Some(self.content_index);
                            self.content_index += 1;
                        }
                        ThinkingEvent::ThinkingDelta(thinking_text) => {
                            if self.strip_thinking {
                                continue;
                            }
                            if let Some(idx) = self.thinking_block_index {
                                out.push_str(&Self::format_sse(
                                    "content_block_delta",
                                    &json!({
                                        "type": "content_block_delta",
                                        "index": idx,
                                        "delta": {
                                            "type": "thinking_delta",
                                            "thinking": thinking_text
                                        }
                                    }),
                                ));
                            }
                        }
                        ThinkingEvent::ThinkingEnd => {
                            if self.strip_thinking {
                                continue;
                            }
                            if let Some(idx) = self.thinking_block_index {
                                out.push_str(&Self::format_sse(
                                    "content_block_stop",
                                    &json!({"type": "content_block_stop", "index": idx}),
                                ));
                                self.thinking_block_index = None;
                            }
                        }
                        ThinkingEvent::Text(regular_text) => {
                            self.accumulated_text.push_str(&regular_text);
                            if !self.in_text_block {
                                out.push_str(&Self::format_sse(
                                    "content_block_start",
                                    &json!({
                                        "type": "content_block_start",
                                        "index": self.content_index,
                                        "content_block": {"type": "text", "text": ""}
                                    }),
                                ));
                                self.in_text_block = true;
                            }
                            self.output_char_count += regular_text.len();
                            out.push_str(&Self::format_sse(
                                "content_block_delta",
                                &json!({
                                    "type": "content_block_delta",
                                    "index": self.content_index,
                                    "delta": {"type": "text_delta", "text": regular_text}
                                }),
                            ));
                        }
                    }
                }
            }

            KiroEvent::ToolUseStart { name, tool_use_id } => {
                // Close text block if open (text comes before tools)
                out.push_str(&self.close_text_block());

                // Finalize any previous tool call
                self.finalize_current_tool();

                // Start accumulating new tool call
                self.current_tool = Some(PendingToolCall {
                    name,
                    tool_use_id,
                    input_buffer: String::new(),
                });
            }

            KiroEvent::ToolInputDelta(partial_json) => {
                // Append to current tool's input buffer
                if let Some(ref mut tool) = self.current_tool {
                    tool.input_buffer.push_str(&partial_json);
                }
            }

            KiroEvent::ToolUseStop => {
                // Finalize current tool call
                self.finalize_current_tool();
            }

            KiroEvent::Usage {
                input_tokens,
                output_tokens,
            } => {
                self.total_input_tokens = input_tokens;
                self.total_output_tokens = output_tokens;
            }

            KiroEvent::ContextUsage(_pct) => {
                // Informational only, no SSE output needed
            }

            KiroEvent::Unknown(_) => {
                // Skip unknown events
            }
        }

        out
    }

    fn finalize(&mut self) -> String {
        let mut out = String::new();

        let flush_events = self.thinking_parser.flush();
        for tp_event in flush_events {
            match tp_event {
                ThinkingEvent::ThinkingDelta(text) => {
                    if let Some(idx) = self.thinking_block_index {
                        out.push_str(&Self::format_sse(
                            "content_block_delta",
                            &json!({
                                "type": "content_block_delta",
                                "index": idx,
                                "delta": {"type": "thinking_delta", "thinking": text}
                            }),
                        ));
                    }
                }
                ThinkingEvent::ThinkingEnd => {
                    if let Some(idx) = self.thinking_block_index {
                        out.push_str(&Self::format_sse(
                            "content_block_stop",
                            &json!({"type": "content_block_stop", "index": idx}),
                        ));
                        self.thinking_block_index = None;
                    }
                }
                ThinkingEvent::Text(text) => {
                    self.accumulated_text.push_str(&text);
                    if !self.in_text_block {
                        out.push_str(&Self::format_sse(
                            "content_block_start",
                            &json!({
                                "type": "content_block_start",
                                "index": self.content_index,
                                "content_block": {"type": "text", "text": ""}
                            }),
                        ));
                        self.in_text_block = true;
                    }
                    self.output_char_count += text.len();
                    out.push_str(&Self::format_sse(
                        "content_block_delta",
                        &json!({
                            "type": "content_block_delta",
                            "index": self.content_index,
                            "delta": {"type": "text_delta", "text": text}
                        }),
                    ));
                }
                _ => {}
            }
        }

        out.push_str(&self.close_text_block());

        if !self.accumulated_text.is_empty() {
            let bracket_tools = parse_bracket_tool_calls(&self.accumulated_text);
            for tool in bracket_tools {
                self.has_tool_calls = true;
                out.push_str(&Self::format_sse(
                    "content_block_start",
                    &json!({
                        "type": "content_block_start",
                        "index": self.content_index,
                        "content_block": {
                            "type": "tool_use",
                            "id": tool.tool_call_id,
                            "name": tool.name,
                            "input": {}
                        }
                    }),
                ));
                let input_str = serde_json::to_string(&tool.arguments).unwrap_or_else(|_| "{}".to_string());
                out.push_str(&Self::format_sse(
                    "content_block_delta",
                    &json!({
                        "type": "content_block_delta",
                        "index": self.content_index,
                        "delta": {"type": "input_json_delta", "partial_json": input_str}
                    }),
                ));
                out.push_str(&Self::format_sse(
                    "content_block_stop",
                    &json!({"type": "content_block_stop", "index": self.content_index}),
                ));
                self.content_index += 1;
            }
        }

        self.finalize_current_tool();

        out.push_str(&self.emit_tool_blocks());

        let input_tokens = if self.total_input_tokens > 0 {
            self.total_input_tokens
        } else {
            self.estimated_input_tokens
        };
        let output_tokens = if self.total_output_tokens > 0 {
            self.total_output_tokens
        } else {
            estimate_tokens(&"x".repeat(self.output_char_count))
        };

        self.total_input_tokens = input_tokens;
        self.total_output_tokens = output_tokens;

        // stop_reason: "tool_use" if tool calls were present, "end_turn" otherwise
        let stop_reason = if self.has_tool_calls { "tool_use" } else { "end_turn" };

        out.push_str(&Self::format_sse(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {
                    "stop_reason": stop_reason,
                    "stop_sequence": null
                },
                "usage": {
                    "output_tokens": output_tokens
                }
            }),
        ));

        out.push_str(&Self::format_sse(
            "message_stop",
            &json!({"type": "message_stop"}),
        ));

        // OpenAI-compatible [DONE] marker for broader client compatibility
        out.push_str("data: [DONE]\n\n");

        out
    }
}

// ===== Main Handler =====

pub async fn handle_kiro_messages(
    request: &ClaudeRequest,
    access_token: &str,
    email: &str,
    account_id: &str,
    trace_id: &str,
    region: &str,
    profile_arn: Option<&str>,
    concurrency_slot: ConcurrencySlot,
    token_manager: &crate::proxy::token_manager::TokenManager,
    original_model: Option<&str>,
    request_timeout_secs: u64,
    fake_reasoning: &crate::proxy::config::FakeReasoningConfig,
) -> Response {
    if has_unsupported_server_tools(request) {
        return error_response(
            StatusCode::BAD_REQUEST,
            AnthropicErrorType::InvalidRequestError,
            "web_search_20250305 is an Anthropic server tool and is not supported on the current Kiro upstream path",
        );
    }

    // Validate tool names early (reject > 64 chars with clear 400 error)
    if let Some(tools) = &request.tools {
        if let Err(msg) = validate_tool_names(tools) {
            return error_response(
                StatusCode::BAD_REQUEST,
                AnthropicErrorType::InvalidRequestError,
                &msg,
            );
        }
    }

    let fingerprint = get_machine_fingerprint();
    let kiro_host = get_kiro_q_host(region);
    let url = format!("{}/generateAssistantResponse", kiro_host);

    info!(
        "[{}] [Kiro] Routing to Kiro upstream | Account: {} | Region: {} | Model: {}",
        trace_id, email, region, request.model
    );

    // 1. Convert Anthropic request to Kiro payload
    let kiro_payload = convert_to_kiro_payload(request, profile_arn, fake_reasoning);

    // Determine whether to strip thinking blocks from SSE output
    let strip_thinking = !fake_reasoning.enabled || fake_reasoning.handling == "strip";
    let open_tags = fake_reasoning.open_tags.clone();

    debug!(
        "[{}] [Kiro] Payload: {}",
        trace_id,
        serde_json::to_string(&kiro_payload).unwrap_or_default()
    );

    // 2. Send request with retry logic (403 → refresh + retry, 429/5xx → exponential backoff)
    const MAX_RETRIES: usize = 3;
    const BASE_DELAY_MS: u64 = 1000;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(request_timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut current_token = access_token.to_string();

    let resp = 'retry: {
        for attempt in 0..MAX_RETRIES {
            let headers = get_kiro_headers(&current_token, &fingerprint);

            let send_result = client
                .post(&url)
                .headers(headers)
                .json(&kiro_payload)
                .send()
                .await;

            let response = match send_result {
                Ok(r) => r,
                Err(e) => {
                    if attempt < MAX_RETRIES - 1 {
                        let delay = BASE_DELAY_MS * (1 << attempt);
                        warn!("[{}] [Kiro] Request error (attempt {}/{}): {}, retrying in {}ms",
                            trace_id, attempt + 1, MAX_RETRIES, e, delay);
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                        continue;
                    }
                    let net_error = classify_network_error(&e);
                    error!("[{}] [Kiro] Request failed after {} attempts: {} (category: {:?})",
                        trace_id, MAX_RETRIES, e, net_error.category);
                    return error_response(
                        StatusCode::from_u16(net_error.suggested_http_status).unwrap_or(StatusCode::BAD_GATEWAY),
                        AnthropicErrorType::ApiError,
                        &net_error.user_message,
                    );
                }
            };

            let status = response.status();

            if status.is_success() {
                break 'retry response;
            }

            // 403 — token expired/invalid, force refresh and retry
            if status.as_u16() == 403 {
                let error_text = response.text().await.unwrap_or_default();
                warn!("[{}] [Kiro] Received 403 (attempt {}/{}): {}, refreshing token...",
                    trace_id, attempt + 1, MAX_RETRIES, error_text);

                if attempt < MAX_RETRIES - 1 {
                    let (rt, creds_file, sqlite_db) = token_manager
                        .get_refresh_inputs(account_id)
                        .await
                        .unwrap_or((String::new(), None, None));
                    let rt = rt.trim();
                    let rt_opt = if rt.is_empty() { None } else { Some(rt) };

                    match crate::modules::oauth::refresh_access_token_with_source(
                        rt_opt,
                        creds_file.as_deref(),
                        sqlite_db.as_deref(),
                        Some(account_id),
                    )
                    .await
                    {
                        Ok(token_response) => {
                            current_token = token_response.access_token.clone();
                            let _ = token_manager.sync_refreshed_token(account_id, &token_response).await;
                            info!("[{}] [Kiro] Token refreshed after 403, retrying...", trace_id);
                            continue;
                        }
                        Err(e) => {
                            error!("[{}] [Kiro] Token refresh failed after 403: {}", trace_id, e);
                        }
                    }
                }

                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    AnthropicErrorType::AuthenticationError,
                    &format!("Kiro API 403 (token invalid): {}", error_text),
                );
            }

            // 401 — bad credentials, force refresh and retry
            if status.as_u16() == 401 {
                let error_text = response.text().await.unwrap_or_default();
                warn!("[{}] [Kiro] Received 401 (attempt {}/{}): {}, refreshing token...",
                    trace_id, attempt + 1, MAX_RETRIES, error_text);

                if attempt < MAX_RETRIES - 1 {
                    let (rt, creds_file, sqlite_db) = token_manager
                        .get_refresh_inputs(account_id)
                        .await
                        .unwrap_or((String::new(), None, None));
                    let rt = rt.trim();
                    let rt_opt = if rt.is_empty() { None } else { Some(rt) };

                    match crate::modules::oauth::refresh_access_token_with_source(
                        rt_opt,
                        creds_file.as_deref(),
                        sqlite_db.as_deref(),
                        Some(account_id),
                    )
                    .await
                    {
                        Ok(token_response) => {
                            current_token = token_response.access_token.clone();
                            let _ = token_manager.sync_refreshed_token(account_id, &token_response).await;
                            info!("[{}] [Kiro] Token refreshed after 401, retrying...", trace_id);
                            continue;
                        }
                        Err(e) => {
                            error!("[{}] [Kiro] Token refresh failed after 401: {}", trace_id, e);
                        }
                    }
                }

                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    AnthropicErrorType::AuthenticationError,
                    &format!("Kiro API 401 (bad credentials): {}", error_text),
                );
            }

            // 429 — rate limited, prefer server-suggested delay over fixed backoff
            if status.as_u16() == 429 {
                let error_text = response.text().await.unwrap_or_default();
                if attempt < MAX_RETRIES - 1 {
                    // Try to extract server-suggested retry delay from error response
                    let delay = parse_retry_delay(&error_text)
                        .unwrap_or_else(|| BASE_DELAY_MS * (1 << attempt));
                    // Cap at 30 seconds to avoid excessively long waits
                    let delay = delay.min(30_000);
                    warn!("[{}] [Kiro] Received 429 (attempt {}/{}), waiting {}ms (server-suggested: {})...",
                        trace_id, attempt + 1, MAX_RETRIES, delay,
                        parse_retry_delay(&error_text).map(|d| format!("{}ms", d)).unwrap_or_else(|| "none".to_string()));
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                    continue;
                }
                error!(
                    "[{}] [Kiro] 429 Rate Limited - Payload: {} | Response: {}",
                    trace_id,
                    serde_json::to_string(&kiro_payload).unwrap_or_default(),
                    error_text
                );
                return error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    AnthropicErrorType::RateLimitError,
                    &format!("Kiro API rate limited: {}", error_text),
                );
            }

            // 5xx — server error, exponential backoff
            if status.as_u16() >= 500 {
                let error_text = response.text().await.unwrap_or_default();
                if attempt < MAX_RETRIES - 1 {
                    let delay = BASE_DELAY_MS * (1 << attempt);
                    warn!("[{}] [Kiro] Received {} (attempt {}/{}), waiting {}ms...",
                        trace_id, status.as_u16(), attempt + 1, MAX_RETRIES, delay);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                    continue;
                }
                error!(
                    "[{}] [Kiro] {} Server Error - Payload: {} | Response: {}",
                    trace_id,
                    status.as_u16(),
                    serde_json::to_string(&kiro_payload).unwrap_or_default(),
                    error_text
                );
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    AnthropicErrorType::ApiError,
                    &format!("Kiro API error ({}): {}", status.as_u16(), error_text),
                );
            }

            // Other errors — attempt to parse Kiro error body and map to user-friendly message
            let error_text = response.text().await.unwrap_or_default();

            // Log payload for 400 and other errors
            if status.as_u16() == 400 {
                let payload_str = serde_json::to_string(&kiro_payload).unwrap_or_default();
                let payload_size = payload_str.len();
                error!(
                    "[{}] [Kiro] 400 Bad Request (payload: {} bytes) - Response: {}",
                    trace_id,
                    payload_size,
                    error_text
                );
                // Save first failing payload for debugging
                let debug_path = format!("/tmp/kiro_failed_payload_{}.json", trace_id);
                if let Ok(mut f) = std::fs::File::create(&debug_path) {
                    let _ = std::io::Write::write_all(&mut f, payload_str.as_bytes());
                    warn!("[{}] [Kiro] Saved failing payload to {}", trace_id, debug_path);
                }
            } else {
                error!(
                    "[{}] [Kiro] {} Error - Payload: {} | Response: {}",
                    trace_id,
                    status.as_u16(),
                    serde_json::to_string(&kiro_payload).unwrap_or_default(),
                    error_text
                );
            }

            // Try to extract reason code from Kiro error JSON
            let error_info = if let Ok(err_json) = serde_json::from_str::<Value>(&error_text) {
                let reason_code = err_json.get("reasonCode")
                    .or_else(|| err_json.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");
                let raw_message = err_json.get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&error_text);
                map_kiro_error(reason_code, raw_message)
            } else {
                map_kiro_error("UNKNOWN", &error_text)
            };

            return error_response(
                StatusCode::from_u16(error_info.http_status).unwrap_or(StatusCode::BAD_GATEWAY),
                match error_info.anthropic_error_type.as_str() {
                    "invalid_request_error" => AnthropicErrorType::InvalidRequestError,
                    "rate_limit_error" => AnthropicErrorType::RateLimitError,
                    "authentication_error" => AnthropicErrorType::AuthenticationError,
                    "overloaded_error" => AnthropicErrorType::OverloadedError,
                    _ => AnthropicErrorType::ApiError,
                },
                &error_info.user_message,
            );
        }

        // Should not reach here, but just in case
        return error_response(
            StatusCode::BAD_GATEWAY,
            AnthropicErrorType::ApiError,
            "Kiro upstream request failed after all retries",
        );
    };

    // 4. Stream the response — parse AWS event stream and convert to Anthropic SSE
    let model = request.model.clone();
    let routed_model_for_header = request.model.clone();
    let trace_id_owned = trace_id.to_string();
    let estimated_input = estimate_request_tokens(request);

    if request.stream {
        let retry_client = client.clone();
        let retry_url = url.clone();
        let retry_payload = kiro_payload.clone();
        let retry_token = current_token.clone();
        let retry_fingerprint = fingerprint.clone();

        let sse_stream = async_stream::stream! {
            let _slot_guard = concurrency_slot;

            let mut builder = AnthropicSseBuilder::new(&model, estimated_input, strip_thinking, &open_tags);
            let mut buffer = BytesMut::new();
            let mut chunk_count: usize = 0;
            let mut total_bytes: usize = 0;

            let mut retry_count = 0u32;
            let max_retries = FIRST_TOKEN_MAX_RETRIES;
            let timeout_duration = tokio::time::Duration::from_secs(FIRST_TOKEN_TIMEOUT_SECS);

            let mut byte_stream: std::pin::Pin<Box<dyn futures::Stream<Item = Result<Bytes, reqwest::Error>> + Send>> =
                Box::pin(resp.bytes_stream());

            let got_first_token = 'first_token: loop {
                match tokio::time::timeout(timeout_duration, byte_stream.next()).await {
                    Ok(Some(Ok(first_chunk))) => {
                        chunk_count += 1;
                        total_bytes += first_chunk.len();
                        buffer.extend_from_slice(&first_chunk);

                        let (events, consumed) = parse_events_from_buffer(&buffer);
                        if consumed > 0 {
                            let _ = buffer.split_to(consumed);
                        }
                        for event in events {
                            let sse_text = builder.process_event(event);
                            if !sse_text.is_empty() {
                                yield Ok::<Bytes, std::io::Error>(Bytes::from(sse_text));
                            }
                        }

                        break 'first_token true;
                    }
                    Ok(Some(Err(e))) => {
                        warn!("[{}] [Kiro] First chunk stream error: {}", trace_id_owned, e);
                        break 'first_token false;
                    }
                    Ok(None) => {
                        break 'first_token false;
                    }
                    Err(_) => {
                        retry_count += 1;
                        if retry_count > max_retries {
                            warn!("[{}] [Kiro] First token timeout after {} retries", trace_id_owned, max_retries);
                            yield Ok::<Bytes, std::io::Error>(Bytes::from(
                                AnthropicSseBuilder::format_sse("error", &json!({
                                    "type": "error",
                                    "error": {"type": "api_error", "message": "First token timeout after retries"}
                                }))
                            ));
                            return;
                        }
                        warn!("[{}] [Kiro] First token timeout (attempt {}/{}), retrying...",
                            trace_id_owned, retry_count, max_retries);

                        let headers = get_kiro_headers(&retry_token, &retry_fingerprint);
                        match retry_client.post(&retry_url).headers(headers).json(&retry_payload).send().await {
                            Ok(new_resp) if new_resp.status().is_success() => {
                                byte_stream = Box::pin(new_resp.bytes_stream());
                                continue 'first_token;
                            }
                            Ok(new_resp) => {
                                warn!("[{}] [Kiro] Retry request returned status {}", trace_id_owned, new_resp.status());
                                byte_stream = Box::pin(new_resp.bytes_stream());
                                break 'first_token false;
                            }
                            Err(e) => {
                                warn!("[{}] [Kiro] Retry request failed: {}", trace_id_owned, e);
                                break 'first_token false;
                            }
                        }
                    }
                }
            };

            if got_first_token {
                while let Some(chunk_result) = byte_stream.next().await {
                    match chunk_result {
                        Ok(chunk) => {
                            chunk_count += 1;
                            total_bytes += chunk.len();
                            buffer.extend_from_slice(&chunk);

                            let (events, consumed) = parse_events_from_buffer(&buffer);
                            if consumed > 0 {
                                let _ = buffer.split_to(consumed);
                            }

                            for event in events {
                                let sse_text = builder.process_event(event);
                                if !sse_text.is_empty() {
                                    yield Ok::<Bytes, std::io::Error>(Bytes::from(sse_text));
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[{}] [Kiro] Stream chunk error after {} chunks ({} bytes): {}", trace_id_owned, chunk_count, total_bytes, e);
                            break;
                        }
                    }
                }
            }

            info!("[{}] [Kiro] Stream ended normally after {} chunks, {} bytes, {} chars output",
                trace_id_owned, chunk_count, total_bytes, builder.output_char_count);

            let final_sse = builder.finalize();
            if !final_sse.is_empty() {
                yield Ok::<Bytes, std::io::Error>(Bytes::from(final_sse));
            }

            info!("[{}] [Kiro] SSE stream finalized, concurrency slot will be released", trace_id_owned);
        };

        let mut resp_builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::CONNECTION, "keep-alive")
            .header("X-Accel-Buffering", "no")
            .header("X-Account-Email", email)
            .header("X-Kiro-Upstream", "true");
        if original_model.is_some() {
            resp_builder = resp_builder.header("X-Original-Model", original_model.unwrap_or_default());
            resp_builder = resp_builder.header("X-Mapped-Model", &routed_model_for_header);
        }
        resp_builder
            .body(Body::from_stream(sse_stream))
            .unwrap()
    } else {
        // Non-streaming mode: collect full response and return as JSON
        let body_bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                error!("[{}] [Kiro] Failed to read response body: {}", trace_id, e);
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    AnthropicErrorType::ApiError,
                    &format!("Failed to read Kiro response: {}", e),
                );
            }
        };

        let (events, _consumed) = parse_events_from_buffer(&body_bytes);
        let mut builder = AnthropicSseBuilder::new(&model, estimated_input, strip_thinking, &open_tags);

        let mut text_parts = Vec::new();
        let mut content_blocks: Vec<Value> = Vec::new();

        for event in events {
            match &event {
                KiroEvent::TextDelta(t) => text_parts.push(t.clone()),
                KiroEvent::Usage { input_tokens, output_tokens } => {
                    builder.total_input_tokens = *input_tokens;
                    builder.total_output_tokens = *output_tokens;
                }
                _ => {}
            }
            // Process for side effects (token counting)
            let _ = builder.process_event(event);
        }

        // Build content blocks
        if !text_parts.is_empty() {
            content_blocks.push(json!({"type": "text", "text": text_parts.join("")}));
        }

        let input_tokens = if builder.total_input_tokens > 0 {
            builder.total_input_tokens
        } else {
            builder.estimated_input_tokens
        };
        let output_tokens = if builder.total_output_tokens > 0 {
            builder.total_output_tokens
        } else {
            estimate_tokens(&"x".repeat(builder.output_char_count))
        };

        let response_json = json!({
            "id": builder.message_id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": content_blocks,
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens
            }
        });

        let mut resp_builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-Account-Email", email)
            .header("X-Kiro-Upstream", "true");
        if original_model.is_some() {
            resp_builder = resp_builder.header("X-Original-Model", original_model.unwrap_or_default());
            resp_builder = resp_builder.header("X-Mapped-Model", &routed_model_for_header);
        }
        resp_builder
            .body(Body::from(serde_json::to_string(&response_json).unwrap()))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Property 3: SSE Thinking block output format
    #[test]
    fn prop_sse_thinking_block_format() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, false, &[]);
        let out = builder.process_event(KiroEvent::TextDelta(
            "<thinking>test content</thinking>normal text".to_string(),
        ));
        let final_out = builder.finalize();
        let combined = format!("{}{}", out, final_out);

        assert!(
            combined.contains("\"type\":\"thinking\"")
                || combined.contains("\"type\": \"thinking\"")
        );
        assert!(combined.contains("thinking_delta"));
        assert!(combined.contains("content_block_stop"));
        assert!(combined.contains("normal text"));
    }

    // Property 6: Truncation recovery message injection
    #[test]
    fn prop_truncation_recovery_message_format() {
        use crate::proxy::upstream::truncation::{
            generate_content_truncation_message, generate_tool_truncation_message,
        };
        let tool_msg = generate_tool_truncation_message("tool_123", "Write");
        assert!(tool_msg.contains("[API Limitation]"));
        assert!(tool_msg.contains("truncated"));

        let content_msg = generate_content_truncation_message();
        assert!(content_msg.contains("[System Notice]"));
        assert!(content_msg.contains("truncated"));
    }

    // Property 12: Tool description truncation
    #[test]
    fn prop_tool_description_truncation() {
        use crate::proxy::mappers::claude::models::Tool;
        let long_desc = "a".repeat(5000);
        let tools = vec![Tool {
            type_: None,
            name: Some("test_tool".to_string()),
            description: Some(long_desc.clone()),
            input_schema: Some(json!({"type": "object"})),
        }];
        let no_overrides: Vec<(String, String)> = vec![];
        let specs = build_tool_specifications(&tools, 4096, &no_overrides);
        let spec = &specs[0];
        let desc = spec["toolSpecification"]["description"].as_str().unwrap();
        assert_eq!(desc.len(), 4096);

        let short_tools = vec![Tool {
            type_: None,
            name: Some("test_tool".to_string()),
            description: Some("short desc".to_string()),
            input_schema: Some(json!({"type": "object"})),
        }];
        let specs2 = build_tool_specifications(&short_tools, 4096, &no_overrides);
        let desc2 = specs2[0]["toolSpecification"]["description"]
            .as_str()
            .unwrap();
        assert_eq!(desc2, "short desc");
    }

    #[test]
    fn test_has_unsupported_server_tools() {
        use crate::proxy::mappers::claude::models::Tool;

        let request = ClaudeRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            messages: vec![],
            max_tokens: Some(256),
            system: None,
            tools: Some(vec![Tool {
                type_: Some("web_search_20250305".to_string()),
                name: Some("web_search".to_string()),
                description: None,
                input_schema: None,
            }]),
            stream: false,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
            size: None,
            quality: None,
        };

        assert!(has_unsupported_server_tools(&request));
    }

    // Property 13: Image content conversion
    #[test]
    fn prop_image_content_in_extract_text() {
        use crate::proxy::mappers::claude::models::{ImageSource, MessageContent};
        let content = MessageContent::Array(vec![
            ContentBlock::Text {
                text: "before".to_string(),
            },
            ContentBlock::Image {
                source: ImageSource {
                    source_type: "base64".to_string(),
                    media_type: "image/png".to_string(),
                    data: "abc123".to_string(),
                },
                cache_control: None,
            },
            ContentBlock::Text {
                text: "after".to_string(),
            },
        ]);
        let text = extract_text(&content);
        assert!(text.contains("before"));
        assert!(text.contains("after"));
        assert!(text.contains("image/png"));
    }

    #[test]
    fn test_merge_adjacent_messages() {
        let messages = vec![
            serde_json::json!({"userInputMessage": {"content": "hello", "modelId": "m", "origin": "AI_EDITOR"}}),
            serde_json::json!({"userInputMessage": {"content": "world", "modelId": "m", "origin": "AI_EDITOR"}}),
            serde_json::json!({"assistantResponseMessage": {"content": "hi"}}),
            serde_json::json!({"assistantResponseMessage": {"content": "there"}}),
            serde_json::json!({"userInputMessage": {"content": "bye", "modelId": "m", "origin": "AI_EDITOR"}}),
        ];
        let merged = merge_adjacent_messages(messages);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0]["userInputMessage"]["content"], "hello\nworld");
        assert_eq!(merged[1]["assistantResponseMessage"]["content"], "hi\nthere");
        assert_eq!(merged[2]["userInputMessage"]["content"], "bye");
    }

    #[test]
    fn test_merge_adjacent_empty() {
        let merged = merge_adjacent_messages(vec![]);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_adjacent_no_merges() {
        let messages = vec![
            serde_json::json!({"userInputMessage": {"content": "a", "modelId": "m", "origin": "AI_EDITOR"}}),
            serde_json::json!({"assistantResponseMessage": {"content": "b"}}),
            serde_json::json!({"userInputMessage": {"content": "c", "modelId": "m", "origin": "AI_EDITOR"}}),
        ];
        let merged = merge_adjacent_messages(messages);
        assert_eq!(merged.len(), 3);
    }

    // Property 21: Incomplete stream truncation detection
    #[test]
    fn prop_incomplete_stream_truncation() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, false, &[]);
        let _ = builder.process_event(KiroEvent::ToolUseStart {
            name: "test_tool".to_string(),
            tool_use_id: "tool_123".to_string(),
        });
        let _ = builder.process_event(KiroEvent::ToolInputDelta(
            "{\"key\":\"value\"}".to_string(),
        ));
        let final_out = builder.finalize();

        assert!(builder.has_tool_calls);
        assert!(final_out.contains("tool_use"));
        assert!(final_out.contains("test_tool"));
    }

    #[test]
    fn test_strip_tool_content_no_tools() {
        let messages = vec![
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::Text { text: "I'll help.".to_string() },
                    ContentBlock::ToolUse {
                        id: "tu_1".to_string(),
                        name: "read_file".to_string(),
                        input: json!({"path": "/tmp/x"}),
                        signature: None,
                        cache_control: None,
                    },
                ]),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "tu_1".to_string(),
                        content: Value::String("file contents".to_string()),
                        is_error: Some(false),
                    },
                ]),
            },
        ];

        let stripped = strip_all_tool_content(&messages);
        assert_eq!(stripped.len(), 2);

        if let MessageContent::Array(blocks) = &stripped[0].content {
            assert!(blocks.iter().all(|b| matches!(b, ContentBlock::Text { .. })));
            let texts: Vec<&str> = blocks.iter().filter_map(|b| match b {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            }).collect();
            assert!(texts[0].contains("I'll help."));
            assert!(texts[1].contains("read_file"));
        } else {
            panic!("expected Array content");
        }

        if let MessageContent::Array(blocks) = &stripped[1].content {
            assert!(blocks.iter().all(|b| matches!(b, ContentBlock::Text { .. })));
            let text = match &blocks[0] {
                ContentBlock::Text { text } => text.as_str(),
                _ => panic!("expected text"),
            };
            assert!(text.contains("tu_1"));
            assert!(text.contains("file contents"));
        } else {
            panic!("expected Array content");
        }
    }

    #[test]
    fn test_ensure_assistant_before_tool_results() {
        let messages = vec![
            Message {
                role: "user".to_string(),
                content: MessageContent::String("hello".to_string()),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "tu_orphan".to_string(),
                        content: Value::String("orphaned result".to_string()),
                        is_error: Some(false),
                    },
                ]),
            },
        ];

        let fixed = ensure_assistant_before_tool_results(&messages);
        assert_eq!(fixed.len(), 2);

        if let MessageContent::Array(blocks) = &fixed[1].content {
            assert!(blocks.iter().all(|b| matches!(b, ContentBlock::Text { .. })));
            let text = match &blocks[0] {
                ContentBlock::Text { text } => text.as_str(),
                _ => panic!("expected text"),
            };
            assert!(text.contains("tu_orphan"));
            assert!(text.contains("orphaned result"));
        } else {
            panic!("expected Array content");
        }

        let messages_valid = vec![
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::ToolUse {
                        id: "tu_valid".to_string(),
                        name: "run".to_string(),
                        input: json!({}),
                        signature: None,
                        cache_control: None,
                    },
                ]),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "tu_valid".to_string(),
                        content: Value::String("ok".to_string()),
                        is_error: Some(false),
                    },
                ]),
            },
        ];

        let kept = ensure_assistant_before_tool_results(&messages_valid);
        assert_eq!(kept.len(), 2);
        if let MessageContent::Array(blocks) = &kept[1].content {
            assert!(blocks.iter().any(|b| matches!(b, ContentBlock::ToolResult { .. })));
        } else {
            panic!("expected Array content");
        }
    }

    #[test]
    fn test_normalize_roles() {
        let mut tuples = vec![
            ("system".to_string(), "sys prompt".to_string(), vec![], vec![], vec![]),
            ("user".to_string(), "hello".to_string(), vec![], vec![], vec![]),
            ("assistant".to_string(), "hi".to_string(), vec![], vec![], vec![]),
            ("developer".to_string(), "dev msg".to_string(), vec![], vec![], vec![]),
            ("tool".to_string(), "tool msg".to_string(), vec![], vec![], vec![]),
        ];

        normalize_message_roles(&mut tuples);

        assert_eq!(tuples[0].0, "user");
        assert_eq!(tuples[1].0, "user");
        assert_eq!(tuples[2].0, "assistant");
        assert_eq!(tuples[3].0, "user");
        assert_eq!(tuples[4].0, "user");
    }

    // ===== New tests: sanitize_json_schema =====

    #[test]
    fn test_sanitize_json_schema_removes_additional_properties() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            },
            "additionalProperties": false
        });
        sanitize_json_schema(&mut schema);
        assert!(schema.get("additionalProperties").is_none());
        // properties should be unchanged
        assert!(schema["properties"]["name"]["type"].as_str() == Some("string"));
    }

    #[test]
    fn test_sanitize_json_schema_removes_empty_required() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "x": { "type": "number" }
            },
            "required": []
        });
        sanitize_json_schema(&mut schema);
        assert!(schema.get("required").is_none());
    }

    #[test]
    fn test_sanitize_json_schema_keeps_nonempty_required() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "x": { "type": "number" }
            },
            "required": ["x"]
        });
        sanitize_json_schema(&mut schema);
        assert!(schema.get("required").is_some());
        assert_eq!(schema["required"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_sanitize_json_schema_recursive() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "additionalProperties": true,
                    "required": [],
                    "properties": {
                        "deep": {
                            "type": "object",
                            "additionalProperties": false
                        }
                    }
                }
            },
            "additionalProperties": false,
            "required": []
        });
        sanitize_json_schema(&mut schema);

        // Top level
        assert!(schema.get("additionalProperties").is_none());
        assert!(schema.get("required").is_none());
        // Nested level
        let nested = &schema["properties"]["nested"];
        assert!(nested.get("additionalProperties").is_none());
        assert!(nested.get("required").is_none());
        // Deep level
        let deep = &nested["properties"]["deep"];
        assert!(deep.get("additionalProperties").is_none());
    }

    #[test]
    fn test_sanitize_json_schema_anyof() {
        let mut schema = json!({
            "anyOf": [
                { "type": "string", "additionalProperties": false },
                { "type": "object", "required": [], "additionalProperties": true }
            ]
        });
        sanitize_json_schema(&mut schema);
        for variant in schema["anyOf"].as_array().unwrap() {
            assert!(variant.get("additionalProperties").is_none());
            assert!(variant.get("required").is_none() || !variant["required"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn test_sanitize_json_schema_items() {
        let mut schema = json!({
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": []
            }
        });
        sanitize_json_schema(&mut schema);
        let items = &schema["items"];
        assert!(items.get("additionalProperties").is_none());
        assert!(items.get("required").is_none());
    }

    // ===== New tests: sanitize_tool_name =====

    #[test]
    fn test_sanitize_tool_name_strips_dollar() {
        assert_eq!(sanitize_tool_name("$bash"), Some("bash".to_string()));
        assert_eq!(sanitize_tool_name("normal"), Some("normal".to_string()));
    }

    #[test]
    fn test_sanitize_tool_name_truncates_long_names() {
        let long_name = "a".repeat(100);
        let result = sanitize_tool_name(&long_name).unwrap();
        assert_eq!(result.len(), TOOL_NAME_MAX_LENGTH);
    }

    #[test]
    fn test_sanitize_tool_name_empty_after_strip() {
        assert_eq!(sanitize_tool_name("$"), None);
        assert_eq!(sanitize_tool_name(""), None);
    }

    // ===== New tests: validate_tool_names =====

    #[test]
    fn test_validate_tool_names_ok() {
        use crate::proxy::mappers::claude::models::Tool;
        let tools = vec![
            Tool {
                type_: None,
                name: Some("read_file".to_string()),
                description: Some("Read a file".to_string()),
                input_schema: Some(json!({})),
            },
        ];
        assert!(validate_tool_names(&tools).is_ok());
    }

    #[test]
    fn test_validate_tool_names_too_long() {
        use crate::proxy::mappers::claude::models::Tool;
        let tools = vec![
            Tool {
                type_: None,
                name: Some("a".repeat(100)),
                description: Some("desc".to_string()),
                input_schema: Some(json!({})),
            },
        ];
        let result = validate_tool_names(&tools);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds"));
    }

    #[test]
    fn test_validate_tool_names_dollar_prefix_still_validated() {
        use crate::proxy::mappers::claude::models::Tool;
        // $+63 chars = 64 without $ : should pass
        let tools = vec![
            Tool {
                type_: None,
                name: Some(format!("${}", "a".repeat(64))),
                description: Some("desc".to_string()),
                input_schema: Some(json!({})),
            },
        ];
        assert!(validate_tool_names(&tools).is_ok());

        // $+65 chars = 65 without $ : should fail
        let tools2 = vec![
            Tool {
                type_: None,
                name: Some(format!("${}", "a".repeat(65))),
                description: Some("desc".to_string()),
                input_schema: Some(json!({})),
            },
        ];
        assert!(validate_tool_names(&tools2).is_err());
    }

    // ===== New tests: process_long_tool_descriptions =====

    #[test]
    fn test_process_long_descriptions_no_long() {
        use crate::proxy::mappers::claude::models::Tool;
        let tools = vec![
            Tool {
                type_: None,
                name: Some("test".to_string()),
                description: Some("short desc".to_string()),
                input_schema: Some(json!({})),
            },
        ];
        let (overrides, system_text) = process_long_tool_descriptions(&tools);
        assert!(overrides.is_empty());
        assert!(system_text.is_empty());
    }

    #[test]
    fn test_process_long_descriptions_moves_to_system() {
        use crate::proxy::mappers::claude::models::Tool;
        let long_desc = "x".repeat(LONG_DESC_THRESHOLD + 100);
        let tools = vec![
            Tool {
                type_: None,
                name: Some("big_tool".to_string()),
                description: Some(long_desc.clone()),
                input_schema: Some(json!({})),
            },
            Tool {
                type_: None,
                name: Some("small_tool".to_string()),
                description: Some("short".to_string()),
                input_schema: Some(json!({})),
            },
        ];
        let (overrides, system_text) = process_long_tool_descriptions(&tools);

        // Only the big_tool should have an override
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].0, "big_tool");
        assert!(overrides[0].1.contains("See full documentation"));
        assert!(overrides[0].1.contains("big_tool"));

        // System text should contain the full tool documentation
        assert!(system_text.contains("## Tool: big_tool"));
        assert!(system_text.contains(&long_desc));
    }

    // ===== New tests: build_tool_specifications with sanitization =====

    #[test]
    fn test_build_tool_specs_sanitizes_schema() {
        use crate::proxy::mappers::claude::models::Tool;
        let tools = vec![Tool {
            type_: None,
            name: Some("my_tool".to_string()),
            description: Some("A tool".to_string()),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "arg": { "type": "string", "additionalProperties": false }
                },
                "additionalProperties": false,
                "required": []
            })),
        }];
        let no_overrides: Vec<(String, String)> = vec![];
        let specs = build_tool_specifications(&tools, 10000, &no_overrides);
        let schema = &specs[0]["toolSpecification"]["inputSchema"]["json"];

        // additionalProperties should be removed at all levels
        assert!(schema.get("additionalProperties").is_none());
        assert!(schema["properties"]["arg"].get("additionalProperties").is_none());
        // empty required should be removed
        assert!(schema.get("required").is_none());
    }

    #[test]
    fn test_build_tool_specs_sanitizes_dollar_name() {
        use crate::proxy::mappers::claude::models::Tool;
        let tools = vec![Tool {
            type_: None,
            name: Some("$bash".to_string()),
            description: Some("Run bash".to_string()),
            input_schema: Some(json!({})),
        }];
        let no_overrides: Vec<(String, String)> = vec![];
        let specs = build_tool_specifications(&tools, 10000, &no_overrides);
        let name = specs[0]["toolSpecification"]["name"].as_str().unwrap();
        assert_eq!(name, "bash");
    }

    #[test]
    fn test_build_tool_specs_applies_desc_overrides() {
        use crate::proxy::mappers::claude::models::Tool;
        let tools = vec![Tool {
            type_: None,
            name: Some("my_tool".to_string()),
            description: Some("Original very long description".to_string()),
            input_schema: Some(json!({})),
        }];
        let overrides = vec![
            ("my_tool".to_string(), "Short reference".to_string()),
        ];
        let specs = build_tool_specifications(&tools, 10000, &overrides);
        let desc = specs[0]["toolSpecification"]["description"].as_str().unwrap();
        assert_eq!(desc, "Short reference");
    }

    #[test]
    fn test_repair_orphan_tool_results_in_history() {
        let mut payload = json!({
            "conversationState": {
                "history": [
                    {
                        "assistantResponseMessage": {
                            "content": "tool call",
                            "toolUses": [
                                {"toolUseId": "tooluse_keep", "name": "Read", "input": {"path": "a"}}
                            ]
                        }
                    },
                    {
                        "userInputMessage": {
                            "content": "before",
                            "modelId": "claude-sonnet-4-20250514",
                            "origin": "AI_EDITOR",
                            "userInputMessageContext": {
                                "toolResults": [
                                    {"toolUseId": "tooluse_keep", "content": [{"text": "ok"}], "status": "success"},
                                    {"toolUseId": "tooluse_orphan", "content": [{"text": "lost"}], "status": "success"}
                                ]
                            }
                        }
                    }
                ]
            }
        });

        let repaired = repair_orphan_tool_results_in_history(&mut payload);
        assert_eq!(repaired, 1);

        let results = payload["conversationState"]["history"][1]["userInputMessage"]["userInputMessageContext"]["toolResults"]
            .as_array()
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["toolUseId"], "tooluse_keep");

        let content = payload["conversationState"]["history"][1]["userInputMessage"]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("Recovered orphan tool_result"));
        assert!(content.contains("tooluse_orphan"));
    }

    #[test]
    fn test_repair_orphan_tool_results_removes_empty_context() {
        let mut payload = json!({
            "conversationState": {
                "history": [
                    {
                        "userInputMessage": {
                            "content": "(empty)",
                            "modelId": "claude-sonnet-4-20250514",
                            "origin": "AI_EDITOR",
                            "userInputMessageContext": {
                                "toolResults": [
                                    {"toolUseId": "tooluse_missing", "content": [{"text": "only orphan"}], "status": "success"}
                                ]
                            }
                        }
                    }
                ]
            }
        });

        let repaired = repair_orphan_tool_results_in_history(&mut payload);
        assert_eq!(repaired, 1);

        let user_input = payload["conversationState"]["history"][0]["userInputMessage"]
            .as_object()
            .unwrap();
        assert!(user_input.get("userInputMessageContext").is_none());
        let content = user_input.get("content").and_then(|v| v.as_str()).unwrap();
        assert!(content.contains("only orphan"));
    }

    // ===== Fake Reasoning config-driven tests =====

    #[test]
    fn test_sse_strip_mode_no_thinking_leak() {
        // strip_thinking = true → thinking blocks MUST NOT appear in output
        let mut builder = AnthropicSseBuilder::new("test-model", 100, true, &[]);
        let out = builder.process_event(KiroEvent::TextDelta(
            "<thinking>secret reasoning</thinking>visible text".to_string(),
        ));
        let final_out = builder.finalize();
        let combined = format!("{}{}", out, final_out);

        // Must not contain any thinking-related SSE events
        assert!(!combined.contains("thinking_delta"), "thinking_delta leaked in strip mode");
        assert!(!combined.contains("\"type\": \"thinking\""), "thinking block leaked in strip mode");
        assert!(!combined.contains("secret reasoning"), "thinking content leaked in strip mode");
        // But visible text should still be present
        assert!(combined.contains("visible text"), "visible text missing in strip mode");
    }

    #[test]
    fn test_sse_inject_mode_emits_thinking() {
        // strip_thinking = false → thinking blocks MUST appear in output
        let mut builder = AnthropicSseBuilder::new("test-model", 100, false, &[]);
        let out = builder.process_event(KiroEvent::TextDelta(
            "<thinking>my reasoning</thinking>answer".to_string(),
        ));
        let final_out = builder.finalize();
        let combined = format!("{}{}", out, final_out);

        // Must contain thinking block
        assert!(combined.contains("thinking_delta"), "thinking_delta missing in inject mode");
        assert!(combined.contains("my reasoning"), "thinking content missing in inject mode");
        // And visible text
        assert!(combined.contains("answer"), "answer text missing in inject mode");
    }

    #[test]
    fn test_convert_payload_enabled() {
        use crate::proxy::config::FakeReasoningConfig;
        let config = FakeReasoningConfig {
            enabled: true,
            handling: "inject".to_string(),
            max_tokens: 8000,
            open_tags: vec![],
        };
        let request = ClaudeRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("hello".to_string()),
            }],
            stream: true,
            max_tokens: Some(4096),
            system: None,
            tools: None,
            metadata: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let payload = convert_to_kiro_payload(&request, None, &config);
        let content = payload["conversationState"]["currentMessage"]["userInputMessage"]["content"]
            .as_str()
            .unwrap_or("");
        assert!(content.contains("<thinking_mode>enabled</thinking_mode>"),
            "thinking_mode tag missing when enabled");
        assert!(content.contains("<max_thinking_length>8000</max_thinking_length>"),
            "max_thinking_length should use config fallback");
    }

    #[test]
    fn test_convert_payload_disabled() {
        use crate::proxy::config::FakeReasoningConfig;
        let config = FakeReasoningConfig {
            enabled: false,
            handling: "inject".to_string(),
            max_tokens: 8000,
            open_tags: vec![],
        };
        let request = ClaudeRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("hello".to_string()),
            }],
            stream: true,
            max_tokens: Some(4096),
            system: None,
            tools: None,
            metadata: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let payload = convert_to_kiro_payload(&request, None, &config);
        let content = payload["conversationState"]["currentMessage"]["userInputMessage"]["content"]
            .as_str()
            .unwrap_or("");
        assert!(!content.contains("<thinking_mode>"),
            "thinking_mode tag should NOT appear when disabled");
        assert!(content.contains("hello"),
            "user text must be present when disabled");
        assert!(!content.contains("<max_thinking_length>"),
            "max_thinking_length tag should NOT appear when disabled");
    }

    // ==================== Task 5: Golden Boundary Tests ====================

    /// Tag split across chunk boundary in inject mode → thinking blocks still emitted
    #[test]
    fn test_sse_inject_mode_chunk_split_tag() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, false, &[]);
        // Split the opening tag across two chunks
        let out1 = builder.process_event(KiroEvent::TextDelta("<think".to_string()));
        let out2 = builder.process_event(KiroEvent::TextDelta("ing>deep thought</thinking>answer".to_string()));
        let final_out = builder.finalize();
        let combined = format!("{}{}{}", out1, out2, final_out);

        assert!(combined.contains("deep thought"), "thinking content missing after split-tag inject");
        assert!(combined.contains("thinking_delta"), "thinking_delta missing after split-tag inject");
        assert!(combined.contains("answer"), "regular answer missing after split-tag inject");
    }

    /// Tag split across chunk boundary in strip mode → ZERO thinking leaks
    #[test]
    fn test_sse_strip_mode_chunk_split_tag_no_leak() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, true, &[]);
        // Split the closing tag across two chunks
        let out1 = builder.process_event(KiroEvent::TextDelta("<thinking>secret</think".to_string()));
        let out2 = builder.process_event(KiroEvent::TextDelta("ing>visible".to_string()));
        let final_out = builder.finalize();
        let combined = format!("{}{}{}", out1, out2, final_out);

        assert!(!combined.contains("secret"), "thinking content 'secret' leaked in strip mode");
        assert!(!combined.contains("thinking_delta"), "thinking_delta leaked in strip mode with split tag");
        assert!(combined.contains("visible"), "visible text missing after strip-mode split tag");
    }

    /// Multiple thinking blocks in one stream (inject mode) → both emitted
    #[test]
    fn test_sse_inject_mode_multiple_thinking_blocks() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, false, &[]);
        let out = builder.process_event(KiroEvent::TextDelta(
            "<thinking>thought1</thinking>mid<thinking>thought2</thinking>final".to_string(),
        ));
        let final_out = builder.finalize();
        let combined = format!("{}{}", out, final_out);

        assert!(combined.contains("thought1"), "first thinking block missing");
        assert!(combined.contains("mid"), "middle text missing");
        // The second <thinking> after STREAMING state should be treated as text
        // (parser only detects first thinking block at start)
        assert!(combined.contains("final"), "final text missing");
    }

    /// Unclosed thinking tag at end-of-stream in strip mode → no leak on flush
    #[test]
    fn test_sse_strip_mode_unclosed_tag_flush() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, true, &[]);
        // Feed opening tag but never close it — stream ends
        let out = builder.process_event(KiroEvent::TextDelta(
            "<thinking>unclosed reasoning that keeps going...".to_string(),
        ));
        let final_out = builder.finalize();
        let combined = format!("{}{}", out, final_out);

        assert!(!combined.contains("unclosed reasoning"), "unclosed thinking content leaked in strip mode");
        assert!(!combined.contains("thinking_delta"), "thinking_delta should not appear for unclosed tags in strip mode");
    }

    /// <thought> tag through SSE builder (inject mode) → thinking blocks emitted
    #[test]
    fn test_sse_inject_mode_thought_tag() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, false, &[]);
        let out = builder.process_event(KiroEvent::TextDelta(
            "<thought>my thought content</thought>result".to_string(),
        ));
        let final_out = builder.finalize();
        let combined = format!("{}{}", out, final_out);

        assert!(combined.contains("my thought content"), "thought tag content missing in inject mode");
        assert!(combined.contains("thinking_delta"), "thinking_delta missing for <thought> tag");
        assert!(combined.contains("result"), "result text missing after <thought> tag");
    }

    /// <thought> tag through SSE builder (strip mode) → no leak
    #[test]
    fn test_sse_strip_mode_thought_tag_no_leak() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100, true, &[]);
        let out = builder.process_event(KiroEvent::TextDelta(
            "<thought>secret thought</thought>visible result".to_string(),
        ));
        let final_out = builder.finalize();
        let combined = format!("{}{}", out, final_out);

        assert!(!combined.contains("secret thought"), "thought content leaked in strip mode");
        assert!(!combined.contains("thinking_delta"), "thinking_delta leaked for <thought> in strip mode");
        assert!(combined.contains("visible result"), "visible result missing after <thought> strip");
    }

    /// System prompt addition is absent when fake_reasoning is disabled
    #[test]
    fn test_convert_payload_disabled_no_system_addition() {
        use crate::proxy::config::FakeReasoningConfig;
        let config = FakeReasoningConfig {
            enabled: false,
            handling: "inject".to_string(),
            max_tokens: 8000,
            open_tags: vec![],
        };
        let request = ClaudeRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("hello".to_string()),
            }],
            stream: true,
            max_tokens: Some(4096),
            system: Some(SystemPrompt::String("You are helpful.".to_string())),
            tools: None,
            metadata: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let payload = convert_to_kiro_payload(&request, None, &config);
        // System prompt is prepended to the user message content in Kiro payload
        let content = payload["conversationState"]["currentMessage"]["userInputMessage"]["content"]
            .as_str()
            .unwrap_or("");
        assert!(!content.contains("Extended Thinking Mode"),
            "system prompt should NOT contain thinking addition when disabled");
        assert!(content.contains("You are helpful."),
            "original system prompt must be preserved when disabled");
    }

    /// System prompt addition IS present when fake_reasoning is enabled
    #[test]
    fn test_convert_payload_enabled_has_system_addition() {
        use crate::proxy::config::FakeReasoningConfig;
        let config = FakeReasoningConfig {
            enabled: true,
            handling: "inject".to_string(),
            max_tokens: 8000,
            open_tags: vec![],
        };
        let request = ClaudeRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("hello".to_string()),
            }],
            stream: true,
            max_tokens: Some(4096),
            system: Some(SystemPrompt::String("You are helpful.".to_string())),
            tools: None,
            metadata: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            output_config: None,
            size: None,
            quality: None,
        };
        let payload = convert_to_kiro_payload(&request, None, &config);
        // System prompt is prepended to the user message content in Kiro payload
        let content = payload["conversationState"]["currentMessage"]["userInputMessage"]["content"]
            .as_str()
            .unwrap_or("");
        assert!(content.contains("Extended Thinking Mode"),
            "system prompt should contain thinking addition when enabled");
        assert!(content.contains("You are helpful."),
            "original system prompt must be preserved when enabled");
    }
}
