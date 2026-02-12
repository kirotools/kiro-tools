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

/// Build tool specifications from Anthropic tools definition
fn build_tool_specifications(tools: &[crate::proxy::mappers::claude::models::Tool], max_desc_length: usize) -> Vec<Value> {
    tools
        .iter()
        .filter_map(|tool| {
            let name = tool.name.as_deref()?;
            let description = tool.description.as_deref().unwrap_or("");
            let description = if max_desc_length > 0 && description.len() > max_desc_length {
                &description[..max_desc_length]
            } else {
                description
            };
            let schema = tool.input_schema.clone().unwrap_or(json!({}));
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
        let last_role = last.get("role").and_then(|r| r.as_str()).unwrap_or("");
        let msg_role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");

        if last_role == msg_role {
            let last_content = last.get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let msg_content = msg.get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(content) = last.get_mut("content") {
                *content = serde_json::Value::String(format!("{}\n{}", last_content, msg_content));
            }

            tracing::debug!("Merged adjacent {} messages", msg_role);
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

/// Convert Anthropic ClaudeRequest to Kiro generateAssistantResponse payload
fn convert_to_kiro_payload(request: &ClaudeRequest, profile_arn: Option<&str>) -> Value {
    let model_id = normalize_model_name(&request.model);

    // 1. Extract system prompt
    let system_text = request.system.as_ref().map(|sp| match sp {
        SystemPrompt::String(s) => s.clone(),
        SystemPrompt::Array(blocks) => blocks
            .iter()
            .map(|b| b.text.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    });

    // 2. Merge consecutive same-role messages
    let merged = merge_to_alternating(&request.messages);
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

    // 9. Build currentMessage
    let (_, current_text, _current_tool_uses, current_tool_results, current_images) = last;
    let current_content = if current_text.is_empty() {
        "Continue".to_string()
    } else {
        current_text
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
        let specs = build_tool_specifications(tools, TOOL_DESCRIPTION_MAX_LENGTH);
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

    if let Some(thinking) = &request.thinking {
        if let Some(budget) = thinking.budget_tokens {
            conversation_state["thinkingConfig"] = json!({
                "enabled": true,
                "budgetTokens": budget
            });
        }
    }

    let mut payload = json!({ "conversationState": conversation_state });

    if let Some(arn) = profile_arn {
        payload["profileArn"] = json!(arn);
    }

    payload
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

/// First-token timeout: how long to wait for the first chunk before retrying
const FIRST_TOKEN_TIMEOUT_SECS: u64 = 15;
/// Maximum number of transparent retries on first-token timeout
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
}

impl AnthropicSseBuilder {
    fn new(model: &str, estimated_input_tokens: u32) -> Self {
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
            thinking_parser: ThinkingParser::new(),
            accumulated_text: String::new(),
            thinking_block_index: None,
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
                            out.push_str(&self.close_text_block());
                            out.push_str(&Self::format_sse(
                                "content_block_start",
                                &json!({
                                    "type": "content_block_start",
                                    "index": self.content_index,
                                    "content_block": {
                                        "type": "thinking",
                                        "thinking": ""
                                    }
                                }),
                            ));
                            self.thinking_block_index = Some(self.content_index);
                            self.content_index += 1;
                        }
                        ThinkingEvent::ThinkingDelta(thinking_text) => {
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
) -> Response {
    let fingerprint = get_machine_fingerprint();
    let kiro_host = get_kiro_q_host(region);
    let url = format!("{}/generateAssistantResponse", kiro_host);

    info!(
        "[{}] [Kiro] Routing to Kiro upstream | Account: {} | Region: {} | Model: {}",
        trace_id, email, region, request.model
    );

    // 1. Convert Anthropic request to Kiro payload
    let kiro_payload = convert_to_kiro_payload(request, profile_arn);

    debug!(
        "[{}] [Kiro] Payload: {}",
        trace_id,
        serde_json::to_string(&kiro_payload).unwrap_or_default()
    );

    // 2. Send request with retry logic (403 → refresh + retry, 429/5xx → exponential backoff)
    const MAX_RETRIES: usize = 3;
    const BASE_DELAY_MS: u64 = 1000;

    let client = reqwest::Client::new();
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
                    match crate::modules::oauth::refresh_access_token(
                        None, None, Some(account_id)
                    ).await {
                        Ok(token_response) => {
                            current_token = token_response.access_token;
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
                    match crate::modules::oauth::refresh_access_token(
                        None, None, Some(account_id)
                    ).await {
                        Ok(token_response) => {
                            current_token = token_response.access_token;
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

            // 429 — rate limited, exponential backoff
            if status.as_u16() == 429 {
                let error_text = response.text().await.unwrap_or_default();
                if attempt < MAX_RETRIES - 1 {
                    let delay = BASE_DELAY_MS * (1 << attempt);
                    warn!("[{}] [Kiro] Received 429 (attempt {}/{}), waiting {}ms...",
                        trace_id, attempt + 1, MAX_RETRIES, delay);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                    continue;
                }
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
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    AnthropicErrorType::ApiError,
                    &format!("Kiro API error ({}): {}", status.as_u16(), error_text),
                );
            }

            // Other errors — attempt to parse Kiro error body and map to user-friendly message
            let error_text = response.text().await.unwrap_or_default();
            error!("[{}] [Kiro] Upstream error {}: {}", trace_id, status.as_u16(), error_text);

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

            let mut builder = AnthropicSseBuilder::new(&model, estimated_input);
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

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::CONNECTION, "keep-alive")
            .header("X-Accel-Buffering", "no")
            .header("X-Account-Email", email)
            .header("X-Kiro-Upstream", "true")
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
        let mut builder = AnthropicSseBuilder::new(&model, estimated_input);

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

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-Account-Email", email)
            .header("X-Kiro-Upstream", "true")
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
        let mut builder = AnthropicSseBuilder::new("test-model", 100);
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
        let specs = build_tool_specifications(&tools, 4096);
        let spec = &specs[0];
        let desc = spec["toolSpecification"]["description"].as_str().unwrap();
        assert_eq!(desc.len(), 4096);

        let short_tools = vec![Tool {
            type_: None,
            name: Some("test_tool".to_string()),
            description: Some("short desc".to_string()),
            input_schema: Some(json!({"type": "object"})),
        }];
        let specs2 = build_tool_specifications(&short_tools, 4096);
        let desc2 = specs2[0]["toolSpecification"]["description"]
            .as_str()
            .unwrap();
        assert_eq!(desc2, "short desc");
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
            serde_json::json!({"role": "user", "content": "hello"}),
            serde_json::json!({"role": "user", "content": "world"}),
            serde_json::json!({"role": "assistant", "content": "hi"}),
            serde_json::json!({"role": "assistant", "content": "there"}),
            serde_json::json!({"role": "user", "content": "bye"}),
        ];
        let merged = merge_adjacent_messages(messages);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0]["content"], "hello\nworld");
        assert_eq!(merged[1]["content"], "hi\nthere");
        assert_eq!(merged[2]["content"], "bye");
    }

    #[test]
    fn test_merge_adjacent_empty() {
        let merged = merge_adjacent_messages(vec![]);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_adjacent_no_merges() {
        let messages = vec![
            serde_json::json!({"role": "user", "content": "a"}),
            serde_json::json!({"role": "assistant", "content": "b"}),
            serde_json::json!({"role": "user", "content": "c"}),
        ];
        let merged = merge_adjacent_messages(messages);
        assert_eq!(merged.len(), 3);
    }

    // Property 21: Incomplete stream truncation detection
    #[test]
    fn prop_incomplete_stream_truncation() {
        let mut builder = AnthropicSseBuilder::new("test-model", 100);
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
}
