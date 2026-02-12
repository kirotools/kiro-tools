// Kiro Upstream Handler
// Converts Anthropic /v1/messages requests to Kiro generateAssistantResponse API format,
// sends to AWS Q endpoint, parses AWS event stream response, and converts back to Anthropic SSE.

use axum::{
    body::Body,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use crate::auth::config::{get_kiro_q_host, get_machine_fingerprint};
use crate::proxy::mappers::claude::models::{
    ClaudeRequest, ContentBlock, Message, MessageContent, SystemPrompt,
};
use crate::proxy::token_manager::ConcurrencySlot;

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
        "aws-sdk-js/1.0.27 ua/2.1 os/linux#6.1.0 lang/js md/nodejs#22.21.1 api/codewhispererstreaming#1.0.27 m/E KiroIDE-0.7.45-{}",
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
                    _ => {}
                }
            }
            parts.join("\n")
        }
    }
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
fn build_tool_specifications(tools: &[crate::proxy::mappers::claude::models::Tool]) -> Vec<Value> {
    tools
        .iter()
        .filter_map(|tool| {
            let name = tool.name.as_deref()?;
            let description = tool.description.as_deref().unwrap_or("");
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
fn merge_to_alternating(messages: &[Message]) -> Vec<(String, String, Vec<Value>, Vec<Value>)> {
    // Returns: Vec<(role, text, tool_uses, tool_results)>
    let mut merged: Vec<(String, String, Vec<Value>, Vec<Value>)> = Vec::new();

    for msg in messages {
        let text = extract_text(&msg.content);
        let tool_uses = extract_tool_uses(&msg.content);
        let tool_results = extract_tool_results(&msg.content);

        if let Some(last) = merged.last_mut() {
            if last.0 == msg.role {
                // Same role — merge
                if !text.is_empty() {
                    if !last.1.is_empty() {
                        last.1.push('\n');
                    }
                    last.1.push_str(&text);
                }
                last.2.extend(tool_uses);
                last.3.extend(tool_results);
                continue;
            }
        }
        merged.push((msg.role.clone(), text, tool_uses, tool_results));
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
fn convert_to_kiro_payload(request: &ClaudeRequest) -> Value {
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
        processed.insert(0, ("user".to_string(), "(empty)".to_string(), vec![], vec![]));
    }

    // 4. Ensure alternating roles — insert synthetic "(empty)" messages where needed
    let mut alternated: Vec<(String, String, Vec<Value>, Vec<Value>)> = vec![processed.remove(0)];
    for item in processed {
        if let Some(last) = alternated.last() {
            if last.0 == item.0 {
                // Same role consecutive — insert synthetic opposite
                if item.0 == "user" {
                    alternated.push(("assistant".to_string(), "(empty)".to_string(), vec![], vec![]));
                } else {
                    alternated.push(("user".to_string(), "(empty)".to_string(), vec![], vec![]));
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
        processed.push(("user".to_string(), "Continue".to_string(), vec![], vec![]));
    }

    // 7. Split into history (all but last) and currentMessage (last)
    let last = processed.pop().unwrap();
    let history_items = processed;

    // 8. Build history array — with userInputMessageContext.toolResults for user messages
    let mut history = Vec::new();
    for (role, text, tool_uses, tool_results) in &history_items {
        if role == "user" {
            let content = if text.is_empty() { "(empty)" } else { text.as_str() };
            let mut user_input = json!({
                "content": content,
                "modelId": &model_id,
                "origin": "AI_EDITOR"
            });

            // Add toolResults in userInputMessageContext if present
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
    let (_, current_text, _current_tool_uses, current_tool_results) = last;
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

    // Build userInputMessageContext (tools + toolResults)
    let mut user_input_context = serde_json::Map::new();

    // Add tool specifications under "tools" key (NOT "toolSpecification")
    if let Some(tools) = &request.tools {
        let specs = build_tool_specifications(tools);
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

    // Only add history if non-empty
    if !history.is_empty() {
        conversation_state["history"] = json!(history);
    }

    json!({ "conversationState": conversation_state })
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
fn parse_events_from_buffer(buffer: &[u8]) -> Vec<KiroEvent> {
    let mut events = Vec::new();
    let text = String::from_utf8_lossy(buffer);

    // Find all JSON objects in the text
    let mut i = 0;
    let chars: Vec<char> = text.chars().collect();
    while i < chars.len() {
        if chars[i] == '{' {
            // Try to find matching closing brace
            let mut depth = 0;
            let mut in_string = false;
            let mut escape_next = false;
            let start = i;

            for j in i..chars.len() {
                if escape_next {
                    escape_next = false;
                    continue;
                }
                match chars[j] {
                    '\\' if in_string => escape_next = true,
                    '"' => in_string = !in_string,
                    '{' if !in_string => depth += 1,
                    '}' if !in_string => {
                        depth -= 1;
                        if depth == 0 {
                            let json_str: String = chars[start..=j].iter().collect();
                            if let Ok(val) = serde_json::from_str::<Value>(&json_str) {
                                events.push(classify_kiro_event(val));
                            }
                            i = j + 1;
                            break;
                        }
                    }
                    _ => {}
                }
                if j == chars.len() - 1 {
                    // Didn't find matching brace, skip this opening brace
                    i = start + 1;
                }
            }
        } else {
            i += 1;
        }
    }

    events
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

    // Check for tool use start (has name + toolUseId)
    if let (Some(name), Some(tool_use_id)) = (
        val.get("name").and_then(|v| v.as_str()),
        val.get("toolUseId").and_then(|v| v.as_str()),
    ) {
        return KiroEvent::ToolUseStart {
            name: name.to_string(),
            tool_use_id: tool_use_id.to_string(),
        };
    }

    // Check for tool input delta (has "input" as string, no "name")
    if val.get("name").is_none() {
        if let Some(input) = val.get("input").and_then(|v| v.as_str()) {
            return KiroEvent::ToolInputDelta(input.to_string());
        }
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

/// State machine for converting Kiro events to Anthropic SSE
struct AnthropicSseBuilder {
    message_id: String,
    model: String,
    content_index: usize,
    in_text_block: bool,
    in_tool_block: bool,
    total_input_tokens: u32,
    total_output_tokens: u32,
    estimated_input_tokens: u32,
    output_char_count: usize,
    has_sent_message_start: bool,
}

impl AnthropicSseBuilder {
    fn new(model: &str, estimated_input_tokens: u32) -> Self {
        Self {
            message_id: format!("msg_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..24].to_string()),
            model: model.to_string(),
            content_index: 0,
            in_text_block: false,
            in_tool_block: false,
            total_input_tokens: 0,
            total_output_tokens: 0,
            estimated_input_tokens,
            output_char_count: 0,
            has_sent_message_start: false,
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
                        "input_tokens": 0,
                        "output_tokens": 0
                    }
                }
            }),
        )
    }

    fn close_current_block(&mut self) -> String {
        let mut out = String::new();
        if self.in_text_block || self.in_tool_block {
            out.push_str(&Self::format_sse(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": self.content_index}),
            ));
            self.content_index += 1;
            self.in_text_block = false;
            self.in_tool_block = false;
        }
        out
    }

    fn process_event(&mut self, event: KiroEvent) -> String {
        let mut out = String::new();

        // Ensure message_start is sent first
        out.push_str(&self.message_start());

        match event {
            KiroEvent::TextDelta(text) => {
                if self.in_tool_block {
                    out.push_str(&self.close_current_block());
                }

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

            KiroEvent::ToolUseStart { name, tool_use_id } => {
                // Close any open block
                out.push_str(&self.close_current_block());

                out.push_str(&Self::format_sse(
                    "content_block_start",
                    &json!({
                        "type": "content_block_start",
                        "index": self.content_index,
                        "content_block": {
                            "type": "tool_use",
                            "id": tool_use_id,
                            "name": name,
                            "input": {}
                        }
                    }),
                ));
                self.in_tool_block = true;
            }

            KiroEvent::ToolInputDelta(partial_json) => {
                if self.in_tool_block {
                    out.push_str(&Self::format_sse(
                        "content_block_delta",
                        &json!({
                            "type": "content_block_delta",
                            "index": self.content_index,
                            "delta": {"type": "input_json_delta", "partial_json": partial_json}
                        }),
                    ));
                }
            }

            KiroEvent::ToolUseStop => {
                out.push_str(&self.close_current_block());
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

        out.push_str(&self.close_current_block());

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

        out.push_str(&Self::format_sse(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {
                    "stop_reason": "end_turn",
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
    let kiro_payload = convert_to_kiro_payload(request);

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
                    error!("[{}] [Kiro] Request failed after {} attempts: {}", trace_id, MAX_RETRIES, e);
                    return (
                        StatusCode::BAD_GATEWAY,
                        axum::Json(json!({
                            "type": "error",
                            "error": {
                                "type": "api_error",
                                "message": format!("Kiro upstream request failed: {}", e)
                            }
                        })),
                    ).into_response();
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

                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(json!({
                        "type": "error",
                        "error": {
                            "type": "api_error",
                            "message": format!("Kiro API 403 (token invalid): {}", error_text)
                        }
                    })),
                ).into_response();
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

                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(json!({
                        "type": "error",
                        "error": {
                            "type": "api_error",
                            "message": format!("Kiro API 401 (bad credentials): {}", error_text)
                        }
                    })),
                ).into_response();
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
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(json!({
                        "type": "error",
                        "error": {
                            "type": "rate_limit_error",
                            "message": format!("Kiro API rate limited: {}", error_text)
                        }
                    })),
                ).into_response();
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
                return (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(json!({
                        "type": "error",
                        "error": {
                            "type": "api_error",
                            "message": format!("Kiro API error ({}): {}", status.as_u16(), error_text)
                        }
                    })),
                ).into_response();
            }

            // Other errors — return immediately
            let error_text = response.text().await.unwrap_or_default();
            error!("[{}] [Kiro] Upstream error {}: {}", trace_id, status.as_u16(), error_text);
            let mapped_status = match status.as_u16() {
                400 => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_GATEWAY,
            };
            return (
                mapped_status,
                axum::Json(json!({
                    "type": "error",
                    "error": {
                        "type": "api_error",
                        "message": format!("Kiro API error ({}): {}", status.as_u16(), error_text)
                    }
                })),
            ).into_response();
        }

        // Should not reach here, but just in case
        return (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({
                "type": "error",
                "error": {
                    "type": "api_error",
                    "message": "Kiro upstream request failed after all retries"
                }
            })),
        ).into_response();
    };

    // 4. Stream the response — parse AWS event stream and convert to Anthropic SSE
    let model = request.model.clone();
    let trace_id_owned = trace_id.to_string();
    let estimated_input = estimate_request_tokens(request);

    if request.stream {
        // Streaming mode: convert AWS event stream to Anthropic SSE in real-time
        let byte_stream = resp.bytes_stream();

        let sse_stream = async_stream::stream! {
            // Hold the concurrency slot alive for the entire duration of the stream.
            // It will be dropped when the stream ends, releasing the slot.
            let _slot_guard = concurrency_slot;

            let mut builder = AnthropicSseBuilder::new(&model, estimated_input);
            let mut buffer = BytesMut::new();

            tokio::pin!(byte_stream);

            while let Some(chunk_result) = byte_stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        buffer.extend_from_slice(&chunk);

                        // Parse events from accumulated buffer
                        let events = parse_events_from_buffer(&buffer);
                        // Clear buffer after parsing (simplified — in production you'd track consumed bytes)
                        if !events.is_empty() {
                            buffer.clear();
                        }

                        for event in events {
                            let sse_text = builder.process_event(event);
                            if !sse_text.is_empty() {
                                yield Ok::<Bytes, std::io::Error>(Bytes::from(sse_text));
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[{}] [Kiro] Stream chunk error: {}", trace_id_owned, e);
                        break;
                    }
                }
            }

            // Finalize the stream
            let final_sse = builder.finalize();
            if !final_sse.is_empty() {
                yield Ok::<Bytes, std::io::Error>(Bytes::from(final_sse));
            }
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
                return (StatusCode::BAD_GATEWAY, format!("Failed to read Kiro response: {}", e))
                    .into_response();
            }
        };

        let events = parse_events_from_buffer(&body_bytes);
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
