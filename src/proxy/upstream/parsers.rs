#![allow(dead_code)]
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ParsedToolCall {
    pub name: String,
    pub arguments: Value,
    pub tool_call_id: String,
}

/// Find closing `}` for opening `{` at `start`, handling strings and escapes.
/// Returns `None` if no matching brace found.
fn find_matching_brace(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if start >= bytes.len() || bytes[start] != b'{' {
        return None;
    }

    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut i = start;

    while i < bytes.len() {
        let ch = bytes[i];

        if escape_next {
            escape_next = false;
            i += 1;
            continue;
        }

        if ch == b'\\' && in_string {
            escape_next = true;
            i += 1;
            continue;
        }

        if ch == b'"' {
            in_string = !in_string;
            i += 1;
            continue;
        }

        if !in_string {
            if ch == b'{' {
                depth += 1;
            } else if ch == b'}' {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
        }

        i += 1;
    }

    None
}

/// Parse `[Called func_name with args: {...}]` patterns from text.
pub fn parse_bracket_tool_calls(text: &str) -> Vec<ParsedToolCall> {
    if text.is_empty() || !text.contains("[Called") {
        return Vec::new();
    }

    let pattern = Regex::new(r"(?i)\[Called\s+(\w+)\s+with\s+args:\s*").unwrap();
    let mut results = Vec::new();

    for caps in pattern.captures_iter(text) {
        let func_name = caps.get(1).unwrap().as_str().to_string();
        let match_end = caps.get(0).unwrap().end();

        // Find the opening brace after the match
        let json_start = match text[match_end..].find('{') {
            Some(offset) => match_end + offset,
            None => continue,
        };

        // Find matching closing brace
        let json_end = match find_matching_brace(text, json_start) {
            Some(pos) => pos,
            None => continue,
        };

        let json_str = &text[json_start..=json_end];

        match serde_json::from_str::<Value>(json_str) {
            Ok(args) => {
                let id = format!("toolu_{}", uuid::Uuid::new_v4().simple());
                // uuid simple is 32 hex chars; spec says 24, so truncate
                let tool_call_id = id[..30].to_string(); // "toolu_" (6) + 24 hex = 30
                results.push(ParsedToolCall {
                    name: func_name,
                    arguments: args,
                    tool_call_id,
                });
            }
            Err(_) => continue,
        }
    }

    results
}

/// Deduplicate tool calls by (name, serialized arguments). Keeps first occurrence.
pub fn deduplicate_tool_calls(calls: Vec<ParsedToolCall>) -> Vec<ParsedToolCall> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();

    for call in calls {
        let key = format!(
            "{}-{}",
            call.name,
            serde_json::to_string(&call.arguments).unwrap_or_default()
        );
        if seen.insert(key) {
            unique.push(call);
        }
    }

    unique
}

/// Diagnose whether a JSON string appears truncated.
/// Returns `None` if valid JSON, `Some(reason)` if truncated.
pub fn diagnose_json_truncation(json_str: &str) -> Option<String> {
    // If it parses fine, it's not truncated
    if serde_json::from_str::<Value>(json_str).is_ok() {
        return None;
    }

    let stripped = json_str.trim();
    if stripped.is_empty() {
        return None;
    }

    // Count braces and brackets (simplified, doesn't account for strings)
    let open_braces = stripped.matches('{').count();
    let close_braces = stripped.matches('}').count();
    let open_brackets = stripped.matches('[').count();
    let close_brackets = stripped.matches(']').count();

    // Check if starts with { but doesn't end with }
    if stripped.starts_with('{') && !stripped.ends_with('}') {
        let missing = open_braces.saturating_sub(close_braces);
        return Some(format!("missing {} closing brace(s)", missing));
    }

    // Check if starts with [ but doesn't end with ]
    if stripped.starts_with('[') && !stripped.ends_with(']') {
        let missing = open_brackets.saturating_sub(close_brackets);
        return Some(format!("missing {} closing bracket(s)", missing));
    }

    // Check unbalanced braces
    if open_braces != close_braces {
        let missing = open_braces.saturating_sub(close_braces);
        return Some(format!("missing {} closing brace(s)", missing));
    }

    // Check unbalanced brackets
    if open_brackets != close_brackets {
        let missing = open_brackets.saturating_sub(close_brackets);
        return Some(format!("missing {} closing bracket(s)", missing));
    }

    // Check for unclosed string literal (count unescaped quotes)
    let mut quote_count = 0usize;
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2; // skip escaped char
            continue;
        }
        if bytes[i] == b'"' {
            quote_count += 1;
        }
        i += 1;
    }

    if quote_count % 2 != 0 {
        return Some("unclosed string literal".to_string());
    }

    // Malformed but not detectably truncated
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_bracket_tool_calls ---

    #[test]
    fn test_parse_single_tool_call() {
        let text = r#"[Called get_weather with args: {"city": "London"}]"#;
        let calls = parse_bracket_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[0].arguments["city"], "London");
        assert!(calls[0].tool_call_id.starts_with("toolu_"));
        assert_eq!(calls[0].tool_call_id.len(), 30);
    }

    #[test]
    fn test_parse_multiple_tool_calls() {
        let text = r#"Some text [Called foo with args: {"a": 1}] middle [Called bar with args: {"b": 2}] end"#;
        let calls = parse_bracket_tool_calls(text);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "foo");
        assert_eq!(calls[0].arguments["a"], 1);
        assert_eq!(calls[1].name, "bar");
        assert_eq!(calls[1].arguments["b"], 2);
        // IDs should be unique
        assert_ne!(calls[0].tool_call_id, calls[1].tool_call_id);
    }

    #[test]
    fn test_parse_no_tool_calls_empty() {
        assert!(parse_bracket_tool_calls("").is_empty());
    }

    #[test]
    fn test_parse_no_tool_calls_no_pattern() {
        assert!(parse_bracket_tool_calls("just some regular text").is_empty());
    }

    #[test]
    fn test_parse_invalid_json_skipped() {
        let text =
            r#"[Called bad with args: {not valid json}] [Called good with args: {"ok": true}]"#;
        let calls = parse_bracket_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "good");
    }

    // --- deduplicate_tool_calls ---

    #[test]
    fn test_deduplicate_removes_exact_duplicates() {
        let calls = vec![
            ParsedToolCall {
                name: "foo".into(),
                arguments: serde_json::json!({"a": 1}),
                tool_call_id: "toolu_aaa".into(),
            },
            ParsedToolCall {
                name: "foo".into(),
                arguments: serde_json::json!({"a": 1}),
                tool_call_id: "toolu_bbb".into(),
            },
        ];
        let deduped = deduplicate_tool_calls(calls);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].tool_call_id, "toolu_aaa");
    }

    #[test]
    fn test_deduplicate_is_idempotent() {
        let calls = vec![
            ParsedToolCall {
                name: "foo".into(),
                arguments: serde_json::json!({"a": 1}),
                tool_call_id: "toolu_aaa".into(),
            },
            ParsedToolCall {
                name: "bar".into(),
                arguments: serde_json::json!({"b": 2}),
                tool_call_id: "toolu_bbb".into(),
            },
            ParsedToolCall {
                name: "foo".into(),
                arguments: serde_json::json!({"a": 1}),
                tool_call_id: "toolu_ccc".into(),
            },
        ];
        let first_pass = deduplicate_tool_calls(calls);
        assert_eq!(first_pass.len(), 2);
        let second_pass = deduplicate_tool_calls(first_pass.clone());
        assert_eq!(second_pass.len(), 2);
        // Same names in same order
        assert_eq!(first_pass[0].name, second_pass[0].name);
        assert_eq!(first_pass[1].name, second_pass[1].name);
    }

    #[test]
    fn test_deduplicate_preserves_order() {
        let calls = vec![
            ParsedToolCall {
                name: "c".into(),
                arguments: serde_json::json!({}),
                tool_call_id: "toolu_1".into(),
            },
            ParsedToolCall {
                name: "a".into(),
                arguments: serde_json::json!({}),
                tool_call_id: "toolu_2".into(),
            },
            ParsedToolCall {
                name: "b".into(),
                arguments: serde_json::json!({}),
                tool_call_id: "toolu_3".into(),
            },
            ParsedToolCall {
                name: "a".into(),
                arguments: serde_json::json!({}),
                tool_call_id: "toolu_4".into(),
            },
        ];
        let deduped = deduplicate_tool_calls(calls);
        assert_eq!(deduped.len(), 3);
        assert_eq!(deduped[0].name, "c");
        assert_eq!(deduped[1].name, "a");
        assert_eq!(deduped[2].name, "b");
    }

    // --- diagnose_json_truncation ---

    #[test]
    fn test_diagnose_valid_json_returns_none() {
        assert!(diagnose_json_truncation(r#"{"key": "value"}"#).is_none());
        assert!(diagnose_json_truncation(r#"[1, 2, 3]"#).is_none());
        assert!(diagnose_json_truncation(r#""hello""#).is_none());
    }

    #[test]
    fn test_diagnose_missing_braces() {
        let result = diagnose_json_truncation(r#"{"key": "value""#);
        assert!(result.is_some());
        let reason = result.unwrap();
        assert!(reason.contains("missing") && reason.contains("brace"));
    }

    #[test]
    fn test_diagnose_unclosed_string() {
        // Odd number of unescaped quotes → unclosed string
        let result = diagnose_json_truncation(r#"{"key": "val"#);
        assert!(result.is_some());
        // Could be detected as missing brace or unclosed string depending on order
        let reason = result.unwrap();
        assert!(
            reason.contains("brace") || reason.contains("unclosed string"),
            "unexpected reason: {}",
            reason
        );
    }

    // --- find_matching_brace ---

    #[test]
    fn test_find_matching_brace_simple() {
        assert_eq!(find_matching_brace(r#"{"a": 1}"#, 0), Some(7));
    }

    #[test]
    fn test_find_matching_brace_nested() {
        assert_eq!(find_matching_brace(r#"{"a": {"b": 1}}"#, 0), Some(14));
    }

    #[test]
    fn test_find_matching_brace_with_string_braces() {
        assert_eq!(find_matching_brace(r#"{"a": "{}"}"#, 0), Some(10));
    }

    #[test]
    fn test_find_matching_brace_incomplete() {
        assert_eq!(find_matching_brace(r#"{"a": 1"#, 0), None);
    }

    #[test]
    fn test_find_matching_brace_not_brace() {
        assert_eq!(find_matching_brace("hello", 0), None);
    }

    use proptest::prelude::*;

    proptest! {
        /// Property 8: bracket tool call parsing extracts correct name and valid JSON args.
        #[test]
        fn prop_bracket_tool_call_parsing(
            name in "[a-zA-Z][a-zA-Z0-9_]{0,20}",
            key in "[a-zA-Z]{1,10}",
            val in "[a-zA-Z0-9 ]{0,30}",
        ) {
            let input = format!(r#"[Called {} with args: {{"{}": "{}"}}]"#, name, key, val);
            let calls = parse_bracket_tool_calls(&input);
            prop_assert_eq!(calls.len(), 1);
            prop_assert_eq!(&calls[0].name, &name);
            prop_assert_eq!(calls[0].arguments[&key].as_str().unwrap(), val.as_str());
        }

        /// Property 9: dedup idempotency — f(f(x)) == f(x).
        #[test]
        fn prop_dedup_idempotency(
            n in 1..10usize,
            name in "[a-zA-Z]{1,8}",
        ) {
            let calls: Vec<ParsedToolCall> = (0..n)
                .map(|i| ParsedToolCall {
                    name: name.clone(),
                    arguments: serde_json::json!({"i": i % 3}),
                    tool_call_id: format!("toolu_{:024x}", i),
                })
                .collect();

            let first = deduplicate_tool_calls(calls);
            let first_len = first.len();
            let first_names: Vec<String> = first.iter().map(|c| c.name.clone()).collect();

            let second = deduplicate_tool_calls(first);
            prop_assert_eq!(second.len(), first_len);
            let second_names: Vec<String> = second.iter().map(|c| c.name.clone()).collect();
            prop_assert_eq!(first_names, second_names);
        }

        /// Property 10: valid JSON → None, truncated JSON → Some.
        #[test]
        fn prop_json_truncation_valid_returns_none(
            key in "[a-zA-Z]{1,10}",
            val in "[a-zA-Z0-9]{0,30}",
        ) {
            let json = format!(r#"{{"{}": "{}"}}"#, key, val);
            prop_assert!(diagnose_json_truncation(&json).is_none());
        }

        #[test]
        fn prop_json_truncation_missing_brace_returns_some(
            key in "[a-zA-Z]{1,10}",
            val in "[a-zA-Z0-9]{0,30}",
        ) {
            let json = format!(r#"{{"{}": "{}""#, key, val);
            prop_assert!(diagnose_json_truncation(&json).is_some());
        }
    }
}
