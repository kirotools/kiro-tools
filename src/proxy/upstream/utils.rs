#![allow(dead_code)]
// Upstream utility functions

use sha2::{Digest, Sha256};

/// Generate a unique tool call ID: "toolu_" + 24 random hex chars
pub fn generate_tool_call_id() -> String {
    let hex = uuid::Uuid::new_v4().to_string().replace('-', "");
    format!("toolu_{}", &hex[..24])
}

/// Generate a unique completion/message ID: "msg_" + 24 random hex chars
pub fn generate_completion_id() -> String {
    let hex = uuid::Uuid::new_v4().to_string().replace('-', "");
    format!("msg_{}", &hex[..24])
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Stable conversation ID from message history.
/// Hash of first 3 + last message (role + first 100 chars of content).
/// Returns 16-char hex (64 bits). Falls back to random UUID if empty.
pub fn generate_conversation_id(messages: &[serde_json::Value]) -> String {
    if messages.is_empty() {
        return uuid::Uuid::new_v4().to_string();
    }

    let key_messages: Vec<&serde_json::Value> = if messages.len() <= 3 {
        messages.iter().collect()
    } else {
        let mut v: Vec<&serde_json::Value> = messages[..3].iter().collect();
        v.push(&messages[messages.len() - 1]);
        v
    };

    let simplified: Vec<serde_json::Value> = key_messages
        .iter()
        .map(|msg| {
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown");
            let content = msg
                .get("content")
                .map(|c| match c {
                    serde_json::Value::String(s) => s.chars().take(100).collect::<String>(),
                    serde_json::Value::Array(_) => {
                        let s = serde_json::to_string(c).unwrap_or_default();
                        s.chars().take(100).collect()
                    }
                    other => {
                        let s = other.to_string();
                        s.chars().take(100).collect()
                    }
                })
                .unwrap_or_default();
            serde_json::json!({"role": role, "content": content})
        })
        .collect();

    let content_json = serde_json::to_string(&simplified).unwrap_or_default();
    let hash = Sha256::digest(content_json.as_bytes());
    bytes_to_hex(&hash[..8])
}

/// Machine fingerprint: SHA256("{hostname}-{username}-kiro-tools")
pub fn get_machine_fingerprint() -> String {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let unique_string = format!("{}-{}-kiro-tools", hostname, username);
    let hash = Sha256::digest(unique_string.as_bytes());
    bytes_to_hex(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_call_id_format() {
        let id = generate_tool_call_id();
        assert!(id.starts_with("toolu_"));
        assert_eq!(id.len(), 6 + 24); // "toolu_" + 24 hex
    }

    #[test]
    fn test_completion_id_format() {
        let id = generate_completion_id();
        assert!(id.starts_with("msg_"));
        assert_eq!(id.len(), 4 + 24); // "msg_" + 24 hex
    }

    #[test]
    fn test_ids_are_unique() {
        let ids: Vec<String> = (0..100).map(|_| generate_tool_call_id()).collect();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    use proptest::prelude::*;

    proptest! {
        /// Property 18: 10000 generated IDs are all unique.
        #[test]
        fn prop_generated_id_uniqueness(_ in 0..1u32) {
            let ids: Vec<String> = (0..10_000)
                .map(|_| generate_completion_id())
                .collect();
            let unique: std::collections::HashSet<&String> = ids.iter().collect();
            prop_assert_eq!(ids.len(), unique.len());

            let tool_ids: Vec<String> = (0..10_000)
                .map(|_| generate_tool_call_id())
                .collect();
            let tool_unique: std::collections::HashSet<&String> = tool_ids.iter().collect();
            prop_assert_eq!(tool_ids.len(), tool_unique.len());
        }
    }

    #[test]
    fn test_conversation_id_stability() {
        let msgs = vec![
            serde_json::json!({"role": "user", "content": "Hello"}),
            serde_json::json!({"role": "assistant", "content": "Hi there!"}),
        ];
        let id1 = generate_conversation_id(&msgs);
        let id2 = generate_conversation_id(&msgs);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    #[test]
    fn test_conversation_id_empty_fallback() {
        let id = generate_conversation_id(&[]);
        assert!(!id.is_empty());
        assert!(id.len() > 16);
    }

    #[test]
    fn test_conversation_id_uses_first3_plus_last() {
        let msgs: Vec<serde_json::Value> = (0..10)
            .map(|i| serde_json::json!({"role": "user", "content": format!("msg {}", i)}))
            .collect();
        let id_full = generate_conversation_id(&msgs);

        let mut msgs2 = msgs.clone();
        msgs2[5] = serde_json::json!({"role": "user", "content": "CHANGED"});
        let id_mid_changed = generate_conversation_id(&msgs2);
        assert_eq!(id_full, id_mid_changed);

        let mut msgs3 = msgs.clone();
        msgs3[0] = serde_json::json!({"role": "user", "content": "CHANGED"});
        let id_first_changed = generate_conversation_id(&msgs3);
        assert_ne!(id_full, id_first_changed);
    }

    #[test]
    fn test_machine_fingerprint_format() {
        let fp = get_machine_fingerprint();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_machine_fingerprint_stable() {
        let fp1 = get_machine_fingerprint();
        let fp2 = get_machine_fingerprint();
        assert_eq!(fp1, fp2);
    }
}
