#![allow(dead_code)]
use std::collections::HashMap;
use std::time::{Duration, Instant};

const DEFAULT_TTL: Duration = Duration::from_secs(300); // 5 minutes

struct TruncatedEntry {
    created_at: Instant,
    ttl: Duration,
}

impl TruncatedEntry {
    fn new() -> Self {
        Self {
            created_at: Instant::now(),
            ttl: DEFAULT_TTL,
        }
    }

    fn with_ttl(ttl: Duration) -> Self {
        Self {
            created_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

/// Tracks truncated tool calls and content with TTL-based expiry.
pub struct TruncationState {
    truncated_tool_calls: HashMap<String, TruncatedEntry>,
    truncated_content: HashMap<String, TruncatedEntry>,
}

impl Default for TruncationState {
    fn default() -> Self {
        Self::new()
    }
}

impl TruncationState {
    pub fn new() -> Self {
        Self {
            truncated_tool_calls: HashMap::new(),
            truncated_content: HashMap::new(),
        }
    }

    /// Mark a tool call as truncated.
    pub fn mark_tool_truncated(&mut self, tool_call_id: &str) {
        self.truncated_tool_calls
            .insert(tool_call_id.to_string(), TruncatedEntry::new());
    }

    /// Mark content as truncated (by hash).
    pub fn mark_content_truncated(&mut self, content_hash: &str) {
        self.truncated_content
            .insert(content_hash.to_string(), TruncatedEntry::new());
    }

    /// Check if a tool call is marked as truncated.
    /// Returns true only if the entry exists AND is not expired.
    pub fn is_tool_truncated(&self, tool_call_id: &str) -> bool {
        self.truncated_tool_calls
            .get(tool_call_id)
            .is_some_and(|e| !e.is_expired())
    }

    /// Check if content is marked as truncated.
    /// Returns true only if the entry exists AND is not expired.
    pub fn is_content_truncated(&self, content_hash: &str) -> bool {
        self.truncated_content
            .get(content_hash)
            .is_some_and(|e| !e.is_expired())
    }

    /// Remove all expired entries.
    pub fn cleanup_expired(&mut self) {
        self.truncated_tool_calls.retain(|_, e| !e.is_expired());
        self.truncated_content.retain(|_, e| !e.is_expired());
    }

    /// Mark a tool call as truncated with a custom TTL (for testing).
    #[cfg(test)]
    fn mark_tool_truncated_with_ttl(&mut self, tool_call_id: &str, ttl: Duration) {
        self.truncated_tool_calls
            .insert(tool_call_id.to_string(), TruncatedEntry::with_ttl(ttl));
    }

    /// Mark content as truncated with a custom TTL (for testing).
    #[cfg(test)]
    fn mark_content_truncated_with_ttl(&mut self, content_hash: &str, ttl: Duration) {
        self.truncated_content
            .insert(content_hash.to_string(), TruncatedEntry::with_ttl(ttl));
    }
}

/// Generate synthetic tool_result message for a truncated tool call.
/// Returns the `[API Limitation]` formatted message string.
pub fn generate_tool_truncation_message(tool_call_id: &str, tool_name: &str) -> String {
    format!(
        "[API Limitation] The tool call `{}` (`{}`) was truncated by the upstream API \
         due to output size limits.\n\n\
         If the tool result below shows an error or unexpected behavior, this is likely \
         a CONSEQUENCE of the truncation, not the root cause. The tool call itself was \
         cut off before it could be fully transmitted.\n\n\
         Repeating the exact same operation will be truncated again. Consider adapting \
         your approach.",
        tool_name, tool_call_id,
    )
}

/// Generate synthetic user message for content truncation.
pub fn generate_content_truncation_message() -> String {
    "[System Notice] Your previous response was truncated by the API due to \
     output size limitations. This is not an error on your part. \
     If you need to continue, please adapt your approach rather than repeating \
     the same output."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn mark_tool_truncated_then_query_returns_true() {
        let mut state = TruncationState::new();
        state.mark_tool_truncated("call_123");
        assert!(state.is_tool_truncated("call_123"));
    }

    #[test]
    fn is_tool_truncated_returns_false_for_unknown_id() {
        let state = TruncationState::new();
        assert!(!state.is_tool_truncated("nonexistent"));
    }

    #[test]
    fn mark_content_truncated_then_query_returns_true() {
        let mut state = TruncationState::new();
        state.mark_content_truncated("hash_abc");
        assert!(state.is_content_truncated("hash_abc"));
    }

    #[test]
    fn cleanup_expired_removes_old_entries() {
        let mut state = TruncationState::new();
        let zero_ttl = Duration::from_millis(0);
        state.mark_tool_truncated_with_ttl("old_tool", zero_ttl);
        state.mark_content_truncated_with_ttl("old_content", zero_ttl);

        // Ensure the zero-TTL entries are already expired
        thread::sleep(Duration::from_millis(1));

        state.cleanup_expired();
        assert!(!state.is_tool_truncated("old_tool"));
        assert!(!state.is_content_truncated("old_content"));
        assert!(state.truncated_tool_calls.is_empty());
        assert!(state.truncated_content.is_empty());
    }

    #[test]
    fn cleanup_expired_keeps_non_expired_entries() {
        let mut state = TruncationState::new();
        // Default TTL is 5 minutes — these should survive cleanup
        state.mark_tool_truncated("fresh_tool");
        state.mark_content_truncated("fresh_content");

        // Add an already-expired entry alongside
        state.mark_tool_truncated_with_ttl("stale_tool", Duration::from_millis(0));
        thread::sleep(Duration::from_millis(1));

        state.cleanup_expired();

        assert!(state.is_tool_truncated("fresh_tool"));
        assert!(state.is_content_truncated("fresh_content"));
        assert!(!state.is_tool_truncated("stale_tool"));
    }

    #[test]
    fn generate_tool_truncation_message_contains_api_limitation() {
        let msg = generate_tool_truncation_message("call_456", "read_file");
        assert!(msg.contains("[API Limitation]"));
        assert!(msg.contains("read_file"));
        assert!(msg.contains("call_456"));
    }

    #[test]
    fn generate_content_truncation_message_contains_system_notice() {
        let msg = generate_content_truncation_message();
        assert!(msg.contains("[System Notice]"));
    }

    #[test]
    fn default_trait_implementation() {
        let state = TruncationState::default();
        assert!(!state.is_tool_truncated("anything"));
        assert!(!state.is_content_truncated("anything"));
    }

    use proptest::prelude::*;

    proptest! {
        /// Property 4: insert/query roundtrip — mark_tool_truncated then
        /// is_tool_truncated returns true for that ID, false for others.
        #[test]
        fn prop_truncation_insert_query_roundtrip(
            id in "[a-zA-Z0-9_]{1,40}",
            other in "[a-zA-Z0-9_]{1,40}",
        ) {
            let mut state = TruncationState::new();
            state.mark_tool_truncated(&id);
            prop_assert!(state.is_tool_truncated(&id));
            if id != other {
                prop_assert!(!state.is_tool_truncated(&other));
            }
        }

        /// Property 5: after TTL, cleanup_expired removes entries.
        #[test]
        fn prop_truncation_ttl_expiry(id in "[a-zA-Z0-9_]{1,40}") {
            let mut state = TruncationState::new();
            state.mark_tool_truncated_with_ttl(&id, Duration::from_millis(0));
            thread::sleep(Duration::from_millis(1));
            state.cleanup_expired();
            prop_assert!(!state.is_tool_truncated(&id));
        }
    }
}
