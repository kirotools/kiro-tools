/// Finite state machine parser that extracts thinking blocks from streaming text.
///
/// Supports configurable tag formats (default: `<thinking>`, `<think>`, `<reasoning>`, `<thought>`).
/// Handles tags split across multiple chunks via cautious buffering.
/// Tag set is driven by configuration, matching `kiro-gateway`'s dynamic approach.

/// Default open tags — used when no custom tags are provided.
const DEFAULT_OPEN_TAGS: [&str; 4] = ["<thinking>", "<think>", "<reasoning>", "<thought>"];

#[derive(Debug, Clone, PartialEq)]
pub enum ThinkingEvent {
    Text(String),
    ThinkingStart,
    ThinkingDelta(String),
    ThinkingEnd,
}

#[derive(Debug, Clone, PartialEq)]
enum ThinkingState {
    Normal,
    PotentialOpen,
    InThinking,
    PotentialClose,
}

#[derive(Debug)]
pub struct ThinkingParser {
    state: ThinkingState,
    buffer: String,
    /// Index into tag_pairs for the currently matched open tag
    active_pair: Option<usize>,
    /// Dynamic tag pairs: (open_tag, close_tag)
    tag_pairs: Vec<(String, String)>,
}

impl ThinkingParser {
    /// Create a parser with default tag set.
    pub fn new() -> Self {
        let tag_pairs = DEFAULT_OPEN_TAGS
            .iter()
            .map(|open| {
                let close = open.replace('<', "</");
                (open.to_string(), close)
            })
            .collect();
        Self {
            state: ThinkingState::Normal,
            buffer: String::new(),
            active_pair: None,
            tag_pairs,
        }
    }

    /// Create a parser with custom open tags (closing tags are derived automatically).
    /// e.g. `["<thinking>", "<think>"]` → `[("<thinking>","</thinking>"), ("<think>","</think>")]`
    pub fn with_tags(open_tags: &[String]) -> Self {
        let tag_pairs = open_tags
            .iter()
            .map(|open| {
                let close = open.replace('<', "</");
                (open.clone(), close)
            })
            .collect();
        Self {
            state: ThinkingState::Normal,
            buffer: String::new(),
            active_pair: None,
            tag_pairs,
        }
    }

    // --- prefix / match helpers ---

    fn is_prefix_of_any_open_tag(&self, s: &str) -> bool {
        self.tag_pairs
            .iter()
            .any(|(open, _)| open.starts_with(s) && open.as_str() != s)
    }

    fn matches_any_open_tag(&self, s: &str) -> Option<usize> {
        self.tag_pairs.iter().position(|(open, _)| open == s)
    }

    fn is_prefix_of_close_tag(&self, s: &str, pair_idx: usize) -> bool {
        let close = &self.tag_pairs[pair_idx].1;
        close.starts_with(s) && close.as_str() != s
    }

    fn matches_close_tag(&self, s: &str, pair_idx: usize) -> bool {
        self.tag_pairs[pair_idx].1 == s
    }

    /// Process a text chunk and return resulting events.
    pub fn feed(&mut self, chunk: &str) -> Vec<ThinkingEvent> {
        let mut events: Vec<ThinkingEvent> = Vec::new();
        let mut text_accum = String::new();

        for ch in chunk.chars() {
            match self.state {
                ThinkingState::Normal => {
                    if ch == '<' {
                        self.buffer.clear();
                        self.buffer.push(ch);
                        self.state = ThinkingState::PotentialOpen;
                    } else {
                        text_accum.push(ch);
                    }
                }

                ThinkingState::PotentialOpen => {
                    self.buffer.push(ch);

                    if let Some(pair_idx) = self.matches_any_open_tag(&self.buffer) {
                        // Flush accumulated text before the tag
                        flush_accum(&mut text_accum, &mut events, &self.state);
                        self.active_pair = Some(pair_idx);
                        self.buffer.clear();
                        self.state = ThinkingState::InThinking;
                        events.push(ThinkingEvent::ThinkingStart);
                    } else if !self.is_prefix_of_any_open_tag(&self.buffer) {
                        // Can't match any open tag — dump buffer as normal text
                        text_accum.push_str(&self.buffer);
                        self.buffer.clear();
                        self.state = ThinkingState::Normal;
                    }
                    // else: still a valid prefix, keep buffering
                }

                ThinkingState::InThinking => {
                    if ch == '<' {
                        // Flush thinking text accumulated so far
                        flush_accum(&mut text_accum, &mut events, &self.state);
                        self.buffer.clear();
                        self.buffer.push(ch);
                        self.state = ThinkingState::PotentialClose;
                    } else {
                        text_accum.push(ch);
                    }
                }

                ThinkingState::PotentialClose => {
                    self.buffer.push(ch);
                    let pair_idx = self
                        .active_pair
                        .expect("active_pair must be set in PotentialClose");

                    if self.matches_close_tag(&self.buffer, pair_idx) {
                        // Flush any thinking delta before the close tag
                        flush_accum(&mut text_accum, &mut events, &ThinkingState::InThinking);
                        self.buffer.clear();
                        self.active_pair = None;
                        self.state = ThinkingState::Normal;
                        events.push(ThinkingEvent::ThinkingEnd);
                    } else if !self.is_prefix_of_close_tag(&self.buffer, pair_idx) {
                        // Not a valid close tag prefix — emit buffer as thinking content
                        text_accum.push_str(&self.buffer);
                        self.buffer.clear();
                        self.state = ThinkingState::InThinking;
                    }
                    // else: still a valid prefix, keep buffering
                }
            }
        }

        // Flush any remaining accumulated text (but NOT the tag buffer — that stays for next chunk)
        flush_accum(&mut text_accum, &mut events, &self.state);

        events
    }

    /// Flush remaining buffer at stream end.
    pub fn flush(&mut self) -> Vec<ThinkingEvent> {
        let mut events: Vec<ThinkingEvent> = Vec::new();

        if !self.buffer.is_empty() {
            match self.state {
                ThinkingState::PotentialOpen => {
                    // Incomplete open tag — emit as plain text
                    events.push(ThinkingEvent::Text(self.buffer.clone()));
                }
                ThinkingState::PotentialClose => {
                    // Incomplete close tag inside thinking — emit as thinking content
                    events.push(ThinkingEvent::ThinkingDelta(self.buffer.clone()));
                }
                _ => {}
            }
            self.buffer.clear();
        }

        // If we're still inside thinking at stream end, there's no ThinkingEnd emitted —
        // the caller can detect this from the absence of ThinkingEnd.

        self.state = ThinkingState::Normal;
        self.active_pair = None;

        events
    }
}

/// Flush the text accumulator into the appropriate event type.
fn flush_accum(accum: &mut String, events: &mut Vec<ThinkingEvent>, state: &ThinkingState) {
    if accum.is_empty() {
        return;
    }
    let text = std::mem::take(accum);
    match state {
        ThinkingState::Normal | ThinkingState::PotentialOpen => {
            events.push(ThinkingEvent::Text(text));
        }
        ThinkingState::InThinking | ThinkingState::PotentialClose => {
            events.push(ThinkingEvent::ThinkingDelta(text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_thinking_block() {
        let mut p = ThinkingParser::new();
        let events = p.feed("<thinking>content</thinking>");
        assert_eq!(
            events,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("content".into()),
                ThinkingEvent::ThinkingEnd,
            ]
        );
    }

    #[test]
    fn text_before_and_after() {
        let mut p = ThinkingParser::new();
        let events = p.feed("hello <thinking>inner</thinking> world");
        assert_eq!(
            events,
            vec![
                ThinkingEvent::Text("hello ".into()),
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("inner".into()),
                ThinkingEvent::ThinkingEnd,
                ThinkingEvent::Text(" world".into()),
            ]
        );
    }

    #[test]
    fn tag_split_across_chunks() {
        let mut p = ThinkingParser::new();

        let e1 = p.feed("<thin");
        assert_eq!(e1, vec![]);

        let e2 = p.feed("king>hello</thinking>");
        assert_eq!(
            e2,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("hello".into()),
                ThinkingEvent::ThinkingEnd,
            ]
        );
    }

    #[test]
    fn close_tag_split_across_chunks() {
        let mut p = ThinkingParser::new();

        let e1 = p.feed("<thinking>data</thin");
        assert_eq!(
            e1,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("data".into()),
            ]
        );

        let e2 = p.feed("king>");
        assert_eq!(e2, vec![ThinkingEvent::ThinkingEnd]);
    }

    #[test]
    fn multiple_thinking_blocks() {
        let mut p = ThinkingParser::new();
        let events = p.feed("<think>a</think>mid<reasoning>b</reasoning>");
        assert_eq!(
            events,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("a".into()),
                ThinkingEvent::ThinkingEnd,
                ThinkingEvent::Text("mid".into()),
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("b".into()),
                ThinkingEvent::ThinkingEnd,
            ]
        );
    }

    #[test]
    fn unclosed_tag_at_flush() {
        let mut p = ThinkingParser::new();

        let e1 = p.feed("<thinking>unclosed content");
        assert_eq!(
            e1,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("unclosed content".into()),
            ]
        );

        let e2 = p.flush();
        assert_eq!(e2, vec![]);
    }

    #[test]
    fn incomplete_open_tag_at_flush() {
        let mut p = ThinkingParser::new();

        let e1 = p.feed("hello <thin");
        assert_eq!(e1, vec![ThinkingEvent::Text("hello ".into())]);

        let e2 = p.flush();
        assert_eq!(e2, vec![ThinkingEvent::Text("<thin".into())]);
    }

    #[test]
    fn no_thinking_tags() {
        let mut p = ThinkingParser::new();
        let events = p.feed("just plain text with no tags");
        assert_eq!(
            events,
            vec![ThinkingEvent::Text("just plain text with no tags".into())]
        );
    }

    #[test]
    fn angle_bracket_not_a_tag() {
        let mut p = ThinkingParser::new();
        let events = p.feed("x < y and a <b> test");
        assert_eq!(
            events,
            vec![ThinkingEvent::Text("x < y and a <b> test".into())]
        );
    }

    #[test]
    fn think_tag_format() {
        let mut p = ThinkingParser::new();
        let events = p.feed("<think>short</think>");
        assert_eq!(
            events,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("short".into()),
                ThinkingEvent::ThinkingEnd,
            ]
        );
    }

    #[test]
    fn reasoning_tag_format() {
        let mut p = ThinkingParser::new();
        let events = p.feed("<reasoning>logic here</reasoning>");
        assert_eq!(
            events,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("logic here".into()),
                ThinkingEvent::ThinkingEnd,
            ]
        );
    }

    #[test]
    fn streaming_char_by_char() {
        let mut p = ThinkingParser::new();
        let input = "<think>hi</think>";
        let mut all_events = Vec::new();
        for ch in input.chars() {
            all_events.extend(p.feed(&ch.to_string()));
        }
        all_events.extend(p.flush());

        // Filter out empty deltas and merge
        let has_start = all_events.contains(&ThinkingEvent::ThinkingStart);
        let has_end = all_events.contains(&ThinkingEvent::ThinkingEnd);
        let thinking_text: String = all_events
            .iter()
            .filter_map(|e| match e {
                ThinkingEvent::ThinkingDelta(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();

        assert!(has_start);
        assert!(has_end);
        assert_eq!(thinking_text, "hi");
    }

    #[test]
    fn incomplete_close_tag_at_flush() {
        let mut p = ThinkingParser::new();

        let e1 = p.feed("<thinking>data</thi");
        assert_eq!(
            e1,
            vec![
                ThinkingEvent::ThinkingStart,
                ThinkingEvent::ThinkingDelta("data".into()),
            ]
        );

        let e2 = p.flush();
        assert_eq!(e2, vec![ThinkingEvent::ThinkingDelta("</thi".into())]);
    }

    // ========================================================================
    // Property tests
    // ========================================================================
    use proptest::prelude::*;

    /// Helper: collect all events from feeding a full string then flushing.
    fn feed_all(input: &str) -> Vec<ThinkingEvent> {
        let mut p = ThinkingParser::new();
        let mut events = p.feed(input);
        events.extend(p.flush());
        events
    }

    /// Helper: concatenate all ThinkingDelta payloads.
    fn collect_thinking(events: &[ThinkingEvent]) -> String {
        events
            .iter()
            .filter_map(|e| match e {
                ThinkingEvent::ThinkingDelta(s) => Some(s.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Helper: concatenate all Text payloads.
    fn collect_text(events: &[ThinkingEvent]) -> String {
        events
            .iter()
            .filter_map(|e| match e {
                ThinkingEvent::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .collect()
    }

    proptest! {
        /// Property 1: ThinkingParser content extraction.
        /// For text with <thinking> tags, ThinkingDelta events concatenate to
        /// the tag content, and Text events concatenate to non-tag content.
        #[test]
        fn prop_thinking_content_extraction(
            before in "[a-zA-Z0-9 ]{0,50}",
            inner in "[a-zA-Z0-9 ]{0,50}",
            after in "[a-zA-Z0-9 ]{0,50}",
        ) {
            let input = format!("{}<thinking>{}</thinking>{}", before, inner, after);
            let events = feed_all(&input);

            let thinking_text = collect_thinking(&events);
            let plain_text = collect_text(&events);

            prop_assert_eq!(thinking_text, inner);
            prop_assert_eq!(plain_text, format!("{}{}", before, after));
        }

        /// Property 2: ThinkingParser chunking invariance.
        /// Splitting text at a random point and feeding two chunks produces
        /// the same concatenated result as feeding the whole string at once.
        #[test]
        fn prop_thinking_chunking_invariance(
            before in "[a-zA-Z0-9 ]{0,30}",
            inner in "[a-zA-Z0-9 ]{0,30}",
            after in "[a-zA-Z0-9 ]{0,30}",
            split_pct in 0..100u32,
        ) {
            let input = format!("{}<thinking>{}</thinking>{}", before, inner, after);

            // Single-feed reference
            let ref_events = feed_all(&input);
            let ref_thinking = collect_thinking(&ref_events);
            let ref_text = collect_text(&ref_events);

            // Split at a percentage point of the byte length (on char boundary)
            let split_byte = (input.len() as u64 * split_pct as u64 / 100) as usize;
            // Find nearest char boundary
            let split_pos = input
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|&i| i <= split_byte)
                .last()
                .unwrap_or(0);

            let (chunk1, chunk2) = input.split_at(split_pos);

            let mut p = ThinkingParser::new();
            let mut events = p.feed(chunk1);
            events.extend(p.feed(chunk2));
            events.extend(p.flush());

            let chunked_thinking = collect_thinking(&events);
            let chunked_text = collect_text(&events);

            prop_assert_eq!(ref_thinking, chunked_thinking);
            prop_assert_eq!(ref_text, chunked_text);
        }
    }

    #[test]
    fn test_thought_tag_detection() {
        let mut p = ThinkingParser::new();
        let events = p.feed("<thought>my thought</thought>rest");
        let mut events_all = events;
        events_all.extend(p.flush());

        let thinking: String = events_all.iter().filter_map(|e| match e {
            ThinkingEvent::ThinkingDelta(t) => Some(t.as_str()),
            _ => None,
        }).collect();
        let text: String = events_all.iter().filter_map(|e| match e {
            ThinkingEvent::Text(t) => Some(t.as_str()),
            _ => None,
        }).collect();

        assert_eq!(thinking, "my thought");
        assert_eq!(text, "rest");
    }
}
