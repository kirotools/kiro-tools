#![allow(dead_code)]
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

const MAX_BUFFER_SIZE: usize = 5000;

static LOG_BRIDGE_ENABLED: AtomicBool = AtomicBool::new(false);
static LOG_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static LOG_BUFFER: OnceLock<Arc<RwLock<VecDeque<LogEntry>>>> = OnceLock::new();

fn get_log_buffer() -> &'static Arc<RwLock<VecDeque<LogEntry>>> {
    LOG_BUFFER.get_or_init(|| Arc::new(RwLock::new(VecDeque::with_capacity(MAX_BUFFER_SIZE))))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: i64,
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: std::collections::HashMap<String, String>,
}

pub fn enable_log_bridge() {
    LOG_BRIDGE_ENABLED.store(true, Ordering::SeqCst);
    tracing::info!("[LogBridge] Debug console enabled");
}

pub fn disable_log_bridge() {
    LOG_BRIDGE_ENABLED.store(false, Ordering::SeqCst);
    tracing::info!("[LogBridge] Debug console disabled");
}

pub fn is_log_bridge_enabled() -> bool {
    LOG_BRIDGE_ENABLED.load(Ordering::SeqCst)
}

pub fn get_buffered_logs() -> Vec<LogEntry> {
    get_log_buffer().read().iter().cloned().collect()
}

pub fn clear_log_buffer() {
    get_log_buffer().write().clear();
}

struct FieldVisitor {
    message: Option<String>,
    fields: std::collections::HashMap<String, String>,
}

impl FieldVisitor {
    fn new() -> Self {
        Self {
            message: None,
            fields: std::collections::HashMap::new(),
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let value_str = format!("{:?}", value);
        if field.name() == "message" {
            self.message = Some(value_str.trim_matches('"').to_string());
        } else {
            self.fields.insert(field.name().to_string(), value_str);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
}

pub struct LogBridgeLayer;

impl LogBridgeLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LogBridgeLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for LogBridgeLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !LOG_BRIDGE_ENABLED.load(Ordering::Relaxed) {
            return;
        }

        let metadata = event.metadata();
        let level = match *metadata.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };

        let mut visitor = FieldVisitor::new();
        event.record(&mut visitor);

        let message = visitor.message.unwrap_or_default();

        if message.is_empty() && visitor.fields.is_empty() {
            return;
        }

        let entry = LogEntry {
            id: LOG_ID_COUNTER.fetch_add(1, Ordering::SeqCst),
            timestamp: chrono::Utc::now().timestamp_millis(),
            level: level.to_string(),
            target: metadata.target().to_string(),
            message,
            fields: visitor.fields,
        };

        let mut buffer = get_log_buffer().write();
        if buffer.len() >= MAX_BUFFER_SIZE {
            buffer.pop_front();
        }
        buffer.push_back(entry);
    }
}

pub fn enable_debug_console() {
    enable_log_bridge();
}

pub fn disable_debug_console() {
    disable_log_bridge();
}

pub fn is_debug_console_enabled() -> bool {
    is_log_bridge_enabled()
}

pub fn get_debug_console_logs() -> Vec<LogEntry> {
    get_buffered_logs()
}

pub fn clear_debug_console_logs() {
    clear_log_buffer();
}
