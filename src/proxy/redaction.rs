use serde_json::Value;

const REDACTED: &str = "[REDACTED]";

pub fn redact_sensitive_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    if let Ok(mut json) = serde_json::from_str::<Value>(input) {
        redact_json_value(&mut json, None);
        return serde_json::to_string(&json).unwrap_or_else(|_| REDACTED.to_string());
    }

    redact_plain_text(input)
}

fn redact_json_value(value: &mut Value, key: Option<&str>) {
    if key.is_some_and(is_sensitive_key) {
        *value = Value::String(REDACTED.to_string());
        return;
    }

    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                redact_json_value(v, Some(k));
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, None);
            }
        }
        Value::String(s) => {
            *s = redact_plain_text(s);
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();

    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "apikey"
            | "xapikey"
            | "adminpassword"
            | "password"
            | "passwd"
            | "secret"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "sessiontoken"
    )
}

fn redact_plain_text(input: &str) -> String {
    let mut out = input.to_string();
    out = redact_after_marker(&out, "Bearer ");
    out = redact_after_marker(&out, "bearer ");
    out
}

fn redact_after_marker(input: &str, marker: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(found) = input[cursor..].find(marker) {
        let start = cursor + found;
        let token_start = start + marker.len();

        result.push_str(&input[cursor..token_start]);

        let mut token_end = token_start;
        for c in input[token_start..].chars() {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '=') {
                token_end += c.len_utf8();
            } else {
                break;
            }
        }

        if token_end > token_start {
            result.push_str(REDACTED);
        }

        cursor = token_end;
    }

    result.push_str(&input[cursor..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_json_keys() {
        let raw = r#"{"accessToken":"abc","refresh_token":"def","safe":"ok"}"#;
        let redacted = redact_sensitive_text(raw);
        assert!(redacted.contains("\"accessToken\":\"[REDACTED]\""));
        assert!(redacted.contains("\"refresh_token\":\"[REDACTED]\""));
        assert!(redacted.contains("\"safe\":\"ok\""));
    }

    #[test]
    fn redacts_bearer_in_plain_text() {
        let raw = "Authorization: Bearer abc.def-123";
        let redacted = redact_sensitive_text(raw);
        assert_eq!(redacted, "Authorization: Bearer [REDACTED]");
    }
}
