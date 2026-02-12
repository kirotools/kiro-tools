/// 流式响应完整性测试
///
/// 用法:
///   cargo test --test stream_test -- --nocapture
///
/// 环境变量:
///   KIRO_TEST_HOST  (默认 http://127.0.0.1:8045)
///   KIRO_TEST_KEY   (默认 sk-test)
///
/// 测试内容:
///   1. 单请求流式完整性 — 检查 SSE 流是否正常结束（message_stop + [DONE]）
///   2. 单请求非流式完整性 — 检查 JSON 响应结构
///   3. 并发流式请求 — 多个流同时进行，验证每个都完整接收

use std::time::Duration;

fn base_url() -> String {
    std::env::var("KIRO_TEST_HOST").unwrap_or_else(|_| "http://127.0.0.1:8045".to_string())
}

fn api_key() -> String {
    std::env::var("KIRO_TEST_KEY").unwrap_or_else(|_| "sk-test".to_string())
}

fn make_request_body(stream: bool, prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "stream": stream,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    })
}

/// 解析 SSE 流，返回 (完整文本, 是否收到 message_stop, 是否收到 [DONE], event 数量)
async fn consume_sse_stream(
    response: reqwest::Response,
) -> Result<(String, bool, bool, usize), String> {
    use futures::StreamExt;

    let mut stream = response.bytes_stream();
    let mut full_data = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Stream chunk error: {}", e))?;
        full_data.extend_from_slice(&chunk);
    }

    let text = String::from_utf8_lossy(&full_data).to_string();

    let mut content = String::new();
    let mut got_message_stop = false;
    let mut got_done = false;
    let mut event_count = 0;

    for line in text.lines() {
        if line.starts_with("data: ") {
            let data = line.trim_start_matches("data: ").trim();
            if data == "[DONE]" {
                got_done = true;
                continue;
            }
            event_count += 1;

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                // Anthropic format
                let event_type = json.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match event_type {
                    "content_block_delta" => {
                        if let Some(delta) = json.get("delta") {
                            if let Some(t) = delta.get("text").and_then(|v| v.as_str()) {
                                content.push_str(t);
                            }
                        }
                    }
                    "message_stop" => {
                        got_message_stop = true;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok((content, got_message_stop, got_done, event_count))
}

// ============================================================================
// 测试 1: 单请求流式完整性
// ============================================================================
#[tokio::test]
async fn test_single_stream_completeness() {
    let client = reqwest::Client::new();
    let url = format!("{}/v1/messages", base_url());

    let body = make_request_body(true, "请用中文写一段200字左右的关于Rust语言优势的介绍。");

    println!(">>> 发送流式请求...");
    let start = std::time::Instant::now();

    let resp = match client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key()))
        .header("Content-Type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .timeout(Duration::from_secs(120))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            println!("⚠ 请求失败 (服务可能未启动): {}", e);
            println!("  跳过测试。请确保服务运行在 {}", base_url());
            return;
        }
    };

    let status = resp.status().as_u16();
    println!(">>> 响应状态: {}", status);

    if status != 200 {
        let body = resp.text().await.unwrap_or_default();
        println!("⚠ 非 200 响应: {}", body);
        println!("  跳过测试（可能没有可用账号）");
        return;
    }

    let (content, got_stop, got_done, event_count) = consume_sse_stream(resp)
        .await
        .expect("SSE 流解析失败");

    let elapsed = start.elapsed();

    println!(">>> 流式结果:");
    println!("  耗时: {:.1}s", elapsed.as_secs_f64());
    println!("  事件数: {}", event_count);
    println!("  内容长度: {} 字符", content.len());
    println!("  收到 message_stop: {}", got_stop);
    println!("  收到 [DONE]: {}", got_done);
    println!("  内容预览: {}...", &content.chars().take(100).collect::<String>());

    assert!(event_count > 0, "应该收到至少一个 SSE 事件");
    assert!(!content.is_empty(), "内容不应为空");
    assert!(got_stop, "流应该以 message_stop 结束（截断检测）");
    assert!(got_done, "流应该以 [DONE] 结束（截断检测）");
}

// ============================================================================
// 测试 2: 单请求非流式完整性
// ============================================================================
#[tokio::test]
async fn test_single_non_stream() {
    let client = reqwest::Client::new();
    let url = format!("{}/v1/messages", base_url());

    let body = make_request_body(false, "用一句话解释什么是Rust的所有权系统。");

    println!(">>> 发送非流式请求...");
    let start = std::time::Instant::now();

    let resp = match client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key()))
        .header("Content-Type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .timeout(Duration::from_secs(120))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            println!("⚠ 请求失败 (服务可能未启动): {}", e);
            return;
        }
    };

    let status = resp.status().as_u16();
    println!(">>> 响应状态: {}", status);

    if status != 200 {
        let body = resp.text().await.unwrap_or_default();
        println!("⚠ 非 200 响应: {}", body);
        return;
    }

    let json: serde_json::Value = resp.json().await.expect("JSON 解析失败");
    let elapsed = start.elapsed();

    println!(">>> 非流式结果:");
    println!("  耗时: {:.1}s", elapsed.as_secs_f64());

    // 验证响应结构
    assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("message"), "type 应为 message");
    assert_eq!(json.get("role").and_then(|v| v.as_str()), Some("assistant"), "role 应为 assistant");

    let content = json.get("content").and_then(|v| v.as_array()).expect("content 应为数组");
    assert!(!content.is_empty(), "content 不应为空");

    let text = content[0].get("text").and_then(|v| v.as_str()).unwrap_or("");
    println!("  内容: {}", text);
    assert!(!text.is_empty(), "文本内容不应为空");

    let usage = json.get("usage").expect("应有 usage 字段");
    let input_tokens = usage.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let output_tokens = usage.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("  Token: input={}, output={}", input_tokens, output_tokens);
    assert!(output_tokens > 0, "output_tokens 应大于 0");
}

// ============================================================================
// 测试 3: 并发流式请求完整性
// ============================================================================
#[tokio::test]
async fn test_concurrent_streams_completeness() {
    let concurrency = 3;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/messages", base_url());

    let prompts = [
        "请列举Rust的3个核心特性，每个用一句话描述。",
        "请用中文写一段100字的关于并发编程的介绍。",
        "请解释什么是零成本抽象，用50字以内。",
    ];

    println!(">>> 发送 {} 个并发流式请求...", concurrency);
    let start = std::time::Instant::now();

    let mut handles = Vec::new();

    for (i, prompt) in prompts.iter().enumerate() {
        let client = client.clone();
        let url = url.clone();
        let key = api_key();
        let body = make_request_body(true, prompt);

        handles.push(tokio::spawn(async move {
            let resp = client
                .post(&url)
                .header("Authorization", format!("Bearer {}", key))
                .header("Content-Type", "application/json")
                .header("anthropic-version", "2023-06-01")
                .json(&body)
                .timeout(Duration::from_secs(120))
                .send()
                .await;

            let resp = match resp {
                Ok(r) => r,
                Err(e) => return (i, Err(format!("请求失败: {}", e))),
            };

            let status = resp.status().as_u16();
            if status != 200 {
                let body = resp.text().await.unwrap_or_default();
                return (i, Err(format!("状态 {}: {}", status, body)));
            }

            match consume_sse_stream(resp).await {
                Ok(result) => (i, Ok(result)),
                Err(e) => (i, Err(e)),
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.expect("task panic"));
    }

    let elapsed = start.elapsed();
    println!(">>> 并发测试完成，总耗时: {:.1}s\n", elapsed.as_secs_f64());

    let mut all_ok = true;
    for (i, result) in &results {
        match result {
            Ok((content, got_stop, got_done, event_count)) => {
                let truncated = if !got_stop || !got_done { " ⚠ 截断!" } else { " ✓" };
                println!(
                    "  请求 #{}: {} 事件, {} 字符, stop={}, done={}{}",
                    i, event_count, content.len(), got_stop, got_done, truncated
                );
                if !got_stop || !got_done {
                    all_ok = false;
                }
            }
            Err(e) => {
                println!("  请求 #{}: ✗ {}", i, e);
                // 不算 all_ok 失败 — 可能是账号不够
            }
        }
    }

    // 至少要有一个成功的请求
    let success_count = results.iter().filter(|(_, r)| r.is_ok()).count();
    println!("\n  成功: {}/{}", success_count, concurrency);

    if success_count > 0 {
        assert!(all_ok, "有流被截断！并发槽位可能过早释放。");
    } else {
        println!("  ⚠ 所有请求都失败了（可能没有可用账号），跳过断言");
    }
}
