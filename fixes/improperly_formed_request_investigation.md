# "Improperly formed request" 错误调查记录

## 调查日期: 2026-02-16

## 问题概述
Kiro/AWS Q 上游频繁返回 `400 Bad Request`，响应体为：
```json
{"message": "Improperly formed request.", "reason": null}
```

## 错误统计（近6天）

| 日期 | 错误次数 |
|------|---------|
| 2026-02-11 | 0 |
| 2026-02-12 | 68 |
| 2026-02-13 | 7 |
| 2026-02-14 | 163 |
| 2026-02-15 | 24 |
| 2026-02-16 | 41 |
| **总计** | **303** |

## 2026-02-16 详细分析

### 时间分布（3个集中爆发时段）

| 时间段 | 错误数 | Payload 大小 | 历史消息数 | 工具数 |
|--------|--------|-------------|-----------|--------|
| 12:40-12:41 | 14 | 38-39 KB | 6 | 5 (TaskCreate/Get/Update/List, SendMessage) |
| 14:10-14:14 | 15 | 519-536 KB | 96 | 8 (Task系列 + TeamCreate/Delete + SendMessage) |
| 19:04-19:05 | 12 | 475 KB | 306 | 21 (read/edit/write/exec/browser + 更多自定义工具) |

当日总请求量: 1505，错误率: 2.7%

### 根因 1：工具名包含无效字符 `$`（Cluster 1）

- 历史消息中包含 `$Bash` 工具调用（Anthropic computer-use 命名风格）
- `$Bash` 未出现在 currentMessage 声明的工具列表中
- AWS Q API 的 tool name 验证不接受 `$` 字符
- 代码位置: `extract_tool_uses()` (kiro_upstream.rs:133) 直接透传 tool name，无清洗

```
Declared tools: [TaskCreate, TaskGet, TaskUpdate, TaskList, SendMessage]
Used in history: {$Bash, TaskList, TaskUpdate}  ← $Bash 未声明且含非法字符
```

### 根因 2：Payload 过大，超出 API 限制（Clusters 2 & 3）

- Cluster 2: 96 条历史消息，总 ~824KB，其中 History[32] 单条达 215KB
- Cluster 3: 306 条历史消息 + 21 个工具定义，总 ~713KB
- AWS Q generateAssistantResponse API 有请求体大小限制（推测 ~256KB 或更低）
- 代码中 `convert_to_kiro_payload()` 无任何 payload 大小限制或历史截断

### 根因 3：历史中使用了未声明的工具

- Cluster 2 历史中使用了 `Edit`, `Skill`, `Bash` 但未在 tools 列表声明
- 可能触发 AWS Q 的工具引用一致性校验

## 涉及代码

| 文件 | 函数 | 问题 |
|------|------|------|
| `src/proxy/handlers/kiro_upstream.rs:133` | `extract_tool_uses()` | 工具名直接透传，无清洗 |
| `src/proxy/handlers/kiro_upstream.rs:609` | `convert_to_kiro_payload()` | 无 payload 大小限制 |
| `src/proxy/handlers/kiro_upstream.rs:187` | `build_tool_specifications()` | `TOOL_DESCRIPTION_MAX_LENGTH=10000`，但无工具数量限制 |
| `src/proxy/handlers/kiro_upstream.rs:1065` | 常量定义 | 只有描述长度限制，无总体大小限制 |

## 修复方案（待实施）

1. **工具名清洗**: 去掉 `$` 前缀（`$Bash` → `Bash`）
2. **Payload 大小限制**: 对 conversation history 实施滑动窗口截断
3. **上下文压缩**: 当接近上下文窗口限制时自动压缩历史消息（需调查 kiro-gateway 实现）
4. **未声明工具处理**: 历史中引用未声明工具时转为纯文本

## 待调查

- [x] 当前程序是否有上下文压缩功能？ → **没有，完全缺失**
- [x] kiro-gateway 的上下文压缩实现方式 → **也没有上下文压缩**，但有：
  - `sanitize_json_schema()`: 移除 `additionalProperties` 和空 `required: []`（这些会导致 400）
  - `validate_tool_names()`: 验证工具名不超过 64 字符
  - `process_tools_with_long_descriptions()`: 超长工具描述移到 system prompt
  - 截断恢复系统（`truncation_recovery.py` + `truncation_state.py`）：处理**响应**被截断的情况
- [ ] AWS Q API 请求体大小限制的精确值（经验值：~120KB 以上一定失败）

## 已实施的修复

### 1. JSON Schema 清洗 (`sanitize_json_schema`)
从 kiro-gateway 移植。递归移除：
- `additionalProperties` 字段（Kiro API 不支持）
- 空的 `required: []` 数组

### 2. 工具名清洗 (`sanitize_tool_name`)
- 去掉 `$` 前缀（`$Bash` → `Bash`）
- 截断超过 64 字符的工具名

### 3. 工具描述兜底
- 空描述改为 `"Tool: {name}"`（Kiro API 要求非空描述）

### 4. 上下文压缩 (`slim_kiro_payload`)
新增功能（kiro-gateway 也没有）：
- **消息数限制**: 历史消息超过 100 条时裁剪
- **大小限制**: 序列化 payload 超过 120KB 时逐步移除最早的消息对
- **保留策略**: 始终保留前 2 条（含 system prompt）和最后的消息
- **提示注入**: 在裁剪点插入合成 assistant 消息告知模型有消息被省略
- **角色交替**: 裁剪后自动修复 user/assistant 交替顺序

### 修改的文件
- `src/proxy/handlers/kiro_upstream.rs`:
  - 新增 `sanitize_json_schema()` 函数
  - 新增 `sanitize_tool_name()` 函数
  - 修改 `build_tool_specifications()`: 应用 schema 清洗 + 工具名清洗 + 空描述兜底
  - 修改 `extract_tool_uses()`: 应用工具名清洗
  - 新增 `slim_kiro_payload()` 函数
  - 修改 `convert_to_kiro_payload()`: 末尾调用 `slim_kiro_payload()`
  - 新增常量: `MAX_PAYLOAD_CHARS = 120_000`, `MAX_HISTORY_MESSAGES = 100`
