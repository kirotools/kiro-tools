# Kiro Tools

基于 Kiro (AWS) 的独立代理服务器，提供 Anthropic 兼容的 `/v1/messages` API，支持多账号轮换、WebUI 管理、Credits 额度追踪和 Cloudflare Tunnel。

## 功能

- Anthropic `/v1/messages` 协议代理
- 多账号自动轮换（POWER > PRO+ > PRO > FREE）
- Kiro Credits 额度追踪（含绝对用量显示）
- 动态模型列表（Haiku 4.5 / Sonnet 4.5 / Opus 4.6）
- WebUI 管理界面（账号、代理、安全、日志）
- Cloudflare Tunnel 集成
- Docker 部署（168MB 镜像）

## 快速开始

```bash
# 构建
cargo build --release
cd webui && npm install && npm run build && cd ..
cp -r webui/dist dist

# 运行
KIRO_CREDS_FILE=/path/to/kiro-auth-token.json \
ABV_DIST_PATH=./dist \
./target/release/kiro-tools
```

## Docker

```bash
docker build -t kiro-tools .
docker run -d -p 8045:8045 \
  -e KIRO_CREDS_FILE=/app/creds/kiro-auth-token.json \
  -v /path/to/creds:/app/creds:ro \
  kiro-tools
```

## 许可证

CC BY-NC-SA 4.0 — 仅限非商业用途。

## 致谢

- [Antigravity-Manager](https://github.com/) — 项目骨架（CC BY-NC-SA 4.0）
- [kiro-gateway](https://github.com/jwadow/kiro-gateway) — 认证流程参考（AGPL-3.0）
