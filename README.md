# Kiro Tools

基于 Kiro (AWS) 的独立代理服务器，提供 Anthropic 兼容的 `/v1/messages` API，支持多账号轮换、WebUI 管理、Credits 额度追踪和 Cloudflare Tunnel。

## 功能

- Anthropic `/v1/messages` 协议代理
- **多账号持久化存储**（AES-256-GCM 加密）
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
KIRO_DIST_PATH=./dist ./target/release/kiro-tools

# 首次启动后，通过 WebUI (http://localhost:8045) 添加账号
# 或设置 KIRO_CREDS_FILE 环境变量自动导入首个账号
```

## 账号管理

### 方式一：WebUI 管理（推荐）
1. 启动服务后访问 `http://localhost:8045`
2. 在账号管理页面添加/删除账号
3. 账号凭据加密存储在 `~/.kiro_tools/accounts/`

### 方式二：环境变量自动导入（仅首次）
```bash
# 如果没有账号，程序会自动从 KIRO_CREDS_FILE 导入
KIRO_CREDS_FILE=/path/to/kiro-auth-token.json ./target/release/kiro-tools
```

**注意**：导入后凭据持久化存储，后续启动无需再设置环境变量。

## 一键脚本

```bash
./start.sh start    # 构建(如需)并启动
./start.sh stop     # 停止
./start.sh restart  # 重启
./start.sh status   # 查看状态
./start.sh build    # 仅构建
```

Deb 安装时使用 systemctl：

```bash
sudo systemctl start kiro-tools
sudo systemctl stop kiro-tools
sudo systemctl restart kiro-tools
```

## Deb 安装

```bash
# 下载并安装
sudo dpkg -i kiro-tools_*_amd64.deb

# 启动服务
sudo systemctl start kiro-tools
sudo systemctl enable kiro-tools   # 开机自启

# 查看状态
sudo systemctl status kiro-tools

# 查看日志
journalctl -u kiro-tools -f
```

安装后二进制位于 `/usr/bin/kiro-tools`，前端文件位于 `/usr/share/kiro-tools/dist`。

## Docker

```bash
docker build -t kiro-tools .

# 基础运行（通过 WebUI 添加账号）
docker run -d -p 8045:8045 \
  -v kiro-data:/root/.kiro_tools \
  kiro-tools

# 或首次自动导入账号
docker run -d -p 8045:8045 \
  -e KIRO_CREDS_FILE=/app/creds/kiro-auth-token.json \
  -v /path/to/creds:/app/creds:ro \
  -v kiro-data:/root/.kiro_tools \
  kiro-tools
```

**重要**：使用 volume 持久化账号数据，否则容器重启后账号丢失。

## 安全特性

- **加密存储**：账号凭据使用 AES-256-GCM 加密
- **文件权限**：账号文件权限设置为 600（仅所有者可读写）
- **内存安全**：敏感数据使用 Zeroize 安全清零
- **自动迁移**：启动时自动将旧版明文账号迁移到加密存储

## 许可证

CC BY-NC-SA 4.0 — 仅限非商业用途。

## 致谢

- [Antigravity-Manager](https://github.com/) — 项目骨架（CC BY-NC-SA 4.0）
- [kiro-gateway](https://github.com/jwadow/kiro-gateway) — 认证流程参考（AGPL-3.0）
