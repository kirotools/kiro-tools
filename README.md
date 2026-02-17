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
```

## 账号管理

### 方式一：WebUI 管理（推荐）
1. 启动服务后访问 `http://localhost:8045`
2. 在账号管理页面添加/删除账号
3. 账号凭据加密存储在 `~/.kiro_tools/accounts/`

**注意**：账号凭据加密持久化存储，后续启动无需重新配置。

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

# 安装时会自动创建:
#   - kiro-tools 系统用户
#   - /var/lib/kiro-tools 数据目录

# 配置环境变量（可选）
sudo nano /etc/kiro-tools/env
# 取消注释并修改需要的配置项：
#   KIRO_PORT=8045              # 监听端口
#   KIRO_API_KEY=sk-xxx         # API 密钥
#   KIRO_WEB_PASSWORD=xxx       # Web UI 密码
#   KIRO_AUTH_MODE=all_except_health
#   KIRO_BIND_LOCAL_ONLY=false  # 是否仅本地访问

# 启动服务
sudo systemctl start kiro-tools
sudo systemctl enable kiro-tools   # 开机自启

# 查看状态
sudo systemctl status kiro-tools

# 查看日志
journalctl -u kiro-tools -f
```

安装后二进制位于 `/usr/bin/kiro-tools`，前端文件位于 `/usr/share/kiro-tools/dist`，数据目录位于 `/var/lib/kiro-tools`。

### Deb 安装后忘记 API Key / Web UI 密码

Deb 安装通常以 `kiro-tools` 系统服务运行，配置文件不在当前登录用户的 `~/.kiro_tools` 下，而在：

```bash
sudo grep -E '"api_key"|"admin_password"' /var/lib/kiro-tools/gui_config.json
```

也可以从服务日志中查看启动时输出：

```bash
sudo journalctl -u kiro-tools -n 200 | grep -E 'Current API Key|Web UI Password|API Key:'
```

如需确认服务实际使用的数据目录：

```bash
sudo systemctl cat kiro-tools | grep -E 'KIRO_DATA_DIR|EnvironmentFile'
sudo cat /etc/kiro-tools/env
```

## Docker

```bash
docker build -t kiro-tools .

# 基础运行（通过 WebUI 添加账号）
docker run -d -p 8045:8045 \
  -v kiro-data:/root/.kiro_tools \
  kiro-tools

# 自定义端口和配置
docker run -d -p 9000:9000 \
  -e KIRO_PORT=9000 \
  -e KIRO_API_KEY=sk-your-key \
  -e KIRO_WEB_PASSWORD=your-password \
  -v kiro-data:/root/.kiro_tools \
  kiro-tools

# 首次启动后通过 WebUI 添加账号
# 访问 http://localhost:8045 进行配置
```

**重要**：使用 volume 持久化账号数据，否则容器重启后账号丢失。

## 环境变量

所有环境变量都是可选的，未设置时使用默认值或配置文件中的值：

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `KIRO_PORT` / `PORT` | 监听端口 | `8045` |
| `KIRO_API_KEY` / `API_KEY` | 代理 API 密钥 | 自动生成 |
| `KIRO_WEB_PASSWORD` / `WEB_PASSWORD` | Web UI 管理密码 | 与 API Key 相同 |
| `KIRO_AUTH_MODE` / `AUTH_MODE` | 认证模式 (`off`, `strict`, `all_except_health`, `auto`) | `all_except_health` |
| `KIRO_BIND_LOCAL_ONLY` | 是否仅本地访问 (`true`/`false`) | `false` |
| `KIRO_DIST_PATH` | 前端资源路径 | `dist` |
| `KIRO_CF_TUNNEL` | CF Tunnel 模式（`quick`=临时URL，或填入 token） | 无（不启用） |
| `KIRO_CF_AUTO_INSTALL` | 自动安装 cloudflared（`true`/`false`） | `false` |


**注意**：环境变量会覆盖配置文件中的值，并在首次设置后持久化到配置文件。

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
