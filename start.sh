#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT=${KIRO_PORT:-8045}
BIN="./target/release/kiro-tools"
DIST="./webui/dist"
PID_FILE="kiro-tools.pid"
LOG_FILE="kiro-tools.log"
LOG_MAX_BYTES=$((10 * 1024 * 1024))  # 10MB

# --- 颜色输出 ---
_red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

# --- PID 管理 ---
read_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE"
    fi
}

pid_alive() {
    local pid="$1"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

write_pid() {
    echo "$1" > "$PID_FILE"
}

clean_pid() {
    rm -f "$PID_FILE"
}

# --- 日志轮转 ---
rotate_log() {
    if [ -f "$LOG_FILE" ]; then
        local size
        size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$size" -ge "$LOG_MAX_BYTES" ]; then
            _yellow "日志文件超过 10MB，执行轮转..."
            mv -f "$LOG_FILE" "${LOG_FILE}.1"
        fi
    fi
}

# --- 用法 ---
usage() {
    echo "用法: $0 {start|stop|restart [--rebuild]|status|build|logs|update|version}"
    echo "  start              - 构建(如需)并启动服务"
    echo "  stop               - 停止服务"
    echo "  restart             - 重启服务"
    echo "  restart --rebuild   - 重新构建并重启服务"
    echo "  status             - 查看运行状态"
    echo "  build              - 仅构建不启动"
    echo "  logs               - 查看实时日志"
    echo "  update             - 拉取更新、构建并重启"
    echo "  version            - 显示版本号"
    exit 1
}

# --- 构建 ---
do_build() {
    _green ">>> 构建后端..."
    cargo build --release

    _green ">>> 构建前端..."
    (cd webui && npm install --legacy-peer-deps && npm run build)

    _green ">>> 构建完成"
}

# --- 启动健康检查 ---
wait_healthy() {
    local pid="$1"
    local elapsed=0
    while [ "$elapsed" -lt 5 ]; do
        if ! pid_alive "$pid"; then
            return 1
        fi
        # 优先 curl health 端点
        if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
            return 0
        fi
        # 回退: 检查端口监听
        if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    # 最终检查
    if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
        return 0
    fi
    if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
        return 0
    fi
    return 1
}

# --- 启动 ---
do_start() {
    local pid
    pid=$(read_pid)
    if pid_alive "$pid"; then
        _yellow "服务已在运行 (PID: $pid, 端口: $PORT)"
        return 0
    fi
    # 清理过期 PID 文件
    clean_pid

    if [ ! -f "$BIN" ] || [ ! -d "$DIST" ]; then
        _yellow "未检测到构建产物，开始构建..."
        do_build
    fi

    # 自动检测 KIRO_CREDS_FILE
    if [ -z "${KIRO_CREDS_FILE:-}" ]; then
        local auto_creds="$HOME/.aws/sso/cache/kiro-auth-token.json"
        if [ -f "$auto_creds" ]; then
            export KIRO_CREDS_FILE="$auto_creds"
            _green "自动检测到凭证文件: $auto_creds"
        else
            _yellow "警告: KIRO_CREDS_FILE 未设置，凭证可能需要通过其他方式配置"
        fi
    fi

    rotate_log

    _green ">>> 启动 kiro-tools (端口: $PORT)..."
    KIRO_CREDS_FILE="${KIRO_CREDS_FILE:-}" KIRO_DIST_PATH="$DIST" nohup "$BIN" >> "$LOG_FILE" 2>&1 &
    local new_pid=$!
    write_pid "$new_pid"

    if wait_healthy "$new_pid"; then
        _green "启动成功 (PID: $new_pid, 端口: $PORT)"
        echo "日志: $0 logs"
    else
        _red "启动失败，请检查日志: cat $LOG_FILE"
        clean_pid
        exit 1
    fi
}

# --- 停止 ---
do_stop() {
    local pid
    pid=$(read_pid)
    if ! pid_alive "$pid"; then
        clean_pid
        _yellow "服务未运行"
        return 0
    fi
    _green ">>> 停止服务 (PID: $pid)..."
    kill "$pid" 2>/dev/null || true
    # 等待进程退出 (最多 5 秒)
    local elapsed=0
    while [ "$elapsed" -lt 5 ]; do
        if ! pid_alive "$pid"; then
            break
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    # 强制终止
    if pid_alive "$pid"; then
        _yellow "强制终止..."
        kill -9 "$pid" 2>/dev/null || true
    fi
    clean_pid
    _green "已停止"
}

# --- 状态 ---
do_status() {
    local pid
    pid=$(read_pid)
    if pid_alive "$pid"; then
        _green "运行中 (PID: $pid, 端口: $PORT)"
    else
        clean_pid
        _red "未运行"
    fi
}

# --- 日志 ---
do_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        _yellow "日志文件不存在"
        exit 1
    fi
    tail -f "$LOG_FILE"
}

# --- 更新 ---
do_update() {
    _green ">>> 拉取最新代码..."
    git pull
    _green ">>> 开始构建..."
    do_build
    _green ">>> 重启服务..."
    do_stop
    do_start
}

# --- 版本 ---
do_version() {
    local ver
    ver=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
    echo "kiro-tools v${ver}"
}

# --- 主入口 ---
case "${1:-}" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart)
        if [ "${2:-}" = "--rebuild" ]; then
            do_stop
            do_build
            do_start
        else
            do_stop
            do_start
        fi
        ;;
    status)  do_status ;;
    build)   do_build ;;
    logs)    do_logs ;;
    update)  do_update ;;
    version) do_version ;;
    *)       usage ;;
esac
