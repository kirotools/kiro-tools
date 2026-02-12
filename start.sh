#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT=8045
BIN="./target/release/kiro-tools"
DIST="./webui/dist"

usage() {
    echo "用法: $0 {start|stop|restart|status|build}"
    echo "  start   - 构建(如需)并启动服务"
    echo "  stop    - 停止服务"
    echo "  restart - 重启服务"
    echo "  status  - 查看运行状态"
    echo "  build   - 仅构建不启动"
    exit 1
}

do_build() {
    echo ">>> 构建后端..."
    cargo build --release

    echo ">>> 构建前端..."
    cd webui
    npm install --legacy-peer-deps
    npm run build
    cd ..

    echo ">>> 构建完成"
}

find_pids() {
    lsof -ti:"$PORT" 2>/dev/null | tr '\n' ' ' | xargs
}

do_start() {
    PIDS=$(find_pids)
    if [ -n "$PIDS" ]; then
        echo "服务已在运行 (PID: $PIDS, 端口: $PORT)"
        return 0
    fi

    if [ ! -f "$BIN" ] || [ ! -d "$DIST" ]; then
        echo "未检测到构建产物，开始构建..."
        do_build
    fi

    echo ">>> 启动 kiro-tools..."
    KIRO_DIST_PATH="$DIST" nohup "$BIN" > kiro-tools.log 2>&1 &
    sleep 1

    PIDS=$(find_pids)
    if [ -n "$PIDS" ]; then
        echo "启动成功 (PID: $PIDS, 端口: $PORT)"
        echo "日志: tail -f kiro-tools.log"
    else
        echo "启动失败，请检查日志: cat kiro-tools.log"
        exit 1
    fi
}

do_stop() {
    PIDS=$(find_pids)
    if [ -z "$PIDS" ]; then
        echo "服务未运行"
        return 0
    fi
    echo ">>> 停止服务 (PID: $PIDS)..."
    kill $PIDS 2>/dev/null || true
    sleep 1
    # 确认已停止
    PIDS=$(find_pids)
    if [ -n "$PIDS" ]; then
        echo "强制终止..."
        kill -9 $PIDS 2>/dev/null || true
    fi
    echo "已停止"
}

do_status() {
    PIDS=$(find_pids)
    if [ -n "$PIDS" ]; then
        echo "运行中 (PID: $PIDS, 端口: $PORT)"
    else
        echo "未运行"
    fi
}

case "${1:-}" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; do_start ;;
    status)  do_status ;;
    build)   do_build ;;
    *)       usage ;;
esac
