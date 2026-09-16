#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "======================================================="
echo "   v2rayA 旁路网关智能分流助手 (Gateway Companion)    "
echo "======================================================="

MODE="${1:-docker}"

if [ "$MODE" = "local" ] || [ "$MODE" = "python" ]; then
    echo "[+] 使用本地 Python3 模式启动 (免 Docker，使用国内清华加速源)..."
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    source venv/bin/activate
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --no-cache-dir -r requirements.txt
    echo "[✓] 正在启动服务..."
    uvicorn app.main:app --host 0.0.0.0 --port 2018
    exit 0
fi

if command -v docker >/dev/null 2>&1; then
    echo "[+] 检测到 Docker 环境，使用 Docker Compose 启动..."
    BUILD_SUCCESS=0
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose up -d --build && BUILD_SUCCESS=1
    else
        docker compose up -d --build && BUILD_SUCCESS=1
    fi
    
    if [ $BUILD_SUCCESS -eq 1 ]; then
        echo ""
        echo "[✓] 启动成功！"
        echo "[*] WebUI 管理面板地址: http://<你的Linux_IP>:2018"
        echo "[*] v2rayA 原生面板地址: http://<你的Linux_IP>:2017"
        exit 0
    else
        echo ""
        echo "[!] Docker 构建失败（通常为国内访问 Docker Hub 超时）。"
        echo "[*] 提示：你可以直接执行 ./run.sh local 使用本地 Python 秒开启动！"
        exit 1
    fi
fi

echo "[!] 未检测到 Docker，尝试直接使用本地 Python 运行..."
if command -v python3 >/dev/null 2>&1; then
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    source venv/bin/activate
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --no-cache-dir -r requirements.txt
    echo "[✓] 正在以前台模式启动服务..."
    uvicorn app.main:app --host 0.0.0.0 --port 2018
else
    echo "[-] 错误：请先安装 Docker 或 Python3 后重试。"
    exit 1
fi
