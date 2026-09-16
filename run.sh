#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "======================================================="
echo "   v2rayA 旁路网关智能分流助手 (Gateway Companion)    "
echo "======================================================="

if command -v docker >/dev/null 2>&1; then
    echo "[+] 检测到 Docker 环境，使用 Docker Compose 启动..."
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose up -d --build
    else
        docker compose up -d --build
    fi
    echo ""
    echo "[✓] 启动成功！"
    echo "[*] WebUI 管理面板地址: http://<你的Linux_IP>:2018"
    echo "[*] v2rayA 原生面板地址: http://<你的Linux_IP>:2017"
    exit 0
fi

echo "[!] 未检测到 Docker，尝试直接使用本地 Python 运行..."
if command -v python3 >/dev/null 2>&1; then
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    source venv/bin/activate
    pip install -r requirements.txt
    echo "[✓] 正在以前台模式启动服务..."
    uvicorn app.main:app --host 0.0.0.0 --port 2018
else
    echo "[-] 错误：请先安装 Docker 或 Python3 后重试。"
    exit 1
fi
