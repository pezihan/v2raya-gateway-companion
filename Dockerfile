ARG BASE_IMAGE=docker.m.daocloud.io/library/python:3.11-slim
FROM ${BASE_IMAGE}

WORKDIR /app

# 替换国内 Debian 软件源以加速 apt
RUN (sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
     sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list 2>/dev/null || true)

# 安装系统依赖（同时兼容 libpcap0.8 与 Debian 13/trixie 的 libpcap0.8t64，并安装编译工具适配 armhf）
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    curl \
    gcc \
    python3-dev \
    && (apt-get install -y --no-install-recommends libpcap0.8t64 2>/dev/null || apt-get install -y --no-install-recommends libpcap0.8 2>/dev/null || true) \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# 使用清华 PyPI 镜像源，防止 pip 下载超时
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

COPY app/ ./app/

EXPOSE 2018

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "2018"]
