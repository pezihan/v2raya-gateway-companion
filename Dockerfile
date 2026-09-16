ARG BASE_IMAGE=docker.m.daocloud.io/library/python:3.11-slim
FROM ${BASE_IMAGE}

WORKDIR /app

# 替换国内 Debian 软件源以加速 apt
RUN (sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
     sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list 2>/dev/null || true)

# Install system dependencies for network capturing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# 使用清华 PyPI 镜像源，防止 pip 下载超时
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

COPY app/ ./app/

EXPOSE 2018

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "2018"]
