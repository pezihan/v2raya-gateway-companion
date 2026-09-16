FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for network capturing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 2018

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "2018"]
