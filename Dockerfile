FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# OpenCV needs libGL and libglib even in headless deployments.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY qrshield ./qrshield
COPY app ./app
COPY allowlist.txt ./
COPY pyproject.toml README.md ./

RUN mkdir -p /app/artifacts /app/data \
    && useradd --create-home --uid 10001 qrshield \
    && chown -R qrshield:qrshield /app
USER qrshield

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"

CMD ["python", "-m", "qrshield", "serve", "--host", "0.0.0.0", "--port", "8000"]
