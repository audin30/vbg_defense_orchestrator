FROM python:3.12-slim

WORKDIR /srv/app

# System deps: psycopg2-binary ships its own libpq, so no build-essential/libpq-dev needed here.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# CISA KEV / MITRE ATT&CK caches (app/connectors/_http_cache.py) live here.
RUN mkdir -p /srv/app/data
VOLUME ["/srv/app/data"]

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
