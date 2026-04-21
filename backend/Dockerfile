FROM python:3.12-slim AS base
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev libxslt-dev libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bundled reference data (rarely changes — own layer for cache efficiency)
COPY data/ ./data/
COPY alembic/ ./alembic/
COPY alembic.ini .
COPY app/ ./app/

# Startup script: run migrations then start server
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8000
CMD ["./entrypoint.sh"]
