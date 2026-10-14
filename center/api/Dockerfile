# Control API image (task 6.3).
# Built from the repository root so the whole ``center`` package is available.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN useradd --system --create-home --uid 10001 appuser

COPY center/api/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY center ./center
COPY honeyforge_common ./honeyforge_common
COPY alembic.ini ./alembic.ini

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Apply migrations, then serve the API (task 2.1, 6.1).
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn center.api.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips=${TRUSTED_PROXY_IPS:?TRUSTED_PROXY_IPS is required} --log-config center/logging.json"]
