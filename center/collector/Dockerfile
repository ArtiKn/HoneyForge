# Collector image (task 6.3).
# Built from the repository root so the ``center`` package is importable.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN useradd --system --create-home --uid 10002 collector

COPY center/collector/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY center ./center
COPY honeyforge_common ./honeyforge_common

RUN chown -R collector:collector /app
USER collector

CMD ["python", "-m", "center.collector"]
