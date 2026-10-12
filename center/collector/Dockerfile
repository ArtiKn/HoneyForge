# Collector image (task 6.3).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --system --create-home --uid 10002 collector

COPY ingest.py ./

RUN chown -R collector:collector /app
USER collector

CMD ["python", "ingest.py"]
