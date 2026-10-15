# Medium-interaction honeypot image (task 6.3).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN mkdir -p /app/agent/low

RUN useradd --system --create-home --uid 10011 honeyforge-agent

RUN pip install --no-cache-dir "asyncssh>=2.20,<3"

COPY agent/medium/main.py ./
COPY agent/medium/http_service.py ./agent/medium/
COPY agent/low/honeyforge_low.py agent/low/profile_runtime.py agent/low/process_masking.py agent/low/__init__.py ./agent/low/
COPY honeyforge_common ./honeyforge_common

RUN install -d -o honeyforge-agent -g honeyforge-agent /var/lib/honeyforge \
    && chown -R honeyforge-agent:honeyforge-agent /app
USER honeyforge-agent

CMD ["python", "main.py"]
