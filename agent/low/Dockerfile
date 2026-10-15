# Low-interaction honeypot image (task 6.3).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --system --create-home --uid 10010 honeyforge-agent

COPY agent/low/honeyforge_low.py agent/low/profile_runtime.py agent/low/process_masking.py agent/low/main.py ./
COPY honeyforge_common ./honeyforge_common

RUN install -d -o honeyforge-agent -g honeyforge-agent /var/lib/honeyforge \
    && chown -R honeyforge-agent:honeyforge-agent /app
USER honeyforge-agent

CMD ["python", "main.py"]
