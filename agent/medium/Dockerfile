# Medium-interaction honeypot image (task 6.3).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN mkdir -p /app/agent/low

RUN useradd --system --create-home --uid 10011 agent

RUN pip install --no-cache-dir "asyncssh>=2.20,<3"

COPY agent/medium/main.py ./
COPY agent/low/honeyforge_low.py agent/low/__init__.py ./agent/low/

RUN chown -R agent:agent /app
USER agent

CMD ["python", "main.py"]
