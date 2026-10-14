# Low-interaction honeypot image (task 6.3).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --system --create-home --uid 10010 agent

COPY honeyforge_low.py profile_runtime.py main.py ./

RUN install -d -o agent -g agent /var/lib/honeyforge \
    && chown -R agent:agent /app
USER agent

CMD ["python", "main.py"]
