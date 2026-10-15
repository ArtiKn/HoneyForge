FROM python:3.12-slim AS bundle
WORKDIR /src
COPY agent ./agent
COPY honeyforge_common ./honeyforge_common
RUN python agent/build_bundle.py --level low --output /out/relay.pyz

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /usr/lib/syslog-relay
RUN useradd --system --user-group --no-create-home --uid 10010 \
    --home-dir /var/lib/syslog-relay --shell /usr/sbin/nologin syslog-relay
COPY --from=bundle /out/relay.pyz ./relay.pyz
RUN install -d -o syslog-relay -g syslog-relay /var/lib/syslog-relay
USER syslog-relay
CMD ["python", "relay.pyz"]
