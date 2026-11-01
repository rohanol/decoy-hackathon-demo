# DeceptionGraph Research Portal (demo-app-01). Build context: dg-soc/demo-app.
# Non-root, no privileges needed, no access log (raw URLs would reach disk).
FROM python:3.11.17-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then \
      PIP_CERT=/run/secrets/proxy_ca pip install --no-cache-dir -r requirements.txt; \
    else pip install --no-cache-dir -r requirements.txt; fi
COPY --chown=1000:1000 portal /app/portal
RUN mkdir -p /telemetry && chown 1000:1000 /telemetry
USER 1000:1000
ENV PORTAL_TELEMETRY_PATH=/telemetry/app.jsonl
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/readyz', timeout=2).status == 200 else 1)"
CMD ["gunicorn", "--bind", "0.0.0.0:8090", "--workers", "1", "--threads", "4", "portal.app:create_app()"]
