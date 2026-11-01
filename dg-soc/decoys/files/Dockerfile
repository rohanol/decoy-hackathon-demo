FROM python:3.11.17-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FILE_CONTAINER_BIND=1
WORKDIR /app
COPY decoys/files/requirements.txt /app/requirements.txt
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then PIP_CERT=/run/secrets/proxy_ca pip install --no-cache-dir -r requirements.txt; \
    else pip install --no-cache-dir -r requirements.txt; fi
COPY --chown=1000:1000 decoys/files /app/decoys/files/
COPY --chown=1000:1000 decoys/database /app/decoys/database/
RUN mkdir -p /logs /quarantine && chown 1000:1000 /logs /quarantine
USER 1000:1000
EXPOSE 1445
CMD ["python", "-m", "decoys.files.server", "--host", "0.0.0.0", "--port", "1445", "--log", "/logs/file.json", "--quarantine", "/quarantine"]
