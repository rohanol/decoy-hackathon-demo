FROM python:3.11.17-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DB_CONTAINER_BIND=1
WORKDIR /app
COPY --chown=1000:1000 . /app/decoys/database/
RUN mkdir -p /logs && chown 1000:1000 /logs
USER 1000:1000
EXPOSE 3306
# Deployment must use internal/container binding explicitly and publish lab IP only.
CMD ["python", "-m", "decoys.database.server", "--host", "0.0.0.0", "--log", "/logs/db.json"]
