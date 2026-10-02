# Shared image for the audit web service and the one-shot verify service.
# Runtime is the Python standard library only -> image build needs no network.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    AUDIT_JOURNAL_PATH=/data/frozen.journal

WORKDIR /app

# Durable frozen-record journal lives on a volume so that it survives
# container restarts and abnormal host power loss.
RUN mkdir -p /data
VOLUME ["/data"]

COPY src/        /app/src/
COPY static/     /app/static/
COPY verify/     /app/verify/
COPY Dockerfile  /app/Dockerfile
COPY .dockerignore /app/.dockerignore

EXPOSE 8080

CMD ["python3", "/app/src/server.py"]
