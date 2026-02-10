ARG IMAGE_REPO=debian
ARG IMAGE_TAG=trixie-slim
FROM ${IMAGE_REPO}:${IMAGE_TAG} AS builder

RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /usr/src/app/wheels -r requirements.txt

# --- Final Image ---
FROM ${IMAGE_REPO}:${IMAGE_TAG}

RUN groupadd --system --gid 1001 appgroup && \
    useradd --system --uid 1001 --gid appgroup --no-create-home appuser

RUN apt-get update && \
    apt-get install -y python3 python3-pip netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies from wheels
COPY --from=builder /usr/src/app/wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --find-links /wheels -r requirements.txt --break-system-packages --ignore-installed packaging && \
    rm -rf /wheels requirements.txt

# Copy application code and supporting files
COPY migrations/ ./migrations/
COPY app/ ./app
COPY wsgi.py .
COPY entrypoint.py .
COPY --chmod=0755 run_migrate.sh .

# Create necessary directories with proper permissions
RUN mkdir -p /tmp /var/run && \
    chown -R appuser:appgroup /app /tmp /var/run

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8800

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import os, requests; scheme='https' if os.environ.get('ENABLE_APPLICATION_TLS','true').lower() not in ('false','no','off','0') else 'http'; requests.get(f'{scheme}://localhost:8800/health', timeout=5, verify=False)"

ENV GUNICORN_LOG_LEVEL="info"
ENV GUNICORN_CMD_ARGS="--bind=0.0.0.0:8800 --workers=2 --access-logfile - --error-logfile - --logger-class app.gunicorn_logging.CustomGunicornLogger"
ENV ENVIRONMENT="production"
ENV FLASK_APP="wsgi:application"

# Default command
CMD ["python3", "entrypoint.py"]