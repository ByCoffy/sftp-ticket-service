FROM python:3.12-slim

LABEL maintainer="sftp-secure-service"
LABEL description="SFTP Ticket Service — Backend API"

# Security: non-root user
RUN groupadd -r sftpapp && useradd -r -g sftpapp -d /app -s /sbin/nologin sftpapp

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libldap2-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /data/sftp-storage /data/keys /data/logs /app \
    && chown -R sftpapp:sftpapp /data /app

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Permissions
RUN chown -R sftpapp:sftpapp /app

USER sftpapp

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--threads", "2", \
     "--timeout", "120", \
     "--access-logfile", "/data/logs/access.log", \
     "--error-logfile", "/data/logs/error.log", \
     "--chdir", "/app/backend", \
     "app:app"]
