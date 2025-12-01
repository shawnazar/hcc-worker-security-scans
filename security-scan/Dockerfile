# Build stage
FROM python:3.11-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set working directory
WORKDIR /app

# Copy project files for dependency installation
COPY pyproject.toml README.md ./

# Copy lock file if it exists (for reproducible builds)
COPY uv.lock* ./

# Copy source for installation
COPY src/ src/

# Create virtual environment and install the project
RUN uv venv .venv && \
    . .venv/bin/activate && \
    uv pip install .

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy virtual environment from builder (with correct ownership)
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv

# Copy application code (with correct ownership)
COPY --from=builder --chown=appuser:appuser /app/src /app/src

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"
ENV PYTHONUNBUFFERED=1

# Create prowler output directory (before switching to non-root user)
RUN mkdir -p /tmp/prowler && chown appuser:appuser /tmp/prowler

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import pika; print('OK')" || exit 1

# Run the worker
CMD ["python", "-m", "security_scan.main"]
