FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || true

# Copy source after dep layer is cached
COPY src/ ./src/

# Install the package itself
RUN pip install --no-cache-dir -e .

# SSE transport for remote/Docker deployment
ENV RUBRICAI_TRANSPORT=sse
ENV RUBRICAI_REPORT_DIR=/reports
ENV RUBRICAI_ENV_DIR=/state

EXPOSE 8000

CMD ["python", "-m", "src.main"]
