FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

# Copy source after dep layer is cached
COPY src/ ./src/

# Install the package itself
RUN pip install --no-cache-dir -e .

# Create non-root user and set up directories
RUN groupadd -r rubricai && useradd -r -g rubricai -d /app rubricai \
    && mkdir -p /reports /state \
    && chown -R rubricai:rubricai /app /reports /state

USER rubricai

# SSE transport for remote/Docker deployment
ENV RUBRICAI_TRANSPORT=sse
ENV RUBRICAI_REPORT_DIR=/reports
ENV RUBRICAI_ENV_DIR=/state
# FastMCP binds 127.0.0.1 by default, which the published port cannot reach.
ENV FASTMCP_HOST=0.0.0.0
ENV FASTMCP_PORT=8000

EXPOSE 8000

# /health is exempt from API-key auth. Plain HTTP: override this if TLS is enabled.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

CMD ["python", "-m", "src.main"]
