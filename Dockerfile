FROM python:3.12-slim

RUN useradd -m -u 1000 mcp && mkdir -p /app/inventory /app/secrets
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py ./
COPY core/ ./core/
COPY clients/ ./clients/
COPY tools/ ./tools/
COPY security/ ./security/
COPY dispatch/ ./dispatch/
RUN chown -R mcp:mcp /app

USER mcp

EXPOSE 8000

# Any HTTP response (even an error status, e.g. missing session/auth) proves
# Uvicorn/FastMCP is accepting connections; only a connection failure/timeout
# means the process is stuck or down.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import sys,urllib.request,urllib.error\ntry:\n    urllib.request.urlopen('http://127.0.0.1:8000/mcp', timeout=3)\nexcept urllib.error.HTTPError:\n    pass\nexcept Exception:\n    sys.exit(1)"]

ENTRYPOINT ["python", "server.py"]
