FROM python:3.12-slim

# Semantic version of this build; passed by docker compose from ./VERSION.
ARG CX_VERSION=dev
ENV CX_VERSION=${CX_VERSION}
LABEL org.opencontainers.image.title="hpe-cx-mcp" \
      org.opencontainers.image.description="ArubaOS-CX MCP server" \
      org.opencontainers.image.version="${CX_VERSION}"

RUN useradd -m -u 1000 mcp && mkdir -p /app/inventory /app/secrets
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py VERSION ./
COPY core/ ./core/
COPY clients/ ./clients/
COPY tools/ ./tools/
COPY security/ ./security/
COPY dispatch/ ./dispatch/
RUN chown -R mcp:mcp /app

USER mcp

EXPOSE 8000

# /healthz returns 200 only when the server can actually serve: inventory
# loaded and not LOCKED (auth enabled with 0 tokens). 503/5xx or a connection
# failure marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import sys,urllib.request\ntry:\n    r=urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)\n    sys.exit(0 if r.status==200 else 1)\nexcept Exception:\n    sys.exit(1)"]

ENTRYPOINT ["python", "server.py"]
