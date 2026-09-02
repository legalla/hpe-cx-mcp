FROM python:3.12-slim

RUN useradd -m -u 1000 mcp && mkdir -p /app/inventory /app/secrets
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aruba_client.py config.py config_backup.py inventory_sources.py server.py ssh_client.py cx_auth.py cx_audit.py cx_token_manager.py cx_reload.py deferred_tools.py tool_prefixes.py write_safety.py flat_tools.py ./
RUN chown -R mcp:mcp /app

USER mcp

EXPOSE 8000

ENTRYPOINT ["python", "server.py"]
