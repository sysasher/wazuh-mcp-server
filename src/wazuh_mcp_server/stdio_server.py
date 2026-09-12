"""
stdio transport for the Wazuh MCP Server.

Claude Desktop (and other local MCP clients) can launch a server directly as a
child process and speak JSON-RPC 2.0 over its stdin/stdout, instead of going
through a network connection. That's a fundamentally different trust model
from the HTTP/SSE transport this project ships by default: with stdio, the
client spawned the process itself, so there's no "who is this request from"
question to answer — no bearer tokens, no OAuth, no CORS, no TLS. All of that
exists in server.py specifically because HTTP is a shared network service
that anyone who can reach the URL could otherwise call.

This module does NOT reimplement any of the Wazuh tool logic. It reuses the
same JSON-RPC dispatcher server.py already uses for HTTP
(`process_mcp_request`, `MCPSession`, `MCPRequest`, the `MCP_METHODS` /
`MCP_NOTIFICATIONS` registries) and just swaps out the transport: read one
JSON-RPC message per line from stdin, dispatch it, write the response as one
JSON-RPC message per line to stdout. Nothing in server.py is modified.

IMPORTANT: stdout must carry ONLY JSON-RPC messages — any stray print() or
misdirected log output on stdout would corrupt the protocol stream from the
client's point of view. All logging here goes to stderr (Python's logging
defaults to stderr, and so does this project's configure_logging()).

Scope model: by default this grants only the read-only `wazuh:read` scope,
same safe default as AUTHLESS_ALLOW_WRITE=false in authless HTTP mode. Set
STDIO_ALLOW_WRITE=true to also grant `wazuh:write`, enabling the active
response / rollback tools (block IP, isolate host, kill process, etc.) over
stdio. Since stdio has no per-request auth check of its own, this is a
blanket, session-wide grant for the lifetime of the process — only enable it
if you're comfortable with Claude having that access every time this server
is launched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger("wazuh_mcp_server.stdio")


def _write_message(payload: Dict[str, Any]) -> None:
    """Write one JSON-RPC message to stdout, newline-delimited."""
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


async def _read_loop() -> None:
    # Imported lazily so `--stdio` never triggers uvicorn/ASGI startup, and so
    # any import-time failure (e.g. missing WAZUH_HOST) can still be reported
    # as a clean JSON-RPC error instead of a bare traceback before we can talk
    # to the client at all.
    from wazuh_mcp_server.auth import AuthToken
    from wazuh_mcp_server.server import (
        MCP_NOTIFICATIONS,
        MCPRequest,
        MCPSession,
        create_error_response,
        is_json_rpc_notification,
        process_mcp_request,
    )
    from pydantic import ValidationError

    allow_write = os.getenv("STDIO_ALLOW_WRITE", "false").strip().lower() in ("true", "1", "yes")
    scopes = ["wazuh:read", "wazuh:write"] if allow_write else ["wazuh:read"]
    logger.info(f"stdio transport starting (scopes={scopes})")

    # One session for the whole process lifetime — stdio has exactly one
    # client: whoever spawned us. No HTTP auth applies, so we hand it a
    # synthetic token directly (mirrors how authless HTTP mode does this)
    # rather than routing through any bearer/OAuth verification path.
    session = MCPSession(f"stdio-{uuid.uuid4()}", origin=None)
    session.authenticated = True
    session._auth_token = AuthToken(
        token="stdio-local",
        api_key_id="stdio-local",
        created_at=datetime.now(timezone.utc),
        scopes=scopes,
    )

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        raw_line = await reader.readline()
        if not raw_line:
            logger.info("stdin closed, exiting")
            return

        line = raw_line.strip()
        if not line:
            continue

        try:
            body = json.loads(line)
        except json.JSONDecodeError as e:
            _write_message(create_error_response(None, -32700, f"Parse error: {e}").dict())
            continue

        if not isinstance(body, dict):
            _write_message(create_error_response(None, -32600, "Invalid Request: expected a JSON object").dict())
            continue

        # Notifications (no "id") never get a response, per JSON-RPC 2.0.
        if is_json_rpc_notification(body):
            handler = MCP_NOTIFICATIONS.get(body.get("method", ""))
            if handler:
                try:
                    await handler(body.get("params") or {}, session)
                except Exception:
                    logger.exception("Error handling notification %s", body.get("method"))
            continue

        try:
            mcp_request = MCPRequest(**body)
        except ValidationError as e:
            _write_message(create_error_response(body.get("id"), -32600, f"Invalid Request: {e}").dict())
            continue

        try:
            response = await process_mcp_request(mcp_request, session)
            _write_message(response.dict())
        except Exception as e:
            logger.exception("Unhandled error processing request")
            _write_message(create_error_response(mcp_request.id, -32603, f"Internal error: {e}").dict())


def main() -> None:
    from wazuh_mcp_server.monitoring import configure_logging
    from wazuh_mcp_server.security import install_log_sanitizer

    # Same log setup the HTTP entry point uses — StreamHandler defaults to
    # stderr, which is what keeps stdout clean for JSON-RPC only.
    configure_logging(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO))
    install_log_sanitizer()

    try:
        asyncio.run(_read_loop())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
