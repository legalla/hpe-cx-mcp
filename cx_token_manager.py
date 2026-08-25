#!/usr/bin/env python3
"""CLI to manage named Bearer tokens for the CX MCP server.

Usage examples::

    # Generate a token for a named client (name is REQUIRED)
    python cx_token_manager.py generate --name "vscode-dev" --description "Laptop VSCode"

    # List existing tokens (values are masked)
    python cx_token_manager.py list

    # Reveal a token value (recovery)
    python cx_token_manager.py show --name "vscode-dev"

    # Revoke a token
    python cx_token_manager.py revoke --name "vscode-dev"

The tokens file location follows the ``CX_TOKENS_FILE`` environment variable
(or ``--file``), defaulting to the same path the server reads. This script only
uses the Python standard library, so it can run on the host without the MCP
dependencies installed.
"""

from __future__ import annotations

import argparse
import sys

import cx_auth


def _generate(args: argparse.Namespace) -> int:
    was_empty = len(cx_auth.load_tokens(args.file)) == 0
    try:
        record = cx_auth.add_token(args.name, args.description or "", args.file)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print("Generated new token:")
    print(f"  Name        : {args.name}")
    print(f"  Token       : {record['token']}")
    print(f"  Description : {record['description']}")
    print(f"  Created     : {record['created']}")
    print("\n⚠️  Save this token securely — it grants access to the CX MCP server.")
    if was_empty:
        print(
            "\n🔄 This is the FIRST token. If authentication is enabled "
            "(CX_AUTH_ENABLED=true), the MCP services are currently LOCKED. "
            "Apply this token to the running server (no restart needed):\n"
            "    docker compose exec cx-mcp python cx_reload.py\n"
            "  (or restart the container: docker compose restart cx-mcp)"
        )
    return 0


def _list(args: argparse.Namespace) -> int:
    tokens = cx_auth.load_tokens(args.file)
    if not tokens:
        print("No tokens found.")
        return 0
    print(f"{'NAME':<24} {'DESCRIPTION':<40} {'CREATED':<22} TOKEN")
    print("-" * 110)
    for name in sorted(tokens):
        rec = tokens[name]
        tok = rec.get("token", "")
        preview = (tok[:10] + "…") if len(tok) > 10 else tok
        print(f"{name:<24} {rec.get('description',''):<40} {rec.get('created',''):<22} {preview}")
    return 0


def _show(args: argparse.Namespace) -> int:
    tokens = cx_auth.load_tokens(args.file)
    rec = tokens.get(args.name)
    if not rec:
        print(f"Error: no token named '{args.name}'.", file=sys.stderr)
        return 1
    print(rec.get("token", ""))
    return 0


def _revoke(args: argparse.Namespace) -> int:
    if cx_auth.revoke_token(args.name, args.file):
        print(f"Token '{args.name}' has been revoked.")
        return 0
    print(f"Error: no token named '{args.name}'.", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CX MCP token manager")
    parser.add_argument(
        "--file",
        default=None,
        help=f"Path to the tokens file (default: {cx_auth.DEFAULT_TOKENS_FILE} or $CX_TOKENS_FILE).",
    )
    sub = parser.add_subparsers(dest="command")

    g = sub.add_parser("generate", help="Generate a new named token")
    g.add_argument("--name", required=True, help="Unique client name (the identity recorded in audit logs).")
    g.add_argument("--description", help="Free-form description of the token usage.")
    g.set_defaults(func=_generate)

    lst = sub.add_parser("list", help="List tokens (values masked)")
    lst.set_defaults(func=_list)

    sh = sub.add_parser("show", help="Reveal a token value")
    sh.add_argument("--name", required=True, help="Token name to reveal.")
    sh.set_defaults(func=_show)

    rv = sub.add_parser("revoke", help="Revoke (delete) a token")
    rv.add_argument("--name", required=True, help="Token name to revoke.")
    rv.set_defaults(func=_revoke)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
