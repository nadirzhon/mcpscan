"""mcpscan — security scanner for MCP servers.

Usage:
    mcpscan <server>                 # e.g. https://host/mcp, "python server.py", or "uvx some-mcp"
    mcpscan <server> --ai            # add Claude-assisted threat analysis (needs ANTHROPIC_API_KEY)
    mcpscan <server> --json          # machine-readable output\n    mcpscan <server> --sarif         # SARIF 2.1.0 for GitHub Code Scanning
    mcpscan <server> --fail-on high  # exit non-zero at this severity or above
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from . import __version__, report
from .checks import check_surface
from .connect import fetch_surface


def _run(args) -> int:
    try:
        surface = asyncio.run(fetch_surface(args.server))
    except Exception as e:  # noqa: BLE001
        print(f"error: could not connect to MCP server {args.server!r}: {e}", file=sys.stderr)
        return 2

    findings = check_surface(surface)

    if args.ai:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            print("warning: --ai set but ANTHROPIC_API_KEY is unset; skipping AI analysis.", file=sys.stderr)
        else:
            try:
                import anthropic

                from .ai import analyze
                client = anthropic.Anthropic(api_key=key)
                findings.extend(analyze(client, args.model, surface))
            except Exception as e:  # noqa: BLE001
                print(f"warning: AI analysis skipped: {type(e).__name__}: {e}", file=sys.stderr)

    counts = {k: len(surface.get(k, [])) for k in ("tools", "resources", "prompts")}

    if args.json:
        print(report.to_json(args.server, findings))
    elif args.markdown:
        print(report.to_markdown(args.server, findings, counts))
    else:
        print(report.to_terminal(args.server, findings, counts))

    if args.fail_on != "none":
        threshold = report.rank(args.fail_on)
        if any(report.rank(f.get("severity", "info")) >= threshold for f in findings):
            return 1
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcpscan", description="Security scanner for MCP servers.")
    p.add_argument("server", help="MCP server: an http(s) URL, a server script path, or a stdio command string.")
    p.add_argument("--ai", action="store_true", help="Add Claude-assisted threat analysis (needs ANTHROPIC_API_KEY).")
    p.add_argument("--model", default="claude-opus-5", help="Claude model for --ai (default: claude-opus-5).")
    p.add_argument("--json", action="store_true", help="Output JSON.")
    p.add_argument("--markdown", action="store_true", help="Output Markdown.")\n    p.add_argument("--sarif", action="store_true", help="Output SARIF 2.1.0 for GitHub Code Scanning.")
    p.add_argument("--fail-on", default="none",
                   choices=["none", "low", "medium", "high", "critical"],
                   help="Exit non-zero when a finding is at this severity or higher.")
    p.add_argument("--version", action="version", version=f"mcpscan {__version__}")
    return _run(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
