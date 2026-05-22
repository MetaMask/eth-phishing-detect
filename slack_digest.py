#!/usr/bin/env python3
"""
slack_digest.py
---------------
Reads issues_digest.json and posts a formatted summary to Slack
via an incoming webhook.

Usage:
  # Post the most recent digest:
  python3 slack_digest.py

  # Post a specific digest file:
  python3 slack_digest.py --file /path/to/digest.json

Requirements:
  SLACK_WEBHOOK_URL in .env (or exported in the shell)
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path

# ── Load .env ─────────────────────────────────────────────────────────────────

def _load_dotenv():
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

_load_dotenv()

CHANNEL = "epd_issues_agent"

# ── Slack Block Kit formatting ────────────────────────────────────────────────

def _divider():
    return {"type": "divider"}


def _header(text: str):
    return {
        "type": "header",
        "text": {"type": "plain_text", "text": text, "emoji": True},
    }


def _section(text: str):
    return {
        "type": "section",
        "text": {"type": "mrkdwn", "text": text},
    }


def _issue_line(entry: dict) -> str:
    domain = entry.get("domain", "(unknown)")
    url    = entry.get("url", "")
    num    = entry.get("issue", "?")
    reporter = entry.get("reporter", "unknown")
    link   = f"<{url}|#{num}>" if url else f"#{num}"
    return f"• `{domain}` — {link} by @{reporter}"


def build_blocks(digest: dict) -> list:
    blocks = []
    ts      = digest.get("timestamp", "unknown time")
    dry_run = digest.get("dry_run", False)
    stats   = digest.get("stats", {})

    mode_tag = " *(dry run)*" if dry_run else ""
    blocks.append(_header(f"🔍 eth-phishing-detect Issue Digest{mode_tag}"))
    blocks.append(_section(f"_{ts}_"))
    blocks.append(_divider())

    # ── Additions needing SEAL911 ─────────────────────────────────────────────
    additions = digest.get("additions_to_review", [])
    if additions:
        lines = "\n".join(_issue_line(e) for e in additions)
        blocks.append(_section(
            f"*🚨 Additions — needs SEAL911 actioning* ({len(additions)})\n{lines}"
        ))
        blocks.append(_divider())

    # ── Bulk additions ────────────────────────────────────────────────────────
    bulk = digest.get("bulk_additions", [])
    if bulk:
        lines = []
        for e in bulk:
            domain = e.get("domain", "(unknown)")
            all_d  = e.get("all_domains", [])
            url    = e.get("url", "")
            num    = e.get("issue", "?")
            reporter = e.get("reporter", "unknown")
            link   = f"<{url}|#{num}>" if url else f"#{num}"
            extra  = f" (+{len(all_d)-1} more)" if len(all_d) > 1 else ""
            lines.append(f"• `{domain}`{extra} — {link} by @{reporter}")
        blocks.append(_section(
            f"*📦 Bulk additions — manual triage needed* ({len(bulk)})\n" + "\n".join(lines)
        ))
        blocks.append(_divider())

    # ── Removals: domain IS in our list ──────────────────────────────────────
    in_list = digest.get("removals_in_list", [])
    if in_list:
        lines = "\n".join(_issue_line(e) for e in in_list)
        blocks.append(_section(
            f"*⚠️ Removal requests — domain in our list, needs your call* ({len(in_list)})\n{lines}"
        ))
        blocks.append(_divider())

    # ── Removals: domain NOT in our list ─────────────────────────────────────
    not_in_list = digest.get("removals_not_in_list", [])
    if not_in_list:
        lines = "\n".join(_issue_line(e) for e in not_in_list)
        blocks.append(_section(
            f"*🔎 Removal requests — domain not in our list (may be Blockaid)* ({len(not_in_list)})\n{lines}"
        ))
        blocks.append(_divider())

    # ── Duplicate removal alerts ──────────────────────────────────────────────
    dupes = digest.get("duplicate_alerts", {})
    if dupes:
        lines = []
        for domain, reporters in dupes.items():
            nums = ", ".join(f"<{r['url']}|#{r['issue']}>" for r in reporters)
            lines.append(f"• `{domain}` — reported in {nums}")
        blocks.append(_section(
            f"*🔁 Duplicate removal reports* ({len(dupes)} domain(s))\n" + "\n".join(lines)
        ))
        blocks.append(_divider())

    # ── Stale closed ─────────────────────────────────────────────────────────
    stale = digest.get("stale_closed", [])
    if stale:
        lines = []
        for e in stale:
            url  = e.get("url", "")
            num  = e.get("issue", "?")
            hrs  = e.get("hours_elapsed", "?")
            link = f"<{url}|#{num}>" if url else f"#{num}"
            lines.append(f"• {link} — no reply after {hrs}h, closed")
        blocks.append(_section(
            f"*🕐 Stale 'needs more info' — auto-closed* ({len(stale)})\n" + "\n".join(lines)
        ))
        blocks.append(_divider())

    # ── Nothing to action ────────────────────────────────────────────────────
    total_actionable = (len(additions) + len(bulk) + len(in_list)
                        + len(not_in_list) + len(dupes))
    if total_actionable == 0 and not stale:
        blocks.append(_section("✅ Nothing to action — all issues are clean."))
        blocks.append(_divider())

    # ── Stats footer ─────────────────────────────────────────────────────────
    stat_parts = []
    if stats.get("closed_duplicate"):
        stat_parts.append(f"{stats['closed_duplicate']} auto-closed (duplicate)")
    if stats.get("closed_no_context"):
        stat_parts.append(f"{stats['closed_no_context']} auto-closed (no context)")
    if stats.get("skipped"):
        stat_parts.append(f"{stats['skipped']} skipped (out of scope)")
    if stat_parts:
        blocks.append(_section("_Also: " + " · ".join(stat_parts) + "_"))

    return blocks


# ── Post to Slack ─────────────────────────────────────────────────────────────

def post_to_slack(digest: dict, webhook_url: str):
    blocks  = build_blocks(digest)
    payload = {
        "channel": CHANNEL,
        "blocks": blocks,
        "text": "eth-phishing-detect issue digest",  # fallback for notifications
    }
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            body = r.read().decode()
            if body != "ok":
                print(f"  ⚠ Slack responded with: {body}", file=sys.stderr)
            else:
                print(f"  ✓ Posted to #{CHANNEL}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  ✗ Slack error {e.code}: {body}", file=sys.stderr)
        sys.exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

def main(digest_path: Path):
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("✗  SLACK_WEBHOOK_URL not set in .env or environment.", file=sys.stderr)
        sys.exit(1)

    if not digest_path.exists():
        print(f"✗  Digest file not found: {digest_path}", file=sys.stderr)
        sys.exit(1)

    with open(digest_path) as f:
        digest = json.load(f)

    print(f"Posting digest ({digest.get('timestamp', '?')}) to #{CHANNEL}…")
    post_to_slack(digest, webhook_url)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Post issues digest to Slack")
    parser.add_argument(
        "--file",
        type=Path,
        default=Path(__file__).parent / "issues_digest.json",
        help="Path to digest JSON (default: issues_digest.json)",
    )
    args = parser.parse_args()
    main(args.file)
