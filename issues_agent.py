#!/usr/bin/env python3
"""
eth-phishing-detect Issues Agent
---------------------------------
Triages open GitHub issues on MetaMask/eth-phishing-detect.

Behaviour by issue type:

  BLOCKLIST ADDITION requests:
    - Domain already in config.json  → comment "this domain is already blocked,
                                        thanks for the report" + close (completed)
    - Domain not in config.json      → collect for Slack digest (no GH action)

  BLOCKLIST REMOVAL / LEGITIMATE SITE BLOCKED requests:
    - No meaningful context provided → close as "not planned" (no comment)
    - Domain not in config.json      → collect for Slack digest
    - Domain IS in config.json       → collect for Slack digest
                                        (flag ⚠️ if multiple distinct reporters)

  FEATURE REQUESTS / OTHER:
    - No action taken

Usage:
  # Dry run – preview actions, output digest JSON, no changes made:
  python3 issues_agent.py

  # Execute – apply GH actions, output digest JSON for Slack posting:
  python3 issues_agent.py --execute

  # Single issue:
  python3 issues_agent.py --issue 12345 --execute

Requirements:
  export GITHUB_TOKEN=ghp_your_token_here
"""

import os
import re
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

# ── Load .env if present ──────────────────────────────────────────────────────

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



# ── Config ───────────────────────────────────────────────────────────────────

REPO        = "MetaMask/eth-phishing-detect"
CONFIG_PATH = Path(__file__).parent / "src" / "config.json"
HEADERS     = {"User-Agent": "eth-phishing-agent/1.0",
               "Accept": "application/vnd.github.v3+json"}

LABEL_ADDITION   = "blocklist addition"
LABEL_REMOVAL    = "blocklist removal"

# Minimum body length (chars) to count as "has context"
MIN_CONTEXT_LEN = 80

# File extensions that are not TLDs
FILE_EXTS = {".json", ".js", ".ts", ".py", ".pdf", ".zip", ".png", ".jpg",
             ".svg", ".txt", ".md", ".csv", ".gif", ".ico", ".html", ".xml",
             ".yaml", ".yml"}

# Domains to exclude from extraction
SKIP_DOMAINS = {
    "github.com", "x.com", "twitter.com", "t.me", "telegram.org",
    "etherscan.io", "bscscan.com", "linkedin.com", "google.com",
    "cloudflare.com", "metamask.io", "w3.org", "gmail.com",
    "raw.githubusercontent.com", "private-user-images.githubusercontent.com",
    "advisories.stingray.security", "coingecko.com", "certik.com",
    "chainpatrol.io", "blockaid.io",
}

# ── GitHub API helpers ────────────────────────────────────────────────────────

def _token_headers():
    token = os.environ.get("GITHUB_TOKEN")
    h = dict(HEADERS)
    if token:
        h["Authorization"] = f"token {token}"
    return h


def gh_get(path: str):
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url, headers=_token_headers())
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  ✗ GitHub API {e.code} for {path}: {e.reason}", file=sys.stderr)
        return {}


def gh_post(path: str, data: dict):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN not set")
    h = dict(HEADERS)
    h["Authorization"] = f"token {token}"
    h["Content-Type"] = "application/json"
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=h, method="POST")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def gh_patch(path: str, data: dict):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN not set")
    h = dict(HEADERS)
    h["Authorization"] = f"token {token}"
    h["Content-Type"] = "application/json"
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=h, method="PATCH")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def post_comment(issue_num: int, body: str):
    gh_post(f"/repos/{REPO}/issues/{issue_num}/comments", {"body": body})


def close_issue(issue_num: int, reason: str = "completed"):
    # reason: "completed" | "not_planned"
    gh_patch(f"/repos/{REPO}/issues/{issue_num}",
             {"state": "closed", "state_reason": reason})


# ── Config / blocklist helpers ────────────────────────────────────────────────

def load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {"blacklist": [], "whitelist": [], "fuzzylist": []}


def normalise_domain(domain: str):
    domain = re.sub(r"^https?://", "", domain.strip().lower())
    return domain.split("/")[0].split("?")[0]


def extract_primary_domains(body: str):
    """
    Extract domains from the template's 'Malicious/Legitimate domains' section only.
    Falls back to full-body extraction if the template section isn't found.
    """
    section = ""
    for marker in ["### malicious domains", "### legitimate domains",
                   "malicious domains, ips"]:
        idx = body.lower().find(marker)
        if idx != -1:
            # Take text up to the next section header
            rest = body[idx + len(marker):]
            next_sec = re.search(r"^###", rest, re.MULTILINE)
            section = rest[:next_sec.start()].strip() if next_sec else rest.strip()
            break
    target = section if section else body
    return extract_domains(target)


def extract_domains(text: str):
    if not text:
        return []
    pattern = r"https?://([^\s/\"'>\)]+)|(?<!\w)([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)(?!\w)"
    domains = []
    for m in re.finditer(pattern, text, re.IGNORECASE):
        raw = (m.group(1) or m.group(2) or "").lstrip("*.")
        d = normalise_domain(raw)
        if not d or len(d) < 4:
            continue
        tld_part = d.rsplit(".", 1)[-1] if "." in d else ""
        if not tld_part or len(tld_part) < 2 or f".{tld_part}" in FILE_EXTS:
            continue
        if len(d.split(".")[0]) < 2:
            continue
        if d in SKIP_DOMAINS or any(d.endswith("." + s) for s in SKIP_DOMAINS):
            continue
        if d not in domains:
            domains.append(d)
    return domains


def _candidates(domain: str):
    parts = domain.split(".")
    cands = [domain, f"www.{domain}"]
    if len(parts) > 2:
        cands.append(".".join(parts[-2:]))
    return cands


def in_blacklist(domain: str, config: dict):
    bl = set(config.get("blacklist", []))
    return any(c in bl for c in _candidates(domain))


def in_fuzzylist(domain: str, config: dict):
    fl = set(config.get("fuzzylist", []))
    return any(c in fl for c in _candidates(domain))


def in_any_list(domain: str, config: dict):
    return in_blacklist(domain, config) or in_fuzzylist(domain, config)


def find_listed_domain(domains, config):
    for d in domains:
        if in_any_list(d, config):
            return d
    return None


def any_in_blacklist(domains, config):
    return any(in_blacklist(d, config) for d in domains)

# ── Issue classification ──────────────────────────────────────────────────────

def classify_issue(issue: dict):
    """Returns 'addition' | 'removal' | 'other'"""
    title  = (issue.get("title") or "").lower()
    body   = (issue.get("body")  or "").lower()
    labels = [l["name"] for l in issue.get("labels", [])]

    # Feature / meta signals → skip
    meta_signals = ["feat:", "feature request", "add support for", "bump ",
                    "synchronize repository", "create sync", "concurrency",
                    "[suggestion]"]
    if any(kw in title for kw in meta_signals):
        return "other"
    if any(lbl in labels for lbl in ["dependencies", "enhancement", "improvement"]):
        return "other"

    if LABEL_ADDITION in labels:
        return "addition"
    if LABEL_REMOVAL in labels:
        return "removal"

    # Heuristic fallbacks
    if any(kw in title for kw in ["addition", "malicious", "phishing", "scam",
                                   "drainer", "wallet drainer"]):
        return "addition"
    if any(kw in title for kw in ["removal", "remove", "false positive",
                                   "legitimate", "blocked", "unblock"]):
        return "removal"
    if "malicious domains" in body or "please explain why this content is malicious" in body:
        return "addition"
    if ("legitimate domains" in body
            or "please explain why this content is legitimate" in body
            or "false positive" in body):
        return "removal"

    return "other"


def has_context(issue: dict):
    """
    Returns True if the reporter provided meaningful context beyond just a URL.
    Checks the 'explain why' section of the issue body.
    """
    body = (issue.get("body") or "").strip()
    if not body:
        return False

    # Try to isolate the explanation section from the template.
    # The template has: "### Please explain why this content is legitimate/malicious"
    explain_idx = -1
    for marker in ["### please explain", "please explain why"]:
        idx = body.lower().find(marker)
        if idx != -1:
            explain_idx = idx
            break

    if explain_idx != -1:
        # Skip past the entire header line, not just the matched prefix
        line_end = body.find("\n", explain_idx)
        explanation = body[line_end:].strip() if line_end != -1 else body[explain_idx:].strip()

        # Strip any subsequent section headers
        next_section = re.search(r"^###", explanation, re.MULTILINE)
        if next_section:
            explanation = explanation[:next_section.start()].strip()

        # If the template field was left as "_No response_" or blank, fall back
        # to the content *before* the template section — the reporter may have
        # written their explanation in custom sections above the template fields.
        if not explanation.strip() or explanation.strip().strip("_").lower() == "no response":
            explanation = body[:explain_idx].strip()
    else:
        explanation = body

    # Strip markdown section headers (template boilerplate) before measuring
    text_only = re.sub(r"^#{1,3}[^\n]*\n?", "", explanation, flags=re.MULTILINE)
    # Remove URLs and domain strings to get pure text
    text_only = re.sub(r"https?://\S+", "", text_only)
    text_only = re.sub(r"[a-z0-9\-]+\.[a-z]{2,}", "", text_only, flags=re.IGNORECASE)
    text_only = text_only.strip()

    return len(text_only) >= MIN_CONTEXT_LEN


# ── Stale "needs more information" checker ────────────────────────────────────

MAINTAINER        = "AlexHerman1"
LABEL_NEEDS_INFO  = "needs more information"
STALE_HOURS       = 24
STALE_COMMENT     = "closing due to no response — feel free to reopen if you have more info"


def check_stale_needs_info(execute=False):
    """
    Find open issues labelled 'needs more information' where:
      - The maintainer (@AlexHerman1) has posted at least one comment
      - No reply has been posted AFTER that comment
      - It has been >= 24 hours since the maintainer's last comment

    Closes matching issues as 'not_planned' with a brief note.
    Returns a list of closed issue dicts for the Slack digest.
    """
    now = datetime.now(timezone.utc)
    closed = []

    # Fetch open issues with the label (URL-encode the label name)
    import urllib.parse
    encoded_label = urllib.parse.quote(LABEL_NEEDS_INFO)
    issues = gh_get(
        f"/repos/{REPO}/issues?state=open&per_page=100"
        f"&labels={encoded_label}&sort=updated&direction=desc"
    )
    if not isinstance(issues, list):
        return closed

    for issue in issues:
        if "pull_request" in issue:
            continue

        num    = issue["number"]
        title  = issue.get("title", "")
        author = issue.get("user", {}).get("login", "")
        url    = issue.get("html_url", "")

        comments = gh_get(f"/repos/{REPO}/issues/{num}/comments?per_page=100")
        if not isinstance(comments, list) or not comments:
            continue

        # Find the maintainer's last comment
        maintainer_comments = [c for c in comments
                                if c.get("user", {}).get("login") == MAINTAINER]
        if not maintainer_comments:
            continue

        last_maintainer_comment = maintainer_comments[-1]
        last_maintainer_ts_str  = last_maintainer_comment["created_at"]
        last_maintainer_ts      = datetime.fromisoformat(
            last_maintainer_ts_str.replace("Z", "+00:00"))

        # Check if anyone replied AFTER the maintainer's last comment
        replies_after = [
            c for c in comments
            if c.get("user", {}).get("login") != MAINTAINER
            and datetime.fromisoformat(
                c["created_at"].replace("Z", "+00:00")) > last_maintainer_ts
        ]
        if replies_after:
            continue  # reporter did reply — leave it open

        # Check if 24 hours have elapsed
        hours_elapsed = (now - last_maintainer_ts).total_seconds() / 3600
        if hours_elapsed < STALE_HOURS:
            print(f"  ~ #{num}: needs info, {hours_elapsed:.1f}h elapsed (< {STALE_HOURS}h) — skipping")
            continue

        print(f"  → #{num}: stale after {hours_elapsed:.1f}h — closing as not planned")
        if execute:
            try:
                post_comment(num, STALE_COMMENT)
                close_issue(num, reason="not_planned")
                print(f"    ✓ Commented & closed")
            except Exception as e:
                print(f"    ✗ Failed: {e}")
        else:
            print(f"    ~ [DRY RUN] Would comment & close as not planned")

        closed.append({
            "issue":   num,
            "title":   title,
            "reporter": author,
            "url":     url,
            "hours_elapsed": round(hours_elapsed, 1),
        })
        time.sleep(0.2)

    return closed


# ── Main processing ───────────────────────────────────────────────────────────

def fetch_open_issues(issue_num=None):
    if issue_num:
        result = gh_get(f"/repos/{REPO}/issues/{issue_num}")
        return [result] if result and result.get("state") == "open" else []

    issues, page = [], 1
    while True:
        batch = gh_get(
            f"/repos/{REPO}/issues?state=open&per_page=100&page={page}"
            f"&sort=created&direction=desc"
        )
        if not batch or not isinstance(batch, list):
            break
        issues.extend(i for i in batch if "pull_request" not in i)
        if len(batch) < 100:
            break
        page += 1
        time.sleep(0.3)
    return issues


def process(execute=False, issue_num=None):
    """
    Main loop. Returns a digest dict for Slack posting.
    """
    if execute and not os.environ.get("GITHUB_TOKEN"):
        print("✗ GITHUB_TOKEN not set.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  eth-phishing-detect Issues Agent")
    print(f"  Mode: {'EXECUTE' if execute else 'DRY RUN'}")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}\n")

    # ── Stale needs-info sweep (runs first) ───────────────────────────────────
    print("Checking stale 'needs more information' issues…")
    stale_closed = check_stale_needs_info(execute=execute)
    if not stale_closed:
        print("  None found.\n")
    else:
        print()

    config = load_config()
    print(f"Config: {len(config.get('blacklist',[]))} blacklisted | "
          f"{len(config.get('whitelist',[]))} whitelisted | "
          f"{len(config.get('fuzzylist',[]))} fuzzy\n")

    print("Fetching open issues…")
    issues = fetch_open_issues(issue_num)
    print(f"Found {len(issues)} open issue(s)\n")

    # Digest buckets for Slack
    additions_to_review   = []   # single domain, not yet in blocklist
    bulk_additions        = []   # multiple domains in one issue, not yet in blocklist
    removals_not_in_list  = []   # reporter says blocked but we don't have it
    removals_in_list      = []   # we DO have it, need Alex's call

    # Track domain → list of reporters (for duplicate alert)
    removal_domain_reporters: dict[str, list[dict]] = defaultdict(list)

    stats = {"closed_duplicate": 0, "closed_no_context": 0, "slack_addition": 0,
             "slack_bulk": 0, "slack_removal": 0, "skipped": 0}

    for issue in issues:
        num    = issue["number"]
        title  = issue.get("title", "")
        body   = issue.get("body") or ""
        author = issue.get("user", {}).get("login", "unknown")
        url    = issue.get("html_url", f"https://github.com/{REPO}/issues/{num}")
        kind   = classify_issue(issue)
        domains = extract_domains(body + " " + title)

        print(f"─── #{num}: {title[:70]}")
        print(f"    Type: {kind} | Author: @{author} | Domains: {domains[:3] or '(none)'}")

        # ── EMPTY DESCRIPTION ─────────────────────────────────────────────
        # Close any issue with no body immediately, regardless of type.
        if not body.strip():
            print(f"    → CLOSE (empty description)")
            if execute:
                try:
                    close_issue(num, reason="not_planned")
                    print(f"    ✓ Closed as not planned")
                except Exception as e:
                    print(f"    ✗ {e}")
            else:
                print(f"    ~ [DRY RUN] Would close as not planned")
            stats["closed_no_context"] += 1
            print()
            continue

        # ── FEATURE REQUESTS / OTHER ──────────────────────────────────────
        if kind == "other":
            print(f"    → No action (feature request / out of scope)")
            stats["skipped"] += 1
            print()
            continue

        # ── BLOCKLIST ADDITION ────────────────────────────────────────────
        if kind == "addition":
            primary_domains = extract_primary_domains(body)
            if not primary_domains:
                primary_domains = domains
            if primary_domains and any_in_blacklist(primary_domains, config):
                # Already blocked — close with thanks
                comment = "this domain is already blocked, thanks for the report"
                print(f"    → CLOSE (duplicate) — domain already in blacklist")
                if execute:
                    try:
                        post_comment(num, comment)
                        close_issue(num, reason="completed")
                        print(f"    ✓ Commented & closed")
                    except Exception as e:
                        print(f"    ✗ {e}")
                else:
                    print(f"    ~ [DRY RUN] Would comment & close as completed")
                stats["closed_duplicate"] += 1
            else:
                # Not yet blocked — single vs bulk
                unblocked = [d for d in (primary_domains or domains)
                             if not in_blacklist(d, config)]
                domain_str = unblocked[0] if unblocked else (primary_domains[0] if primary_domains else "(domain not found)")
                entry = {
                    "issue": num,
                    "domain": domain_str,
                    "all_domains": unblocked or primary_domains or domains,
                    "reporter": author,
                    "url": url,
                    "title": title,
                }
                if len(unblocked) > 1:
                    print(f"    → SLACK BULK ({len(unblocked)} domains, needs manual triage)")
                    bulk_additions.append(entry)
                    stats["slack_bulk"] += 1
                else:
                    print(f"    → SLACK (needs actioning via SEAL911)")
                    additions_to_review.append(entry)
                    stats["slack_addition"] += 1

        # ── BLOCKLIST REMOVAL ─────────────────────────────────────────────
        elif kind == "removal":
            context = has_context(issue)

            if not context:
                # No meaningful explanation — close as not planned, silently
                print(f"    → CLOSE (no context provided)")
                if execute:
                    try:
                        close_issue(num, reason="not_planned")
                        print(f"    ✓ Closed as not planned")
                    except Exception as e:
                        print(f"    ✗ {e}")
                else:
                    print(f"    ~ [DRY RUN] Would close as not planned")
                stats["closed_no_context"] += 1
            else:
                listed = find_listed_domain(domains, config)
                domain_str = listed or (domains[0] if domains else "(domain not found)")

                # Track for duplicate detection
                removal_domain_reporters[domain_str].append({
                    "issue": num, "reporter": author, "url": url, "title": title,
                    "in_our_list": listed is not None,
                })

                if listed:
                    print(f"    → SLACK (domain IS in our list — needs Alex's call)")
                    removals_in_list.append({
                        "issue": num, "domain": domain_str, "reporter": author,
                        "url": url, "title": title,
                    })
                else:
                    print(f"    → SLACK (domain not in our list — may be Blockaid)")
                    removals_not_in_list.append({
                        "issue": num, "domain": domain_str, "reporter": author,
                        "url": url, "title": title,
                    })
                stats["slack_removal"] += 1

        print()
        time.sleep(0.15)

    # Build duplicate alerts
    duplicate_alerts = {
        domain: reporters
        for domain, reporters in removal_domain_reporters.items()
        if len(set(r["reporter"] for r in reporters)) > 1
    }

    print(f"{'='*60}")
    print(f"  Summary")
    print(f"{'='*60}")
    print(f"  Closed stale needs-info (no reply 24h) : {len(stale_closed)}")
    print(f"  Closed as duplicate (already blocked) : {stats['closed_duplicate']}")
    print(f"  Closed (no context)                   : {stats['closed_no_context']}")
    print(f"  → Slack: additions needing SEAL911     : {stats['slack_addition']}")
    print(f"  → Slack: bulk additions (manual)       : {stats['slack_bulk']}")
    print(f"  → Slack: removals needing review       : {stats['slack_removal']}")
    print(f"  Skipped (out of scope)                 : {stats['skipped']}")
    if duplicate_alerts:
        print(f"  ⚠️  Duplicate removal requests          : {len(duplicate_alerts)} domain(s)")
    print()

    if not execute:
        print("  ℹ️  DRY RUN — no changes made. Run with --execute to apply.\n")

    return {
        "additions_to_review":  additions_to_review,
        "bulk_additions":       bulk_additions,
        "removals_not_in_list": removals_not_in_list,
        "removals_in_list":     removals_in_list,
        "duplicate_alerts":     duplicate_alerts,
        "stale_closed":         stale_closed,
        "stats":                stats,
        "timestamp":            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "dry_run":              not execute,
    }


# ── Close helper ─────────────────────────────────────────────────────────────

def close_actioned(issue_nums, comment=None, reason="completed"):
    """Close a list of issue numbers, optionally posting a comment first."""
    if not os.environ.get("GITHUB_TOKEN"):
        print("✗ GITHUB_TOKEN not set.", file=sys.stderr)
        sys.exit(1)
    for n in issue_nums:
        try:
            if comment:
                post_comment(n, comment)
            close_issue(n, reason=reason)
            action = "commented & closed" if comment else "closed silently"
            print(f"  ✓ #{n} {action}")
        except Exception as e:
            print(f"  ✗ #{n} failed: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--issue",   type=int, default=None)
    # Close specific issues with a comment after SEAL911 actioning
    parser.add_argument("--close",      type=int, nargs="+", metavar="ISSUE",
                        help="Issue numbers to close")
    parser.add_argument("--comment",    type=str,
                        default="thanks for the report, this has been scheduled for blocking.",
                        help="Comment to post when using --close")
    parser.add_argument("--no-comment", action="store_true",
                        help="Close without posting a comment")
    parser.add_argument("--not-planned", action="store_true",
                        help="Close as not planned instead of completed")
    args = parser.parse_args()

    if args.close:
        print(f"\nClosing {len(args.close)} issue(s)…")
        comment = None if args.no_comment else args.comment
        reason  = "not_planned" if args.not_planned else "completed"
        close_actioned(args.close, comment=comment, reason=reason)
    else:
        digest = process(execute=args.execute, issue_num=args.issue)
        out = Path(__file__).parent / "issues_digest.json"
        with open(out, "w") as f:
            json.dump(digest, f, indent=2)
        print(f"  Digest written to {out.name}")
