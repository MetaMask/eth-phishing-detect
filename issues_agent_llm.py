#!/usr/bin/env python3
"""
eth-phishing-detect Issues Agent (LLM edition)
-----------------------------------------------
Drop-in replacement for issues_agent.py that uses Claude instead of
hand-written heuristics for the two fuzzy judgement calls:

  classify_issue()  →  Claude decides addition / removal / other
  has_context()     →  Claude decides whether the reporter explained themselves

Everything else — GitHub API calls, blocklist checks, digest building,
--execute / --issue / --close flags — is identical to issues_agent.py.

Requirements:
  Claude Code CLI installed and authenticated (no API key needed)
  export GITHUB_TOKEN=ghp_...
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


# ── Claude CLI helper ─────────────────────────────────────────────────────────

import subprocess
import shutil

def _claude_bin() -> str:
    """
    Locate the claude CLI binary.
    Checks common install locations if it isn't on the subprocess PATH.
    """
    # shutil.which uses the current process PATH — may differ from the shell
    found = shutil.which("claude")
    if found:
        return found
    # Common install locations on macOS / Linux
    for candidate in [
        "/usr/local/bin/claude",
        "/opt/homebrew/bin/claude",
        os.path.expanduser("~/.npm/bin/claude"),
        os.path.expanduser("~/.local/bin/claude"),
        os.path.expanduser("~/Library/Application Support/Claude/claude-code-vm/2.1.128/claude"),
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("'claude' CLI not found — is Claude Code installed?")


def _ask_claude(system: str, prompt: str) -> str:
    """
    Call the Claude Code CLI non-interactively.
    Uses existing authentication — no API key required.
    """
    full_prompt = f"{system}\n\n---\n\n{prompt}"
    result = subprocess.run(
        [_claude_bin(), "-p", full_prompt],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "non-zero exit")
    return result.stdout.strip().lower()


def _check_claude_cli():
    """Fail fast if the claude CLI isn't available."""
    try:
        _claude_bin()
    except RuntimeError as e:
        print(f"✗  {e}", file=sys.stderr)
        sys.exit(1)


# ── Config ───────────────────────────────────────────────────────────────────

REPO        = "MetaMask/eth-phishing-detect"
CONFIG_PATH = Path(__file__).parent / "src" / "config.json"
HEADERS     = {"User-Agent": "eth-phishing-agent/1.0",
               "Accept": "application/vnd.github.v3+json"}

LABEL_ADDITION   = "blocklist addition"
LABEL_REMOVAL    = "blocklist removal"

# Minimum body length (chars) to count as "has context" — kept as a last-resort
# fallback if the LLM call fails.
MIN_CONTEXT_LEN = 80

FILE_EXTS = {".json", ".js", ".ts", ".py", ".pdf", ".zip", ".png", ".jpg",
             ".svg", ".txt", ".md", ".csv", ".gif", ".ico", ".html", ".xml",
             ".yaml", ".yml"}

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
    section = ""
    for marker in ["### malicious domains", "### legitimate domains",
                   "malicious domains, ips"]:
        idx = body.lower().find(marker)
        if idx != -1:
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


# ── LLM-powered issue classification ─────────────────────────────────────────

_CLASSIFY_SYSTEM = """\
You triage GitHub issues for eth-phishing-detect, a blocklist used by MetaMask
to protect users from phishing sites.

Classify the issue into exactly one category:

  addition  – reporter wants a domain added to the blocklist (phishing, scam,
              wallet drainer, malicious dApp, etc.)
  removal   – reporter wants a domain removed from the blocklist (false positive,
              legitimate site that was wrongly blocked, unblock request)
  other     – feature request, infrastructure change, dependency bump,
              question, duplicate meta-issue, or anything not directly
              about adding/removing a specific domain

Reply with exactly one word: addition, removal, or other."""

_CONTEXT_SYSTEM = """\
You assess whether the reporter of a GitHub issue on eth-phishing-detect has
provided a meaningful explanation for their request — beyond just listing a URL.

A good explanation might include: why they believe the site is malicious or
legitimate, what kind of scam it is, who reported it, what evidence they have,
or why they think the block is a false positive.

A bad (or absent) explanation is: only a domain or URL with no prose, a
template left mostly blank, or just "please remove" / "please add" with no
supporting detail.

Reply with exactly one word: yes (has meaningful context) or no (does not)."""


def classify_issue(issue: dict) -> str:
    """
    Ask Claude to classify the issue as 'addition', 'removal', or 'other'.
    Falls back to the original label-based heuristic if the API call fails.
    """
    title  = (issue.get("title") or "").strip()
    body   = (issue.get("body")  or "").strip()
    labels = [l["name"] for l in issue.get("labels", [])]

    # Fast-path: explicit GitHub labels are reliable, skip the API call.
    if LABEL_ADDITION in labels:
        return "addition"
    if LABEL_REMOVAL in labels:
        return "removal"

    prompt = f"Title: {title}\n\nBody:\n{body[:1500]}"
    if labels:
        prompt += f"\n\nGitHub labels: {', '.join(labels)}"

    try:
        result = _ask_claude(_CLASSIFY_SYSTEM, prompt)
        if result in ("addition", "removal", "other"):
            return result
        # Unexpected output — parse loosely
        if "addition" in result:
            return "addition"
        if "removal" in result or "remove" in result:
            return "removal"
        return "other"
    except Exception as e:
        print(f"    ⚠ classify_issue LLM error: {e} — falling back to heuristic",
              file=sys.stderr)
        return _classify_heuristic(issue)


def _classify_heuristic(issue: dict) -> str:
    """Original keyword-based fallback, used if the Claude call fails."""
    title  = (issue.get("title") or "").lower()
    body   = (issue.get("body")  or "").lower()
    labels = [l["name"] for l in issue.get("labels", [])]

    meta_signals = ["feat:", "feature request", "add support for", "bump ",
                    "synchronize repository", "create sync", "concurrency",
                    "[suggestion]"]
    if any(kw in title for kw in meta_signals):
        return "other"
    if any(lbl in labels for lbl in ["dependencies", "enhancement", "improvement"]):
        return "other"
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


def has_context(issue: dict) -> bool:
    """
    Ask Claude whether the reporter provided a meaningful explanation.
    Falls back to a character-count heuristic if the API call fails.
    """
    title = (issue.get("title") or "").strip()
    body  = (issue.get("body")  or "").strip()

    if not body:
        return False

    prompt = f"Title: {title}\n\nBody:\n{body[:2000]}"

    try:
        result = _ask_claude(_CONTEXT_SYSTEM, prompt)
        return result.startswith("yes")
    except Exception as e:
        print(f"    ⚠ has_context LLM error: {e} — falling back to heuristic",
              file=sys.stderr)
        return _has_context_heuristic(issue)


def _has_context_heuristic(issue: dict) -> bool:
    """Original character-count fallback, used if the Claude call fails."""
    body = (issue.get("body") or "").strip()
    if not body:
        return False
    explain_idx = -1
    for marker in ["### please explain", "please explain why"]:
        idx = body.lower().find(marker)
        if idx != -1:
            explain_idx = idx
            break
    if explain_idx != -1:
        line_end = body.find("\n", explain_idx)
        explanation = body[line_end:].strip() if line_end != -1 else body[explain_idx:].strip()
        next_section = re.search(r"^###", explanation, re.MULTILINE)
        if next_section:
            explanation = explanation[:next_section.start()].strip()
        if not explanation.strip() or explanation.strip().strip("_").lower() == "no response":
            explanation = body[:explain_idx].strip()
    else:
        explanation = body
    text_only = re.sub(r"^#{1,3}[^\n]*\n?", "", explanation, flags=re.MULTILINE)
    text_only = re.sub(r"https?://\S+", "", text_only)
    text_only = re.sub(r"[a-z0-9\-]+\.[a-z]{2,}", "", text_only, flags=re.IGNORECASE)
    return len(text_only.strip()) >= MIN_CONTEXT_LEN


# ── Stale "needs more information" checker ────────────────────────────────────

MAINTAINER        = "AlexHerman1"
LABEL_NEEDS_INFO  = "needs more information"
STALE_HOURS       = 24
STALE_COMMENT     = "closing due to no response — feel free to reopen if you have more info"


def check_stale_needs_info(execute=False):
    now = datetime.now(timezone.utc)
    closed = []

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

        maintainer_comments = [c for c in comments
                                if c.get("user", {}).get("login") == MAINTAINER]
        if not maintainer_comments:
            continue

        last_maintainer_comment = maintainer_comments[-1]
        last_maintainer_ts = datetime.fromisoformat(
            last_maintainer_comment["created_at"].replace("Z", "+00:00"))

        replies_after = [
            c for c in comments
            if c.get("user", {}).get("login") != MAINTAINER
            and datetime.fromisoformat(
                c["created_at"].replace("Z", "+00:00")) > last_maintainer_ts
        ]
        if replies_after:
            continue

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
    if execute and not os.environ.get("GITHUB_TOKEN"):
        print("✗ GITHUB_TOKEN not set.", file=sys.stderr)
        sys.exit(1)

    # Fail fast if the claude CLI isn't available
    _check_claude_cli()

    print(f"\n{'='*60}")
    print(f"  eth-phishing-detect Issues Agent (LLM edition)")
    print(f"  Mode: {'EXECUTE' if execute else 'DRY RUN'}")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}\n")

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

    additions_to_review   = []
    bulk_additions        = []
    removals_not_in_list  = []
    removals_in_list      = []
    removal_domain_reporters: dict[str, list[dict]] = defaultdict(list)

    stats = {"closed_duplicate": 0, "closed_no_context": 0, "slack_addition": 0,
             "slack_bulk": 0, "slack_removal": 0, "skipped": 0}

    for issue in issues:
        num    = issue["number"]
        title  = issue.get("title", "")
        body   = issue.get("body") or ""
        author = issue.get("user", {}).get("login", "unknown")
        url    = issue.get("html_url", f"https://github.com/{REPO}/issues/{num}")
        domains = extract_domains(body + " " + title)

        print(f"─── #{num}: {title[:70]}")

        # Classify via Claude (or fast-path labels)
        kind = classify_issue(issue)
        print(f"    Type: {kind} | Author: @{author} | Domains: {domains[:3] or '(none)'}")

        # ── EMPTY DESCRIPTION ─────────────────────────────────────────────
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
    parser = argparse.ArgumentParser(
        description="eth-phishing-detect issue triage agent (LLM edition)")
    parser.add_argument("--execute",    action="store_true",
                        help="Apply GitHub actions (default: dry run)")
    parser.add_argument("--issue",      type=int, default=None,
                        help="Process a single issue number")
    parser.add_argument("--close",      type=int, nargs="+", metavar="ISSUE",
                        help="Issue numbers to close after SEAL911 actioning")
    parser.add_argument("--comment",    type=str,
                        default="thanks for the report, this has been scheduled for blocking.",
                        help="Comment to post when using --close")
    parser.add_argument("--no-comment", action="store_true",
                        help="Close without posting a comment")
    parser.add_argument("--not-planned", action="store_true",
                        help="Close as not planned instead of completed")
    parser.add_argument("--post-slack", action="store_true",
                        help="Post the digest to Slack after processing (requires SLACK_WEBHOOK_URL in .env)")
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

        if args.post_slack:
            from slack_digest import main as post_digest
            post_digest(out)
