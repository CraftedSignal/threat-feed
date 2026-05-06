#!/usr/bin/env python3
"""Remove invalid IoCs from brief YAML frontmatter and add context to PoC URLs.

Usage:
    python3 scripts/cleanup_iocs.py [--dry-run] [-v]
"""

import re
import sys
from collections import Counter
from ipaddress import ip_address, ip_network
from pathlib import Path

import yaml

BRIEFS_DIR = Path("site/content/briefs")

# --- Classification rules ---

INVALID_URL_SUBSTRINGS = [
    "nvd.nist.gov",
    "nist.gov/vuln",
    "vuldb.com",
    "vulncheck.com",
    "exploit-db.com",
    "cisa.gov",
    "/security/advisories/",
    "github.com/advisories/",
    "github.com/github/",
    "github.com/cisagov/",   # CISA GitHub org — advisory files, not IoCs
    "api.github.com/",        # GitHub API commit/ref endpoints
    "/releases/tag/",
    "/commit/",
    "/commits/",
    "/pull/",
    "/issues/",
    "packages.debian.org",
    "ubuntu.com/security",
    "security.snyk.io",
    "huntr.com",
    "packetstormsecurity.com",
]

# Path markers that indicate a GitHub URL is a PoC / exploit / research repo
# rather than a vendor's own software repo.
_POC_MARKERS = ["poc", "exploit", "cve", "vulnerability", "advisory", "user-attachments/files"]

INVALID_EMAIL_DOMAINS = [
    "nist.gov",
    "electronjs.org",
    "orca.security",
    "github.com",
]

INVALID_DOMAINS = {"github.com", "smtp.github.com"}

INVALID_IP_NETS = [
    ip_network("0.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]


def _is_private_ip(value: str) -> bool:
    try:
        addr = ip_address(value.strip())
        return any(addr in net for net in INVALID_IP_NETS)
    except ValueError:
        return False


def _should_remove(ioc: dict) -> tuple[bool, str]:
    t = ioc.get("type", "").lower()
    v = str(ioc.get("value", ""))
    # Email obfuscation placeholders (Cloudflare or similar) — never a real IoC
    if "[email" in v.lower() or "&#160;" in v:
        return True, "email obfuscation placeholder"
    if t == "url":
        if any(s in v for s in INVALID_URL_SUBSTRINGS):
            return True, "reference/advisory URL"
    elif t == "email":
        domain = v.split("@")[-1].lower() if "@" in v else ""
        if any(domain.endswith(d) for d in INVALID_EMAIL_DOMAINS):
            return True, "reference/researcher email"
    elif t in ("ip", "ipv4", "ipv6"):
        if _is_private_ip(v):
            return True, "private/special-purpose IP"
    elif t == "domain":
        if v.lower() in INVALID_DOMAINS:
            return True, "legitimate service domain"
    return False, ""


def _needs_poc_context(ioc: dict) -> bool:
    if ioc.get("context"):
        return False
    t = ioc.get("type", "").lower()
    v = str(ioc.get("value", ""))
    if t != "url" or "github.com" not in v:
        return False
    if any(s in v for s in INVALID_URL_SUBSTRINGS):
        return False
    # Only flag as PoC when the URL path contains an explicit research/exploit marker.
    # This avoids mislabelling vendor software repos (kyverno, sharp, etc.).
    v_lower = v.lower()
    return any(m in v_lower for m in _POC_MARKERS)


# --- YAML block manipulation (surgical — preserves all other frontmatter formatting) ---

def _remove_key_block(lines: list[str], key: str) -> list[str]:
    """Remove a top-level YAML key and all its indented continuation lines."""
    out: list[str] = []
    in_block = False
    for line in lines:
        if not in_block:
            if re.match(rf"^{re.escape(key)}:", line):
                in_block = True
            else:
                out.append(line)
        else:
            if line.startswith(" ") or line.startswith("\t"):
                pass  # skip indented continuation
            else:
                in_block = False
                out.append(line)
    return out


def _yaml_scalar(value: str) -> str:
    """Return a YAML-safe scalar representation of value."""
    # Values that need quoting
    needs_quote = (
        not value
        or value[0] in ('"', "'", "{", "[", "|", ">", "!", "%", "@", "`")
        or ": " in value
        or value.endswith(":")
        or value in ("true", "false", "null", "yes", "no", "on", "off")
    )
    if needs_quote:
        return yaml.dump(value, default_flow_style=True).strip()
    return value


def _format_iocs(iocs: list[dict]) -> str:
    if not iocs:
        return ""
    lines = ["iocs:"]
    for ioc in iocs:
        lines.append(f"  - type: {ioc['type']}")
        lines.append(f"    value: {_yaml_scalar(str(ioc['value']))}")
        if ioc.get("context"):
            lines.append(f"    context: {_yaml_scalar(str(ioc['context']))}")
    return "\n".join(lines) + "\n"


def _format_counts(counts: Counter) -> str:
    if not counts:
        return ""
    lines = ["ioc_counts:"]
    for k, v in sorted(counts.items()):
        lines.append(f"  {k}: {v}")
    return "\n".join(lines) + "\n"


def _insert_before_first_anchor(lines: list[str], anchors: list[str], insert_text: str) -> list[str]:
    """Insert lines of insert_text before the first line matching any anchor key."""
    insert_lines = insert_text.rstrip("\n").splitlines()
    for i, line in enumerate(lines):
        if any(line == f"{a}:" or line.startswith(f"{a}: ") for a in anchors):
            return lines[:i] + insert_lines + lines[i:]
    return lines + insert_lines


def process_file(path: Path, dry_run: bool) -> dict | None:
    text = path.read_text()
    if "iocs:" not in text:
        return None

    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end == -1:
        return None
    fm_str = text[4:end]
    body = text[end + 5:]

    try:
        fm = yaml.safe_load(fm_str)
    except yaml.YAMLError:
        return None

    orig_iocs = fm.get("iocs") or []
    if not orig_iocs:
        return None

    kept: list[dict] = []
    removed: list[tuple[dict, str]] = []
    context_added = 0

    for ioc in orig_iocs:
        should_rm, reason = _should_remove(ioc)
        if should_rm:
            removed.append((ioc, reason))
        else:
            if _needs_poc_context(ioc):
                ioc = dict(ioc, context="Proof-of-concept exploit code")
                context_added += 1
            kept.append(ioc)

    if not removed and context_added == 0:
        return None

    if not dry_run:
        lines = fm_str.split("\n")
        lines = _remove_key_block(lines, "iocs")
        lines = _remove_key_block(lines, "ioc_counts")
        if kept:
            new_block = _format_iocs(kept) + _format_counts(Counter(i["type"] for i in kept))
            lines = _insert_before_first_anchor(lines, ["rules", "rules_count"], new_block)
        new_text = "---\n" + "\n".join(lines) + "\n---\n" + body
        path.write_text(new_text)

    return {"removed": removed, "kept": kept, "context_added": context_added}


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    check = "--check" in sys.argv   # like dry-run but exits non-zero if issues found
    verbose = "-v" in sys.argv or dry_run or check

    if check:
        dry_run = True  # --check implies dry-run

    total_removed = 0
    total_ctx = 0
    changed: list[str] = []

    for path in sorted(BRIEFS_DIR.glob("*.md")):
        r = process_file(path, dry_run)
        if not r:
            continue
        changed.append(path.name)
        total_removed += len(r["removed"])
        total_ctx += r["context_added"]
        if verbose:
            print(f"\n{path.name}")
            for ioc, reason in r["removed"]:
                print(f"  INVALID [{ioc.get('type')}] {ioc.get('value')} — {reason}")
            for ioc in r["kept"]:
                if ioc.get("context") == "Proof-of-concept exploit code":
                    print(f"  NEEDS CONTEXT [{ioc.get('type')}] {ioc.get('value')}")

    if check:
        if changed:
            print(f"\n✗ {len(changed)} brief(s) contain {total_removed} invalid IoC(s) and/or {total_ctx} unannotated PoC URL(s).")
            print("  Run: python3 scripts/cleanup_iocs.py  (to fix automatically)")
            sys.exit(1)
        else:
            print("✓ All IoCs look clean.")
    else:
        label = "Would change" if dry_run else "Changed"
        print(f"\n{label} {len(changed)} file(s): removed {total_removed} invalid IoC(s), added context to {total_ctx}")
        if dry_run:
            print("Run without --dry-run to apply.")


if __name__ == "__main__":
    main()
