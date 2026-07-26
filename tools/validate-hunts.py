#!/usr/bin/env python3
"""
validate-hunts.py — integrity checker for the threat-hunting-sentinel-defender
Hunt Card library. Stdlib-only (no pip installs), so it runs identically in CI
and locally.

Checks, per Hunt Card:
  - Required sections present (Metadata, Trigger, Hypothesis, Scope, Hunt Query,
    Triage Guidance, Validation, Outcome, References)
  - A Hunt ID, at least one ATT&CK technique, and a primary ```kql block
  - Author is the full name (no GitHub handle leaked)
  - KQL convention: no '| take N' in the primary query
  - Purple-team Validation section present

Repo-wide:
  - mapping/mitre-attack.yaml <-> hunts/ on disk are bijective (every card
    registered, every registered file exists), Hunt IDs unique
  - README badge / index-row count matches the number of hunts
  - ATTACK_MATRIX Hunt-Card count matches
  - deploy/ ARM templates are valid JSON

Exit 0 = all good; exit 1 = one or more failures (CI-friendly).
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HUNTS = os.path.join(REPO, "hunts")

REQUIRED_SECTIONS = [
    "## Metadata",
    "## 1. Trigger",
    "## 2. Hypothesis",
    "## 3. Scope",
    "## 4. Hunt Query",
    "## 5. Triage Guidance",
    "## Validation (Purple Team)",
    "## 6. Outcome",
    "## References",
]

RE_HUNT_ID = re.compile(r"(?im)\|\s*\**\s*Hunt ID\s*\**\s*\|\s*([A-Z0-9\-]+)\s*\|")
RE_TACTIC = re.compile(r"(?im)\|\s*\**\s*Tactic\s*\**\s*\|\s*([^\|\r\n]+?)\s*\|")
RE_KQL = re.compile(r"(?s)```kql\s*(.+?)```")
RE_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
RE_TAKE = re.compile(r"\|\s*take\s+\d")
RE_HANDLE = re.compile(r"rizko-d|@rizko", re.IGNORECASE)

SENTINEL_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
}


def discover_hunt_files():
    out = []
    for root, _, files in os.walk(HUNTS):
        for fn in files:
            if fn.endswith(".md"):
                out.append(os.path.relpath(os.path.join(root, fn), REPO))
    return sorted(out)


def check_card(rel, errors):
    md = open(os.path.join(REPO, rel), encoding="utf-8").read()

    for sec in REQUIRED_SECTIONS:
        if sec not in md:
            errors.append(f"{rel}: missing section '{sec}'")

    if not RE_HUNT_ID.search(md):
        errors.append(f"{rel}: no Hunt ID in metadata table")
    if not RE_TECH.search(md):
        errors.append(f"{rel}: no ATT&CK technique id (Txxxx) found")

    kql = RE_KQL.search(md)
    if not kql:
        errors.append(f"{rel}: no ```kql primary query block")
    elif RE_TAKE.search(kql.group(1)):
        errors.append(f"{rel}: '| take N' present in primary KQL (convention: end with '| order by ... desc')")

    if "Rizko Febri Rachmayadi" not in md:
        errors.append(f"{rel}: author full name missing")
    if RE_HANDLE.search(md):
        errors.append(f"{rel}: GitHub handle leaked (use full name only)")

    tac = RE_TACTIC.search(md)
    if tac:
        first = tac.group(1).split("/")[0].strip().lower().replace(" ", "-")
        if first not in SENTINEL_TACTICS:
            errors.append(f"{rel}: unmapped tactic '{first}'")


def parse_yaml_refs():
    text = open(os.path.join(REPO, "mapping/mitre-attack.yaml"), encoding="utf-8").read()
    blocks = re.split(r"\n\s*-\s*id:", text)[1:]
    ids, files = [], []
    for b in blocks:
        ids.append(b.splitlines()[0].strip())
        m = re.search(r"^\s*file:\s*(\S+)", b, re.M)
        if m:
            files.append(m.group(1))
    return ids, files


def main():
    errors = []
    disk = discover_hunt_files()

    # Per-card checks
    for rel in disk:
        check_card(rel, errors)

    # yaml <-> disk bijective
    ids, files = parse_yaml_refs()
    if len(set(ids)) != len(ids):
        dupes = sorted({x for x in ids if ids.count(x) > 1})
        errors.append(f"mitre-attack.yaml: duplicate Hunt IDs {dupes}")
    for fp in files:
        if not os.path.isfile(os.path.join(REPO, fp)):
            errors.append(f"mitre-attack.yaml: references missing file {fp}")
    reg = set(files)
    for d in disk:
        if d not in reg:
            errors.append(f"hunt on disk not registered in mitre-attack.yaml: {d}")

    n = len(disk)

    # README count consistency
    readme = open(os.path.join(REPO, "README.md"), encoding="utf-8").read()
    if not re.search(rf"\*\*Hunts:\*\*\s*{n}\b", readme):
        errors.append(f"README badge hunt count != {n}")
    idx_rows = len(re.findall(r"\| \[[^\]]+\]\(hunts/", readme))
    if idx_rows != n:
        errors.append(f"README hunt-index rows {idx_rows} != {n} cards")

    # ATTACK_MATRIX count
    am = open(os.path.join(REPO, "ATTACK_MATRIX.md"), encoding="utf-8").read()
    if f"| **Hunt Cards** | {n} |" not in am:
        errors.append(f"ATTACK_MATRIX Hunt-Card count != {n}")

    # deploy ARM templates valid JSON
    for t in ["deploy/scheduled-query-rule.template.json", "deploy/hunting-query.template.json"]:
        p = os.path.join(REPO, t)
        if os.path.isfile(p):
            try:
                json.load(open(p, encoding="utf-8"))
            except json.JSONDecodeError as e:
                errors.append(f"{t}: invalid JSON — {e}")

    # Report
    print(f"Hunt Cards discovered: {n}")
    print(f"Registered in mitre-attack.yaml: {len(ids)}")
    if errors:
        print(f"\nFAIL — {len(errors)} issue(s):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("\nOK: all Hunt Cards valid, metadata in sync, deploy templates valid JSON.")
    sys.exit(0)


if __name__ == "__main__":
    main()
