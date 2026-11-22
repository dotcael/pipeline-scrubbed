#!/usr/bin/env python3
"""
dedupe_gate.py — PRE-DISPATCH duplicate gate for a typed hypothesis.

WHY THIS EXISTS
---------------
On 2026-10-22 the pipeline spent a committee on the A&F `setDefaultAddress`
hypothesis and parked it -- and the packet was for a hypothesis that was
ALREADY A CONFIRMED DUPLICATE (H1 #4132187, dupe of #2649524). The gate that
was supposed to catch that runs PRE-FILING (G2b). A duplicate should never
have reached a model at all. This is G2a, made cheap and automatic.

THE KEY
-------
Duplicates are matched on (canonical asset, weakness class) -- plus a
capability-text overlap, because the dupe unit on a mature programme is the
CAPABILITY, not the endpoint (that is the lesson the A&F dupe taught: 4 of 5
sibling resolvers were correctly scoped, only one was broken, and it was
STILL a duplicate because the capability was already claimed).

SOURCES (both, because each knows something the other does not)
----------------------------------------------------------------
  research/dupe-registry.json  -- capability classes we already filed, or were
                                  closed as duplicate on, per programme. It is
                                  the ONLY source that knows about PRIVATE
                                  reports, which no public search can surface.
  findings.md                 -- our own findings and logged negatives. It
                                  knows about work that has NOT been filed,
                                  and about classes already refuted on an
                                  asset (a refuted class must not be
                                  re-dispatched as if it were new).

VERDICTS
--------
  NEW          nothing matched -> DISPATCH
  DUPLICATE    same asset, same weakness, already claimed -> DROP
  OVERLAP      same asset, related weakness, or capability text overlap
               -> HOLD for a human (this is the G2b fix-boundary question,
                  which is expensive and is NOT this tool's job)
  UNRESOLVED   the records are invalid or their evidence does not resolve
               -> HOLD (fail closed: we cannot certify what we cannot read)

Exit codes: 0 = DISPATCH, 3 = DROP, 4 = HOLD, 5 = UNRESOLVED.
The JSON report goes to stdout; human-readable lines to stderr.

Usage:
    python3 dedupe_gate.py --records <file> [--program <name>] \
        [--evidence-index <file>] [--repo-root <dir>]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import records as rec_mod  # noqa: E402

# Reuse the existing tokeniser and registry matcher rather than growing a
# second, subtly different notion of "same capability". One definition only.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import dupecheck  # noqa: E402
except ImportError:  # pragma: no cover - depends on deployment
    dupecheck = None

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Weakness CLASSES: two CWEs in the same family raise the same question --
# "would the same fix resolve both?" -- so they are OVERLAP, not DUPLICATE.
WEAKNESS_FAMILIES = {
    "authorization": {"CWE-284", "CWE-285", "CWE-287", "CWE-639", "CWE-862",
                      "CWE-863", "CWE-441", "CWE-122", "CWE-346", "CWE-863"},
    "idor": {"CWE-639", "CWE-863"},
    "xss": {"CWE-79", "CWE-80", "CWE-116"},
    "sqli": {"CWE-89", "CWE-564"},
    "ssrf": {"CWE-918"},
    "crypto": {"CWE-327", "CWE-328", "CWE-326", "CWE-311", "CWE-330"},
    "business-logic": {"CWE-840", "CWE-841", "CWE-694", "CWE-799", "CWE-840"},
    "traversal": {"CWE-22", "CWE-23", "CWE-36"},
    "info-disclosure": {"CWE-200", "CWE-209", "CWE-532", "CWE-538"},
    "race": {"CWE-362", "CWE-367", "CWE-377"},
    "dos": {"CWE-400", "CWE-770", "CWE-834"},
    "ssti": {"CWE-917"},
    "rce": {"CWE-78", "CWE-94", "CWE-502"},
}

# Weakness overlap thresholds: same asset + same class is a duplicate; same
# asset + same family is an overlap that needs a human.
SAME_CLASS_JACCARD = 0.55

# Capability-text overlap threshold, borrowed from dupecheck's registry rule
# (a score >= 0.55 means "same capability" regardless of programme).
CAPABILITY_OVERLAP = 0.55
# Containment threshold: a short candidate capability whose every meaningful
# word appears in an existing claim is the SAME capability, even though
# Jaccard would punish the length difference.
CAPABILITY_CONTAINMENT = 0.70


# ── canonicalisation ───────────────────────────────────────────────────────
def canonical_asset(value: str) -> str:
    """Reduce a URL/host to a comparable host.

    scheme, path, port, trailing dot and a leading "www." are noise. Two
    records that name the same asset in different ways must land on the same
    key or the gate is blind.
    """
    v = (value or "").strip().lower()
    if not v:
        return ""
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    v = v.split("/", 1)[0]
    v = v.split("?", 1)[0]
    v = v.split("#", 1)[0]
    v = v.split("@")[-1]
    if v.startswith("["):  # IPv6 literal
        return v
    v = v.split(":", 1)[0]
    v = v.rstrip(".")
    if v.startswith("www."):
        v = v[4:]
    return v


def extract_cwes(text: str) -> set[str]:
    """Pull normalised CWE ids out of free text ('639' -> 'CWE-639')."""
    found = set()
    for m in re.finditer(r"\bCWE[-_ ]?(\d{1,4})\b", text or "", re.IGNORECASE):
        found.add(f"CWE-{int(m.group(1))}")
    return found


def normalize_weakness_field(value: str) -> set[str]:
    """Normalise a weakness FIELD to a set of CWE ids.

    A bare number is a legitimate spelling of a weakness field ("639"), and
    the field is where a candidate is most likely to write it. Missing that
    spelling would make the gate blind to exactly the record it should catch.
    """
    v = (value or "").strip()
    if re.fullmatch(r"\d{1,4}", v):
        return {f"CWE-{int(v)}"}
    return extract_cwes(v)


def weakness_family(cwes: set[str]) -> str:
    """The family name for a set of CWEs, or '' if they span families."""
    names = set()
    for c in cwes:
        for fam, members in WEAKNESS_FAMILIES.items():
            if c in members:
                names.add(fam)
                break
    if len(names) == 1:
        return next(iter(names))
    if not names:
        return ""
    return "mixed:" + ",".join(sorted(names))


# ── sources ────────────────────────────────────────────────────────────────
def load_registry(repo_root: str) -> dict:
    path = os.path.join(repo_root, "research", "dupe-registry.json")
    if not os.path.exists(path):
        return {"classes": []}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"classes": []}


def load_findings_rows(repo_root: str) -> list[dict]:
    """Parse findings.md into rows with NAMED columns.

    findings.md has more than one table with DIFFERENT column sets (the
    findings table has Program/Severity/Finding/Location/URL/...; the
    negatives table has Program/Checked/Result/Evidence). A fixed column
    index would read a negative's Result as a Finding, so the header row is
    detected and the column names are used instead.
    """
    path = os.path.join(repo_root, "findings.md")
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return rows
    header: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0]
        if first == "#":
            header = [c.lower() for c in cells]
            continue
        if set(first) <= set("-: ") or not first:
            continue
        if not re.match(r"^(\d+|N-\d+)$", first):
            continue
        row = {"id": first, "header": list(header), "cells": cells, "text": " | ".join(cells)}

        def col(*names):
            for n in names:
                for idx, h in enumerate(header):
                    if h == n and idx < len(cells):
                        return cells[idx]
            return ""

        row["program"] = col("program")
        row["claim"] = col("finding", "checked")
        row["location"] = col("location/url", "result", "location")
        row["status"] = col("status", "evidence")
        row["evidence"] = col("evidence")
        rows.append(row)
    return rows


# ── matching ───────────────────────────────────────────────────────────────
def _tokens(text: str) -> set[str]:
    if dupecheck is not None:
        return dupecheck.tokens(text)
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(w) > 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _containment(a: set[str], b: set[str]) -> float:
    """How much of the SMALLER token set is contained in the larger."""
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def capability_match(cand_tokens: set[str], other_tokens: set[str]) -> tuple[bool, float]:
    """Do these two capability statements describe the same capability?

    Jaccard alone is wrong here: a candidate capability is normally a SHORT
    summary of a long claim, and Jaccard punishes that length difference into
    a non-match. Containment fixes it -- if every meaningful word of the
    candidate appears in the other statement, they are the same capability.

    A minimum token count guards the degenerate case: a two-word candidate
    is contained in almost anything, and would flag the whole ledger.
    """
    if len(cand_tokens) < 4 or len(other_tokens) < 4:
        return False, 0.0
    jac = _jaccard(cand_tokens, other_tokens)
    cont = _containment(cand_tokens, other_tokens)
    if jac >= CAPABILITY_OVERLAP:
        return True, jac
    if cont >= CAPABILITY_CONTAINMENT:
        return True, cont
    return False, max(jac, cont)


def check_hypothesis(hyp, registry, finding_rows, program=""):
    """Run every source against one hypothesis. Returns the report dict."""
    asset = canonical_asset(hyp.asset)
    cwes = normalize_weakness_field(hyp.weakness)
    family = weakness_family(cwes)
    cap_tokens = _tokens(hyp.capability)

    matches = []
    reasons = []

    # 1. registry -- the only source that knows about private reports
    for entry in registry.get("classes", []):
        entry_asset = canonical_asset(entry.get("asset", ""))
        if not asset or not entry_asset or asset != entry_asset:
            continue
        entry_cwes = extract_cwes(entry.get("weakness", ""))
        entry_family = weakness_family(entry_cwes)
        same_class = bool(cwes & entry_cwes)
        same_family = bool(family) and family == entry_family
        ent_tokens = _tokens(entry.get("capability", "")) | _tokens(
            " ".join(entry.get("class_terms", []))
        )
        cap_match, cap_overlap = capability_match(cap_tokens, ent_tokens)
        status = (entry.get("status") or "").lower()
        # The dupe unit is the CAPABILITY, not the endpoint -- that is the
        # lesson the A&F dupe taught. Same asset + same weakness class is the
        # cheap pre-filter; it becomes a DUPLICATE only when the capability
        # text matches too. Same class with a DIFFERENT capability is an
        # OVERLAP for a human (the G2b fix-boundary question).
        if same_class and cap_match:
            verdict = "DUPLICATE"
        elif same_class or same_family or cap_match:
            verdict = "OVERLAP"
        else:
            continue
        matches.append({
            "source": "research/dupe-registry.json",
            "verdict": verdict,
            "program": entry.get("program"),
            "asset": entry.get("asset"),
            "weakness": entry.get("weakness"),
            "capability": entry.get("capability"),
            "status": status,
            "our_report_id": entry.get("our_report_id"),
            "original": entry.get("original"),
            "date": entry.get("date"),
            "capability_overlap": round(cap_overlap, 3),
            "lesson": entry.get("lesson"),
        })

    # 2. findings.md -- our own filed findings and logged negatives
    for row in finding_rows:
        row_text = row["text"]
        row_asset = canonical_asset(row["location"]) if row["location"] else ""
        # a row may name several assets; fall back to scanning the whole row
        row_assets = set()
        for host in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", row_text.lower()):
            row_assets.add(canonical_asset(host))
        if asset and asset not in row_assets and (not row_asset or row_asset != asset):
            continue
        row_cwes = extract_cwes(row_text)
        same_class = bool(cwes & row_cwes)
        same_family = bool(family) and weakness_family(row_cwes) == family
        # Compare against the row's CLAIM cell, not the whole row: a finding
        # row also carries a reproduction, an impact and a long status note,
        # and diffing a short candidate against all of that dilutes the
        # signal to nothing.
        row_claim_tokens = _tokens(row.get("claim", "")) or _tokens(row_text)
        row_match, row_overlap = capability_match(cap_tokens, row_claim_tokens)
        if not (same_class or same_family or row_match):
            continue
        matches.append({
            "source": "findings.md",
            "verdict": "OVERLAP",
            "row_id": row["id"],
            "program": row["program"],
            "status": row["status"][:300],
            "same_class": same_class,
            "capability_overlap": round(row_overlap, 3),
        })
    if not matches:
        verdict = "NEW"
    elif any(m["verdict"] == "DUPLICATE" for m in matches):
        verdict = "DUPLICATE"
    else:
        verdict = "OVERLAP"

    if verdict == "DUPLICATE":
        decision = "DROP"
        reasons.append("same asset and weakness class already claimed")
    elif verdict == "OVERLAP":
        decision = "HOLD"
        reasons.append("related capability or weakness family already on record")
    else:
        decision = "DISPATCH"
        reasons.append("no match in the registry or in findings.md")

    return {
        "id": hyp.id,
        "program": hyp.program or program,
        "claim": hyp.claim,
        "capability": hyp.capability,
        "key": {"canonical_asset": asset, "weakness": hyp.weakness, "cwe": sorted(cwes),
                "family": family},
        "evidence": hyp.evidence,
        "verdict": verdict,
        "decision": decision,
        "reasons": reasons,
        "matches": matches,
    }


# ── main ───────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="pre-dispatch duplicate gate")
    p.add_argument("--records", required=True, help="typed records file")
    p.add_argument("--program", default="", help="program name (defaults to the record's)")
    p.add_argument("--evidence-index", default="", help="JSON map of evidence id -> entry")
    p.add_argument("--repo-root", default=REPO, help="repo root (for the dupe sources)")
    p.add_argument("--json", action="store_true", help="print only the JSON report")
    args = p.parse_args(argv)

    repo_root = args.repo_root
    try:
        index = rec_mod.load_evidence_index(args.evidence_index or None)
    except rec_mod.RecordError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 5

    parsed, errors = rec_mod.parse_file(args.records)
    report = rec_mod.validate(parsed, errors, index, repo_root)

    hypotheses = [r for r in parsed if r.kind == rec_mod.HYPOTHESIS]
    facts = [r for r in parsed if r.kind == rec_mod.FACT]

    out = {
        "records": report["records"],
        "facts": len(facts),
        "hypotheses": len(hypotheses),
        "syntax_errors": report["syntax_errors"],
        "unresolved_evidence": report["unresolved_evidence"],
        "results": [],
    }

    # Fail closed: invalid records or unresolvable evidence means we cannot
    # certify the hypothesis, so we do not dispatch it.
    if report["syntax_errors"] or report["unresolved_evidence"] or not hypotheses:
        out["verdict"] = "UNRESOLVED"
        out["decision"] = "UNRESOLVED"
        out["reasons"] = [
            "records are invalid or their evidence does not resolve"
            if (report["syntax_errors"] or report["unresolved_evidence"])
            else "no HYPOTHESIS record present"
        ]
        if not args.json:
            for e in report["syntax_errors"]:
                print(f"  SYNTAX ERROR  {e}", file=sys.stderr)
            for rid, bad in report["unresolved_evidence"].items():
                print(f"  UNRESOLVED EVIDENCE  {rid}: {', '.join(bad)}", file=sys.stderr)
            print(f"HOLD: {out['reasons'][0]}", file=sys.stderr)
        print(json.dumps(out, indent=2))
        return 5

    registry = load_registry(repo_root)
    finding_rows = load_findings_rows(repo_root)

    # A MISSING SOURCE IS NOT AN EMPTY SOURCE. The registry is the only place
    # that knows about PRIVATE reports (no public search can surface them), and
    # findings.md knows about classes we already refuted on an asset. If either
    # file is absent, the gate is not "clear" -- it is BLIND, and a blind gate
    # that says DISPATCH looks exactly like a gate that works. Fail closed.
    missing_sources = []
    if not os.path.exists(os.path.join(repo_root, "research", "dupe-registry.json")):
        missing_sources.append("research/dupe-registry.json")
    if not os.path.exists(os.path.join(repo_root, "findings.md")):
        missing_sources.append("findings.md")
    if missing_sources:
        out["verdict"] = "UNRESOLVED"
        out["decision"] = "UNRESOLVED"
        out["missing_sources"] = missing_sources
        out["reasons"] = ["dedupe source(s) not found: " + ", ".join(missing_sources)]
        if not args.json:
            print(f"HOLD: dedupe source(s) missing: {', '.join(missing_sources)}", file=sys.stderr)
            print("The gate cannot certify a hypothesis against sources it does not have.", file=sys.stderr)
        print(json.dumps(out, indent=2))
        return 5

    for hyp in hypotheses:
        res = check_hypothesis(hyp, registry, finding_rows, args.program)
        out["results"].append(res)
        if not args.json:
            print(
                f"  {res['decision']:>8}  {res['id']}  key="
                f"({res['key']['canonical_asset']}, {res['key']['weakness']})  {res['verdict']}",
                file=sys.stderr,
            )
            for m in res["matches"]:
                print(f"             match: {m['source']} {m.get('row_id') or m.get('program','')} "
                      f"{m.get('status','')}"[:160], file=sys.stderr)

    decisions = [r["decision"] for r in out["results"]]
    if "DROP" in decisions:
        out["verdict"] = "DUPLICATE"
        out["decision"] = "DROP"
        rc = 3
    elif "HOLD" in decisions:
        out["verdict"] = "OVERLAP"
        out["decision"] = "HOLD"
        rc = 4
    else:
        out["verdict"] = "NEW"
        out["decision"] = "DISPATCH"
        rc = 0

    if not args.json:
        print(f"{out['decision']}: {out['verdict']}", file=sys.stderr)
    print(json.dumps(out, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
