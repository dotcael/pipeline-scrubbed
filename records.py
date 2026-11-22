#!/usr/bin/env python3
"""
records.py — typed FACT / HYPOTHESIS records with RESOLVABLE evidence IDs.

WHY TYPED RECORDS
-----------------
A free-text hypothesis cannot be deduplicated, audited, or handed to a
reviewer without re-reading it. A typed record has a machine-readable
identity, a program, an asset, a weakness class, and -- crucially -- a list of
evidence IDs that RESOLVE to real artifacts. "We saw something odd" is not a
record; "FACT F-1: response 200 with another user's order id (evidence
E-0007)" is.

RECORD SYNTAX
-------------
One record per line, TYPE first, then key=value pairs:

    FACT       id=F1 program="Abercrombie & Fitch" claim="..." evidence=E-0001,E-0002
    HYPOTHESIS id=H1 program="Abercrombie & Fitch" asset=www.abercrombie.com \
                weakness=CWE-639 capability="..." evidence=E-0003

  * Values may be bare (no spaces) or double-quoted; inside quotes, \" is a
    literal quote.
  * `evidence` is a COMMA-separated list of evidence IDs.
  * Unknown keys are an ERROR, not a shrug: a typo like `asset=` vs `aset=`
    must not silently drop the one field the dedup gate keys on.
  * Only FACT and HYPOTHESIS exist. There is no third type to hide in.

EVIDENCE RESOLUTION
-------------------
An evidence ID resolves when it is present in the evidence index AND, if the
index entry names a path, that path exists on disk. An ID that does not
resolve is a hard error: the record is UNVERIFIED, not "probably fine".
A hypothesis whose evidence does not resolve may not be dispatched.

Usage:
    python3 records.py --validate <records-file> [--evidence-index <json>]
    python3 records.py --help

Exit codes: 0 = all records valid, 2 = invalid records (details on stderr).
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from dataclasses import dataclass, field

FACT = "FACT"
HYPOTHESIS = "HYPOTHESIS"

# The only fields each type may carry. Anything else is an error.
FIELDS_BY_TYPE = {
    FACT: {"id", "program", "claim", "evidence"},
    HYPOTHESIS: {"id", "program", "asset", "weakness", "capability", "evidence"},
}

REQUIRED_BY_TYPE = {
    FACT: {"id", "program", "claim", "evidence"},
    HYPOTHESIS: {"id", "program", "asset", "weakness", "capability", "evidence"},
}


class RecordError(Exception):
    """A malformed record. Carries the line number for the human."""


@dataclass
class Record:
    kind: str
    line: int
    fields: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.fields.get("id", "")

    @property
    def program(self) -> str:
        return self.fields.get("program", "")

    @property
    def asset(self) -> str:
        return self.fields.get("asset", "")

    @property
    def weakness(self) -> str:
        return self.fields.get("weakness", "")

    @property
    def capability(self) -> str:
        return self.fields.get("capability", "")

    @property
    def claim(self) -> str:
        return self.fields.get("claim", "")

    @property
    def evidence(self) -> list[str]:
        raw = self.fields.get("evidence", "")
        return [e.strip() for e in raw.split(",") if e.strip()]


def _split_fields(section: str) -> list[str]:
    """Split a record's field section into key=value tokens, quote-aware.

    shlex (POSIX mode) keeps `key="a b"` as ONE token and honours the \\"
    escape. Splitting on whitespace instead would tear a quoted value that
    contains a space, which is most of them.
    """
    try:
        return shlex.split(section, comments=False, posix=True)
    except ValueError as exc:
        raise RecordError(f"unparseable fields: {exc}") from exc


def parse_record(line: str, lineno: int) -> Record:
    """Parse one line into a typed Record. Raises RecordError on any problem."""
    text = line.strip()
    if not text or text.startswith("#"):
        raise RecordError("blank or comment line")
    parts = text.split(None, 1)
    kind = parts[0].upper()
    if kind not in FIELDS_BY_TYPE:
        raise RecordError(f"unknown record type {parts[0]!r} (expected FACT or HYPOTHESIS)")
    if len(parts) < 2:
        raise RecordError("record has no fields")

    allowed = FIELDS_BY_TYPE[kind]
    fields: dict = {}
    for token in _split_fields(parts[1]):
        if "=" not in token:
            raise RecordError(f"field {token!r} is not key=value")
        key, value = token.split("=", 1)
        key = key.strip()
        if key not in allowed:
            raise RecordError(
                f"unknown field {key!r} for {kind} (allowed: {', '.join(sorted(allowed))})"
            )
        if key in fields:
            raise RecordError(f"duplicate field {key!r}")
        fields[key] = value

    missing = REQUIRED_BY_TYPE[kind] - set(fields)
    if missing:
        raise RecordError(f"missing required field(s): {', '.join(sorted(missing))}")

    return Record(kind=kind, line=lineno, fields=fields)


def parse_file(path: str) -> tuple[list[Record], list[str]]:
    """Parse a records file. Returns (records, errors). Never raises."""
    records: list[Record] = []
    errors: list[str] = []
    seen_ids: dict[str, int] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [], [f"cannot read {path}: {exc}"]
    for i, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        try:
            rec = parse_record(raw, i)
        except RecordError as exc:
            errors.append(f"line {i}: {exc}")
            continue
        if rec.id in seen_ids:
            errors.append(f"line {i}: duplicate record id {rec.id!r} (first seen on line {seen_ids[rec.id]})")
            continue
        seen_ids[rec.id] = i
        records.append(rec)
    return records, errors


# ── evidence resolution ────────────────────────────────────────────────────
def load_evidence_index(path: str | None) -> dict:
    """Load the evidence index. Missing index -> empty (every ID unresolved)."""
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise RecordError(f"cannot read evidence index {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RecordError(f"evidence index {path} must be a JSON object of id -> entry")
    return data


def resolve_evidence(record: Record, index: dict, base_dir: str = ".") -> list[str]:
    """Return the list of UNRESOLVED evidence IDs for this record.

    An ID resolves when it is in the index and, if the entry names a path,
    that path exists relative to base_dir.
    """
    unresolved = []
    for eid in record.evidence:
        entry = index.get(eid)
        if entry is None:
            unresolved.append(eid)
            continue
        if isinstance(entry, dict):
            rel = entry.get("path")
        else:
            rel = entry if isinstance(entry, str) else None
        if rel:
            full = rel if os.path.isabs(rel) else os.path.join(base_dir, rel)
            if not os.path.exists(full):
                unresolved.append(eid)
    return unresolved


def validate(records, errors, index, base_dir=".") -> dict:
    """Full validation: syntax + evidence resolution. Returns a report dict."""
    unresolved_by_id = {}
    for rec in records:
        bad = resolve_evidence(rec, index, base_dir)
        if bad:
            unresolved_by_id[rec.id] = bad
    report = {
        "records": len(records),
        "facts": sum(1 for r in records if r.kind == FACT),
        "hypotheses": sum(1 for r in records if r.kind == HYPOTHESIS),
        "syntax_errors": errors,
        "unresolved_evidence": unresolved_by_id,
        "valid": not errors and not unresolved_by_id,
    }
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="validate typed FACT/HYPOTHESIS records")
    p.add_argument("--validate", metavar="FILE", help="records file to validate")
    p.add_argument("--evidence-index", metavar="FILE", help="JSON map of evidence id -> entry")
    p.add_argument("--base-dir", default=".", help="root the evidence paths are relative to")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    args = p.parse_args(argv)

    if not args.validate:
        p.print_help()
        return 2

    try:
        index = load_evidence_index(args.evidence_index)
    except RecordError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    records, errors = parse_file(args.validate)
    report = validate(records, errors, index, args.base_dir)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"records: {report['records']} (facts {report['facts']}, hypotheses {report['hypotheses']})")
        for e in report["syntax_errors"]:
            print(f"  SYNTAX ERROR  {e}")
        for rid, bad in report["unresolved_evidence"].items():
            print(f"  UNRESOLVED EVIDENCE  {rid}: {', '.join(bad)}")
        print("valid" if report["valid"] else "INVALID")

    return 0 if report["valid"] else 2


if __name__ == "__main__":
    sys.exit(main())
