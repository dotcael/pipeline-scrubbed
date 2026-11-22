#!/usr/bin/env python3
"""log_outcome.py -- append ONE resolved finding to research/outcomes.jsonl.

The ledger is shared by both hunting modes: the automated pipeline calls this
when a packet resolves, and a GHOST session calls it by hand when something
closes out (paid, duplicate, no reply, whatever it was).

TWO OUTCOME FIELDS, NEVER BLENDED
---------------------------------
`pipeline_verdict` vs `operator_decision` measures whether the committee's
judgment matched what the operator actually did -- a MODEL CALIBRATION signal.

`final_outcome` measures whether the hunting approach itself worked -- a
STRATEGY signal.

Nothing in this tool, or in rank_patterns.py, may combine them into a single
"success rate". They answer different questions, and a blended number would
look authoritative while answering neither.

APPEND-ONLY
-----------
One JSON object per line, appended. Existing lines are never rewritten, so a
`pending` finding resolves by appending a SECOND record with the same `id`;
rank_patterns.py folds by `id` (latest `logged_at` wins) and counts it once.

USAGE
-----
    python3 log_outcome.py --source ghost --program aswatson \\
      --asset "api.example.test/v2/cart" --weakness-class IDOR \\
      --evidence "cart ownership not checked on update" \\
      --operator-decision submitted --final-outcome pending

EXIT
----
    0  appended
    2  validation error (nothing written, nothing truncated)
    3  write error

A rejected call writes NOTHING. That matters: a half-valid record that lands
in the ledger is worse than a rejected one, because the ranking reads it
forever.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

# -- the schema, as enums --------------------------------------------------
# "backfill" is a distinct SOURCE on purpose: a row recovered from prose in
# 2026-10 vs a row logged live at the moment of resolution have different
# evidential weight, and provenance is part of the deliverable.
SOURCE = ("pipeline", "ghost", "backfill")
PIPELINE_VERDICT = ("promote", "park", "n/a")
OPERATOR_DECISION = ("submitted", "rejected_before_submit", "n/a")
# The workspace adopted a negative-result vocabulary on 2026-10-21 (REFUTED /
# NOT REPRODUCED / UNREACHABLE / UNTESTED). The ledger could not express two
# of those four, so every "we tried and it held" result was being flattened
# into not_applicable -- which reads identically to "we never looked".
# `not_reproduced` and `unreachable` are additive; existing values are
# unchanged and rank_patterns groups them dynamically.
FINAL_OUTCOME = (
    "paid",
    "duplicate",
    "informative",
    "not_applicable",
    "not_reproduced",
    "unreachable",
    "no_reply",
    "scope_denied",
    "pending",
)
# The severity BAND, never the dollar amount. A parenthetical score is allowed
# ("Medium (6.8)") because the packet states bands that way, but a bare number
# or a currency amount is not a band and would smuggle payout value into a
# field that is supposed to be a band.
BAND_RE = re.compile(r"^(Critical|High|Medium|Low|None)\s*(\([0-9]+(\.[0-9]+)?\))?$")

# -- economics fields (added 2026-10-28, Impact-First Doctrine line 5) ------
# These exist so lane choice can be a number instead of a feeling. They are
# OPTIONAL at write time and NEVER imputed at read time: a record without
# hours is INCOMPLETE, not zero hours. A missing source is not an empty one.
IMPACT_CLASS = (
    "rce",
    "priv_esc",
    "cross_tenant",
    "authn_bypass",
    "deployment_trust",
    "business_logic",
    "info_leak",
    "other",
    "n/a",
)
GATE_OUTCOME = (
    "reached_surface",
    "identity_gate",
    "capacity_gate",
    "edge_block",
    "disclosure_gate",
    "n/a",
)

DEFAULT_LEDGER = Path(__file__).resolve().parents[2] / "research" / "outcomes.jsonl"
TAXONOMY = Path(__file__).resolve().parent / "taxonomy.yaml"

MAX_EVIDENCE = 600


def taxonomy_ids() -> list:
    """The closed class vocabulary, or an empty list if it cannot be read.

    An UNREADABLE taxonomy is not an empty one: callers must treat [] as
    "cannot validate", never as "nothing allowed". `check_class` below makes
    that distinction explicit.
    """
    try:
        import yaml

        data = yaml.safe_load(TAXONOMY.read_text(encoding="utf-8")) or {}
        return [c["id"] for c in (data.get("classes") or []) if isinstance(c, dict) and c.get("id")]
    except Exception:
        return []


def check_class(field: str, value: str) -> str | None:
    """Validate an optional class_id against the closed taxonomy.

    Absent is allowed (legacy and manually-logged rows predate the taxonomy).
    Present-but-unknown is a hard error: a typo would silently create a
    nineteenth bucket and the pattern map would count a class that does not
    exist.
    """
    value = (value or "").strip()
    if not value:
        return None
    known = taxonomy_ids()
    if not known:
        raise Rejected(
            "class_id: taxonomy.yaml could not be read, so no class id can be "
            "validated. Fix the taxonomy rather than skipping the check."
        )
    if value not in known:
        raise Rejected(
            f"class_id: {value!r} is not in taxonomy.yaml ({len(known)} classes). "
            "Add the class to the taxonomy first, or use OTHER."
        )
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_id() -> str:
    # Timestamp-first so the file stays roughly chronological when read raw,
    # plus entropy so two findings in the same second cannot collide.
    return f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"


class Rejected(Exception):
    """A value the schema does not allow. Nothing has been written."""


def check_enum(field: str, value: str, allowed: tuple) -> str:
    if value not in allowed:
        raise Rejected(
            f"{field}: {value!r} is not one of {', '.join(allowed)}"
        )
    return value


def check_text(field: str, value: str, limit: int | None = None) -> str:
    if not value or not value.strip():
        raise Rejected(f"{field}: must not be empty")
    if "\n" in value or "\r" in value:
        # A newline would break the one-object-per-line invariant and corrupt
        # the ledger for every later reader.
        raise Rejected(f"{field}: must be a single line (no newlines)")
    if limit is not None and len(value) > limit:
        raise Rejected(f"{field}: {len(value)} chars, limit is {limit}")
    return value.strip()


def check_iso(field: str, value: str) -> str:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise Rejected(
            f"{field}: {value!r} is not an ISO 8601 timestamp "
            "(expected e.g. 2026-10-22T12:00:00Z)"
        )
    return value


def check_nonneg_float(field: str, value: str) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        raise Rejected(f"{field}: {value!r} is not a number")
    if out < 0:
        raise Rejected(f"{field}: {out} is negative; hours spent cannot be")
    if out != out or out in (float("inf"), float("-inf")):
        raise Rejected(f"{field}: {value!r} is not finite")
    return out


def check_nonneg_int(field: str, value: str) -> int:
    try:
        out = int(value)
    except (TypeError, ValueError):
        raise Rejected(f"{field}: {value!r} is not an integer")
    if out < 0:
        raise Rejected(f"{field}: {out} is negative; a count cannot be")
    return out


def build_record(args) -> dict:
    # -- required, plain text
    source = check_enum("source", args.source, SOURCE)
    program = check_text("program", args.program)
    asset = check_text("asset", args.asset)
    weakness_class = check_text("weakness_class", args.weakness_class)
    evidence = check_text("evidence_summary", args.evidence, MAX_EVIDENCE)

    # -- enums with the schema's defaults
    pipeline_verdict = check_enum(
        "pipeline_verdict", args.pipeline_verdict or "n/a", PIPELINE_VERDICT
    )
    operator_decision = check_enum(
        "operator_decision", args.operator_decision or "n/a", OPERATOR_DECISION
    )
    final_outcome = check_enum("final_outcome", args.final_outcome, FINAL_OUTCOME)

    # -- payout_band is REQUIRED when paid and forbidden otherwise. Not merely
    #    "optional": a band on an unpaid finding invites a reader to sum bands
    #    as if they were money.
    band = (args.payout_band or "").strip()
    if final_outcome == "paid":
        if not band:
            raise Rejected("payout_band: required when final_outcome is 'paid'")
        if not BAND_RE.match(band):
            raise Rejected(
                f"payout_band: {band!r} is not a severity band "
                "(Critical|High|Medium|Low|None, optionally '(score)'). "
                "Record the BAND, not the dollar amount."
            )
    else:
        if band:
            raise Rejected(
                f"payout_band: {band!r} given for final_outcome {final_outcome!r}. "
                "A band only applies to a paid finding."
            )
        band = None

    # -- resolved_at: null while pending, a timestamp once resolved
    resolved = args.resolved_at
    if final_outcome == "pending":
        if resolved:
            raise Rejected(
                f"resolved_at: {resolved!r} given for a 'pending' outcome; "
                "it must be null until the finding resolves"
            )
    elif resolved:
        resolved = check_iso("resolved_at", resolved)
    elif source == "backfill":
        # A BACKFILLED row is history. Its resolution date is whatever the
        # source says, and when the source does not say, the honest value is
        # UNKNOWN -- not the moment the backfill happened to run. Imputing
        # now_iso() here silently dated a month-old negative as today, and
        # made every re-run look like a change.
        resolved = None
    else:
        resolved = now_iso()

    rid = (args.id or "").strip() or make_id()
    if "\n" in rid or " " in rid:
        raise Rejected(f"id: {rid!r} must not contain spaces or newlines")

    # -- the closed-vocabulary class, optional but validated ----------------
    class_id = check_class("class_id", getattr(args, "class_id", None))

    # -- economics (optional; absent means absent, never zero) --------------
    impact_class = check_enum(
        "impact_class", (args.impact_class or "n/a").strip(), IMPACT_CLASS
    )
    gate_outcome = check_enum(
        "gate_outcome", (args.gate_outcome or "n/a").strip(), GATE_OUTCOME
    )

    # band_predicted is OUR forecast and may sit on any record. It is a
    # different thing from payout_band, which is an award and stays paid-only:
    # a prediction is not money, and only one of the two may be summed.
    predicted = (args.band_predicted or "").strip()
    if predicted:
        if not BAND_RE.match(predicted):
            raise Rejected(
                f"band_predicted: {predicted!r} is not a severity band "
                "(Critical|High|Medium|Low|None, optionally '(score)'). "
                "Record the BAND, not the dollar amount."
            )
    else:
        predicted = None

    hours = args.hours_spent
    hours = check_nonneg_float("hours_spent", hours) if hours not in (None, "") else None
    hyp = args.hypotheses_tested
    hyp = check_nonneg_int("hypotheses_tested", hyp) if hyp not in (None, "") else None
    dtests = args.discriminating_tests
    dtests = (
        check_nonneg_int("discriminating_tests", dtests)
        if dtests not in (None, "")
        else None
    )

    return {
        "id": rid,
        "logged_at": now_iso(),
        "source": source,
        "program": program,
        "asset": asset,
        "weakness_class": weakness_class,
        "class_id": class_id,
        "vrt_leaf": (getattr(args, "vrt_leaf", None) or "").strip() or None,
        "technique_id": (getattr(args, "technique", None) or "").strip() or None,
        "evidence_summary": evidence,
        "pipeline_verdict": pipeline_verdict,
        "operator_decision": operator_decision,
        "final_outcome": final_outcome,
        "payout_band": band,
        "resolved_at": resolved,
        "impact_class": impact_class,
        "gate_outcome": gate_outcome,
        "band_predicted": predicted,
        "hours_spent": hours,
        "hypotheses_tested": hyp,
        "discriminating_tests": dtests,
    }


def append_line(path: Path, record: dict) -> None:
    """Append exactly one line. Never truncate, never rewrite."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # If a previous writer died mid-write the file may not end in a newline,
    # and appending would fuse two objects onto one line -- silently
    # corrupting every record after it. Repair the boundary, do not rewrite
    # the content.
    needs_repair = False
    if path.exists() and path.stat().st_size > 0:
        with open(path, "rb") as fh:
            fh.seek(-1, os.SEEK_END)
            needs_repair = fh.read(1) != b"\n"

    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    if "\n" in line:  # defence in depth: json.dumps escapes newlines, so this is unreachable
        raise RuntimeError("serialised record contains a newline; refusing to write")

    with open(path, "a", encoding="utf-8") as fh:
        if needs_repair:
            fh.write("\n")
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Append one resolved finding to research/outcomes.jsonl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--file", default=str(DEFAULT_LEDGER), help="ledger path")
    ap.add_argument("--id", help="reuse an id to append a resolution for an existing record")
    ap.add_argument("--source", required=True, choices=SOURCE)
    ap.add_argument("--program", required=True)
    ap.add_argument("--asset", required=True)
    ap.add_argument("--weakness-class", dest="weakness_class", required=True)
    ap.add_argument(
        "--class-id",
        dest="class_id",
        help="closed-vocabulary class from taxonomy.yaml (recommended; "
        "required for a row that should be countable in the pattern map)",
    )
    ap.add_argument("--evidence", dest="evidence", required=True)
    ap.add_argument("--pipeline-verdict", dest="pipeline_verdict", default="n/a")
    ap.add_argument("--operator-decision", dest="operator_decision", default="n/a")
    ap.add_argument("--final-outcome", dest="final_outcome", required=True)
    ap.add_argument("--payout-band", dest="payout_band")
    ap.add_argument("--resolved-at", dest="resolved_at")
    ap.add_argument("--impact-class", dest="impact_class")
    ap.add_argument("--gate-outcome", dest="gate_outcome")
    ap.add_argument("--band-predicted", dest="band_predicted")
    ap.add_argument("--hours-spent", dest="hours_spent")
    ap.add_argument("--hypotheses-tested", dest="hypotheses_tested")
    ap.add_argument("--discriminating-tests", dest="discriminating_tests")
    # Attribution. A result nobody can attribute is a result the selector can
    # never learn from: without these two, an outcome informs no leaf and no
    # technique, and every posterior stays at its prior.
    ap.add_argument("--vrt-leaf", dest="vrt_leaf",
                    help="path-qualified VRT leaf this attempt tested, e.g. "
                         "broken_access_control/idor/view_non_sensitive_information")
    ap.add_argument("--technique", dest="technique",
                    help="skill id that was actually run, e.g. subject-binding-after-token-swap")
    args = ap.parse_args()

    try:
        record = build_record(args)
    except Rejected as exc:
        print(f"log_outcome: REJECTED -- {exc}", file=sys.stderr)
        print("log_outcome: nothing was written", file=sys.stderr)
        return 2

    path = Path(args.file)
    try:
        append_line(path, record)
    except Exception as exc:  # noqa: BLE001 - any write failure is fatal, report it
        print(f"log_outcome: WRITE FAILED -- {exc}", file=sys.stderr)
        return 3

    print(
        f"logged {record['id']} -> {path} "
        f"({record['program']}/{record['weakness_class']}, "
        f"{record['final_outcome']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
