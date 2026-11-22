#!/usr/bin/env python3
"""rank_patterns.py -- ADVISORY report over research/outcomes.jsonl.

WHAT THIS IS
------------
A reading aid for the operator: which (program, weakness_class) patterns have
historically paid off, and which have not.

WHAT THIS IS NOT
----------------
It is NOT a filter. It does not dispatch, promote, park, skip, or reorder
anything, and it writes nothing that any gate reads. A genuinely novel finding
matches no historical pattern BY DEFINITION -- so a system that let this
report influence dispatch would be blind to exactly the findings that are
worth the most. The suite enforces that separation
(`rank_patterns is never wired into a gate`), and that test is meant to fail
loudly if anyone ever connects them.

This module opens the ledger for READING ONLY. `--json` goes to stdout; no
file is created, modified, or deleted.

TWO SIGNALS, KEPT SEPARATE
--------------------------
  agreement_rate    pipeline_verdict vs operator_decision  -> model calibration
  outcome_breakdown final_outcome                          -> strategy

They are reported side by side and NEVER multiplied, averaged, or collapsed
into one "success rate". A blended number would look authoritative while
answering neither question.

THE HONESTY RULES, ENFORCED IN CODE
-----------------------------------
1. A rate is only computed over entries where both fields are meaningful
   (`pipeline_verdict != n/a` AND `operator_decision != n/a`). A denominator
   of zero is reported as "no comparable entries", NEVER as 0.0 -- a rate over
   an empty set is an assertion that cannot fail.
2. A rate is never printed without its confidence label. The label is part of
   the string that formats the rate, so "print the rate, forget the label" is
   not expressible here.
3. Confidence counts RESOLVED entries only. Ten pending findings are not
   evidence of anything.

USAGE
-----
    python3 rank_patterns.py                 # human-readable report
    python3 rank_patterns.py --json          # for the evidence packet
    python3 rank_patterns.py --program aswatson --weakness-class IDOR
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_LEDGER = Path(__file__).resolve().parents[2] / "research" / "outcomes.jsonl"

# Confidence thresholds, in RESOLVED entries per group. Named, not inlined, so
# the test and the report cannot drift apart.
INSUFFICIENT_BELOW = 5
ESTABLISHED_FROM = 15

# Which verdict/decision pairs count as agreement. "promote then submitted"
# and "park then rejected" agree; the crossed pairs do not. `n/a` never
# enters the rate at all.
AGREEING_PAIRS = {
    ("promote", "submitted"),
    ("park", "rejected_before_submit"),
}


def confidence_for(resolved: int) -> str:
    if resolved < INSUFFICIENT_BELOW:
        return "insufficient data"
    if resolved < ESTABLISHED_FROM:
        return "early signal"
    return "established"


# -- economics (2026-10-28) -------------------------------------------------
# Payout RANGES do not live in the ledger: the ledger records a severity BAND,
# because a band is what the programme awards. Money comes from the
# programme's own published table (research/programme-bands.json), which is a
# separate, quotable source. Two numbers, never blended:
#   realised $/h  -- paid records only, no model, no probability
#   modelled $/h  -- predicted band x hours; an UPPER BOUND, not an estimate
# A missing band table or a missing hours field is reported as INCOMPLETE,
# never as 0.0. (A rate over an imputed denominator is an assertion that
# cannot fail.)
DEFAULT_BANDS = Path(__file__).resolve().parents[2] / "research" / "programme-bands.json"


def load_bands(path: Path) -> tuple[dict, str | None]:
    """Return ({normalised_programme_name: bands_dict}, problem_or_None)."""
    if not path.exists():
        return {}, f"band table not found: {path} (dollars per hour is UNRESOLVED)"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same answer
        return {}, f"band table unreadable: {path} ({exc})"
    progs = doc.get("programmes") or {}
    if not isinstance(progs, dict) or not progs:
        return {}, f"band table has no 'programmes' entries: {path}"
    return progs, None


def band_for_programme(progs: dict, programme: str) -> tuple[str | None, str]:
    """Resolve a ledger `program` string to a band table entry.

    Exact (case-insensitive) first, then a unique substring match in either
    direction. An AMBIGUOUS match is UNRESOLVED, not a coin flip -- the
    corpus writes the same programme under several names, and guessing which
    payout table applies is how a wrong number becomes authoritative.
    """
    want = programme.strip().lower()
    if not want:
        return None, "programme name is empty"
    exact = [k for k in progs if k.strip().lower() == want]
    if len(exact) == 1:
        return exact[0], "exact"
    partial = [
        k
        for k in progs
        if want in k.strip().lower() or k.strip().lower() in want
    ]
    if len(partial) == 1:
        return partial[0], "unique partial match"
    if len(partial) > 1:
        return None, "AMBIGUOUS: " + " | ".join(sorted(partial))
    return None, "not in band table"


def midpoint(rng) -> float | None:
    if not isinstance(rng, list) or len(rng) != 2:
        return None
    lo, hi = rng
    if not isinstance(lo, (int, float)) or not isinstance(hi, (int, float)):
        return None
    return (float(lo) + float(hi)) / 2.0


def economics_for(recs: list[dict], programme: str, progs: dict) -> dict:
    """Hours, realised $/h and modelled $/h for one group. Labelled, honest."""
    with_hours = [r for r in recs if isinstance(r.get("hours_spent"), (int, float))]
    missing_hours = len(recs) - len(with_hours)
    hours = sum(float(r["hours_spent"]) for r in with_hours) if with_hours else None

    out: dict = {
        "records": len(recs),
        "records_with_hours": len(with_hours),
        "records_missing_hours": missing_hours,
        "hours_total": hours,
        "realised": {"text": None, "dollars": None, "per_hour": None},
        "modelled": {"text": None, "dollars": None, "per_hour": None},
    }

    key, why = band_for_programme(progs, programme)
    bands = (progs.get(key) or {}).get("bands") if key else None
    out["band_table"] = {
        "entry": key,
        "how": why,
        "source": (progs.get(key) or {}).get("source") if key else None,
    }

    # -- realised: only over paid records that carry BOTH a band and hours.
    paid = [r for r in recs if r.get("final_outcome") == "paid"]
    if not paid:
        out["realised"]["text"] = "no paid records -- nothing realised"
    elif not bands:
        out["realised"]["text"] = f"UNRESOLVED: {why} (no published table to price the band)"
    else:
        claims = [r for r in paid if r.get("payout_band") in bands]
        unpriced = [r for r in paid if r.get("payout_band") not in bands]
        priced_hours = [r for r in claims if isinstance(r.get("hours_spent"), (int, float))]
        unpriced_hours = [r for r in claims if r not in priced_hours]
        if unpriced or unpriced_hours:
            bits = []
            if unpriced:
                bits.append(f"{len(unpriced)} paid record(s) with a band not in the table")
            if unpriced_hours:
                bits.append(f"{len(unpriced_hours)} paid record(s) with no hours")
            out["realised"]["text"] = (
                "INCOMPLETE: " + "; ".join(bits) + " -- not zero, not averaged over a subset"
            )
        else:
            dollars = sum(midpoint(bands[r["payout_band"]]) or 0.0 for r in claims)
            h = sum(float(r["hours_spent"]) for r in priced_hours)
            if h <= 0:
                out["realised"]["text"] = "INCOMPLETE: paid records record 0 hours"
            else:
                out["realised"]["dollars"] = dollars
                out["realised"]["per_hour"] = dollars / h
                out["realised"]["text"] = (
                    f"${dollars:,.0f} over {h:.1f}h = ${dollars / h:,.0f}/h "
                    f"({len(claims)} paid, midpoint of the PUBLISHED band, no model)"
                )

    # -- modelled: predicted band is an upper bound, not a probability.
    if not bands:
        out["modelled"]["text"] = f"UNRESOLVED: {why}"
    else:
        preds = [
            r
            for r in recs
            if r.get("band_predicted") in bands
            and isinstance(r.get("hours_spent"), (int, float))
        ]
        if not preds:
            out["modelled"]["text"] = (
                "no record carries both band_predicted and hours -- INCOMPLETE"
            )
        else:
            dollars = sum(midpoint(bands[r["band_predicted"]]) or 0.0 for r in preds)
            h = sum(float(r["hours_spent"]) for r in preds)
            if h <= 0:
                out["modelled"]["text"] = "INCOMPLETE: 0 predicted hours"
            else:
                out["modelled"]["dollars"] = dollars
                out["modelled"]["per_hour"] = dollars / h
                out["modelled"]["text"] = (
                    f"${dollars:,.0f} over {h:.1f}h = ${dollars / h:,.0f}/h "
                    f"({len(preds)} records, predicted band = UPPER BOUND, not a probability)"
                )
    return out


def load(path: Path) -> tuple[list[dict], list[str]]:
    """Read the ledger. Returns (records, warnings).

    A malformed line is reported, never silently dropped: a ranker that hides
    parse failures will eventually rank on half a file and look confident
    about it.
    """
    if not path.exists():
        return [], [f"ledger not found: {path} (no findings logged yet)"]

    records: list[dict] = []
    warnings: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                # A human-readable header is allowed at the top of the ledger.
                # It is not data, and it is not a problem worth warning about.
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                warnings.append(f"line {lineno}: not JSON ({exc.msg}) -- skipped")
                continue
            if not isinstance(obj, dict):
                warnings.append(f"line {lineno}: not a JSON object -- skipped")
                continue
            missing = {"id", "program", "weakness_class", "final_outcome"} - obj.keys()
            if missing:
                warnings.append(
                    f"line {lineno}: missing {', '.join(sorted(missing))} -- skipped"
                )
                continue
            records.append(obj)
    return records, warnings


def fold_by_id(records: list[dict], warnings: list[str]) -> list[dict]:
    """Collapse re-logged findings to their LATEST record.

    The ledger is append-only, so a `pending` finding resolves by appending a
    second line with the same `id`. Counting raw lines would double-count it
    and would let a stale `pending` drag the resolved count down. Latest
    `logged_at` wins; on a tie the later line in the file wins (it was
    appended last, so it is the more recent statement).
    """
    latest: dict[str, dict] = {}
    for rec in records:
        rid = str(rec.get("id", ""))
        prev = latest.get(rid)
        if prev is None or str(rec.get("logged_at", "")) >= str(prev.get("logged_at", "")):
            latest[rid] = rec

    collapsed = len(records) - len(latest)
    if collapsed:
        warnings.append(f"folded {collapsed} re-logged record(s) by id")
    return list(latest.values())


def summarise(records: list[dict], progs: dict | None = None) -> dict:
    group = {}
    if not records:
        return group
    progs = progs or {}

    # Group, then summarise. Sorting is stable so the report is reproducible.
    by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for rec in records:
        by_key[(str(rec.get("program", "")), str(rec.get("weakness_class", "")))].append(rec)

    for (program, weakness), recs in sorted(by_key.items()):
        resolved = sum(1 for r in recs if r.get("final_outcome") != "pending")
        confidence = confidence_for(resolved)

        # -- agreement (both fields meaningful, or the rate is meaningless)
        comparable = [
            r
            for r in recs
            if r.get("pipeline_verdict") not in (None, "n/a")
            and r.get("operator_decision") not in (None, "n/a")
        ]
        agreed = sum(
            1
            for r in comparable
            if (r.get("pipeline_verdict"), r.get("operator_decision")) in AGREEING_PAIRS
        )
        if comparable:
            rate_value = agreed / len(comparable)
            rate_text = (
                f"{rate_value:.2f} ({agreed}/{len(comparable)} comparable) "
                f"-- confidence: {confidence}"
            )
        else:
            rate_value = None
            rate_text = f"no comparable entries -- confidence: {confidence}"

        # -- outcome breakdown (strategy signal, deliberately not a score)
        breakdown = Counter(str(r.get("final_outcome", "unknown")) for r in recs)

        group[f"{program}/{weakness}"] = {
            "program": program,
            "weakness_class": weakness,
            "total_entries": len(recs),
            "resolved_entries": resolved,
            "confidence": confidence,
            "agreement": {
                "rate": rate_value,
                "agreed": agreed,
                "comparable": len(comparable),
                # The one string a formatter is allowed to print.
                "text": rate_text,
            },
            "outcome_breakdown": dict(sorted(breakdown.items())),
            "economics": economics_for(recs, program, progs),
        }
    return group


def render_text(group: dict, warnings: list[str]) -> str:
    out: list[str] = []
    out.append("ADVISORY ONLY -- historical signal for the operator to read.")
    out.append("This report never filters, ranks dispatch order, or gates anything.")
    out.append("A novel finding matches no pattern here by definition; that is expected.")
    out.append("")
    if not group:
        out.append("No findings logged yet. Confidence: insufficient data.")
        for w in warnings:
            out.append(f"  note: {w}")
        return "\n".join(out)

    for key, g in group.items():
        out.append(f"{key}")
        out.append(
            f"  entries: {g['total_entries']}   "
            f"resolved: {g['resolved_entries']}   "
            f"confidence: {g['confidence']}"
        )
        # Printed through the pre-built string, so the label cannot be lost.
        out.append(f"  calibration (verdict vs decision): {g['agreement']['text']}")
        breakdown = ", ".join(f"{k}={v}" for k, v in g["outcome_breakdown"].items())
        out.append(f"  outcomes: {breakdown}")
        eco = g.get("economics") or {}
        if eco:
            hours = eco.get("hours_total")
            hours_txt = f"{hours:.1f}h" if isinstance(hours, (int, float)) else "no hours recorded"
            out.append(
                f"  hours: {hours_txt} "
                f"({eco.get('records_with_hours', 0)} with, "
                f"{eco.get('records_missing_hours', 0)} without)"
            )
            out.append(f"  realised $/h: {eco['realised']['text']}")
            out.append(f"  modelled $/h: {eco['modelled']['text']}")
        out.append("")

    if warnings:
        out.append("Notes:")
        for w in warnings:
            out.append(f"  - {w}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Advisory report over research/outcomes.jsonl (read-only)",
    )
    ap.add_argument("--file", default=str(DEFAULT_LEDGER), help="ledger path")
    ap.add_argument(
        "--bands-file",
        default=str(DEFAULT_BANDS),
        help="published band -> payout table (research/programme-bands.json)",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--program", help="only this program")
    ap.add_argument("--weakness-class", dest="weakness_class", help="only this weakness class")
    args = ap.parse_args()

    records, warnings = load(Path(args.file))
    records = fold_by_id(records, warnings)

    progs, bands_problem = load_bands(Path(args.bands_file))
    if bands_problem:
        warnings.append(bands_problem)

    if args.program:
        records = [r for r in records if str(r.get("program", "")) == args.program]
    if args.weakness_class:
        records = [
            r for r in records if str(r.get("weakness_class", "")) == args.weakness_class
        ]

    group = summarise(records, progs=progs)

    if args.json:
        print(
            json.dumps(
                {
                    "advisory": True,
                    "note": "historical signal only; never used to dispatch, promote or park",
                    "program_filter": args.program,
                    "weakness_class_filter": args.weakness_class,
                    "bands": {"entries": len(progs), "problem": bands_problem},
                    "groups": group,
                    "warnings": warnings,
                },
                indent=2,
            )
        )
    else:
        print(render_text(group, warnings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
