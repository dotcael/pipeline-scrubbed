#!/usr/bin/env python3
"""
disagreement.py — EVALUATOR vs INDEPENDENT CHALLENGER, and the matrix between them.

WHY TWO ROLES
--------------
A committee that only agrees is a committee that only measures severity. A
severity band says what a finding is WORTH; it says nothing about whether the
finding EXISTS. Those are different questions, and a pipeline that answers
only the first will happily promote a well-scored non-finding.

So two roles answer two questions, and neither sees the other's answer:

  EVALUATOR   "does the evidence support the claim, and how severe is it?"
              -> support: SUPPORTED | REFUTED | UNTESTED
  CHALLENGER  "attack the claim — what is the strongest reason it fails?"
              -> attack:  HOLDS | INCONCLUSIVE | FALLS

They are deliberately INDEPENDENT: the challenger is asked to break the
hypothesis, not to confirm the evaluator. A challenger that only sees the
evaluator's verdict anchors on it and rubber-stamps it.

THE MATRIX
----------
Three dimensions, each of which can disagree:

  severity  the severity BAND, CALCULATED from each side's CVSS vector with
            tools/cvss31.py. Not the numbers the models wrote — the bands.
  support   SUPPORTED/HOLDS = 1, UNTESTED/INCONCLUSIVE = 0, REFUTED/FALLS = -1
  boundary  did the test actually cross an authorisation boundary? YES/NO

VERDICT
-------
  AGREED_SUPPORTED  every KNOWN dimension agrees AND the claim is SUPPORTED
                    (evaluator SUPPORTED / challenger HOLDS)
  AGREED_UNTESTED   the reviewers agree, but on INCONCLUSIVE/UNTESTED
  AGREED_REFUTED    the reviewers agree, but on REFUTED/FALLS
  INCOMPLETE        a dimension could not be assessed (a gap)
  CONTESTED         at least one dimension disagrees

ONLY `AGREED_SUPPORTED` PROMOTES. The others park.

That last line is the whole point, and it was learned the hard way on
2026-10-22: a live run produced an evaluator saying UNTESTED and a challenger
saying INCONCLUSIVE -- both correctly noting that the evidence never sent a
traversal payload -- and the matrix said "the two agree", so the pipeline
PROMOTED it. Agreement on "the evidence does not settle this" is agreement on
NOT HAVING A FINDING. The verdict has to distinguish agreement about the
CLAIM from agreement about the EVIDENCE.

Usage:
    python3 disagreement.py --evaluator <file> --challenger <file> [--json]
Exit: 0 = AGREED_SUPPORTED (promote), 2 = CONTESTED, 1 = any other park,
3 = unusable input.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import cvss31
except ImportError:  # pragma: no cover
    cvss31 = None

SUPPORT_SCALE = {"SUPPORTED": 1, "UNTESTED": 0, "REFUTED": -1}
ATTACK_SCALE = {"HOLDS": 1, "INCONCLUSIVE": 0, "FALLS": -1}

_VECTOR_RE = re.compile(r"CVSS:3\.1/[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])+", re.IGNORECASE)


def _load_json_blob(path: str) -> dict:
    """Read a role's answer: a JSON file, or JSON embedded in free text."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(raw)
    except ValueError:
        pass
    # fall back: the first {...} block in the text
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"no JSON in {path}")
    try:
        return json.loads(raw[start:end + 1])
    except ValueError as exc:
        raise ValueError(f"no usable JSON in {path}: {exc}")


def _find_value(blob: dict, *keys) -> str:
    """Look for a key at the top level, then one level down."""
    for k in keys:
        if k in blob and isinstance(blob[k], (str, int, float)):
            return str(blob[k]).strip()
    for v in blob.values():
        if isinstance(v, dict):
            for k in keys:
                if k in v and isinstance(v[k], (str, int, float)):
                    return str(v[k]).strip()
    return ""


def extract_vector(blob: dict, text: str = "") -> str:
    raw = _find_value(blob, "cvss_vector", "vector", "severity_vector")
    if raw:
        v = raw.strip()
        if not v.upper().startswith("CVSS:3.1/"):
            v = "CVSS:3.1/" + v.lstrip("/")
        return v
    m = _VECTOR_RE.search(text)
    if m:
        return m.group(0)
    return ""


def band_of(vector: str) -> str:
    """CALCULATE the band from a vector. '' if the vector is unusable."""
    if not vector or cvss31 is None:
        return ""
    try:
        base = cvss31.compute(cvss31.parse_vector(vector))["base"]
    except (ValueError, IndexError):
        return ""
    return cvss31.severity(base)


def evaluate(evaluator_blob: dict, challenger_blob: dict, evaluator_text="", challenger_text="") -> dict:
    """Build the disagreement matrix and the verdict."""
    ev_vec = extract_vector(evaluator_blob, evaluator_text)
    ch_vec = extract_vector(challenger_blob, challenger_text)

    ev_support = _find_value(evaluator_blob, "support", "verdict").upper()
    ch_attack = _find_value(challenger_blob, "attack", "verdict").upper()
    ev_boundary = _find_value(evaluator_blob, "boundary").upper()
    ch_boundary = _find_value(challenger_blob, "boundary").upper()

    dims = []

    # severity -- compared as CALCULATED bands
    ev_band = band_of(ev_vec)
    ch_band = band_of(ch_vec)
    if ev_band and ch_band:
        agree = ev_band == ch_band
        dims.append({
            "dimension": "severity",
            "evaluator": ev_band,
            "challenger": ch_band,
            "agree": agree,
            "known": True,
            "detail": f"{ev_vec} vs {ch_vec}",
        })
    else:
        dims.append({
            "dimension": "severity",
            "evaluator": ev_band or "UNKNOWN",
            "challenger": ch_band or "UNKNOWN",
            "agree": None,
            "known": False,
            "detail": f"{ev_vec or 'no vector'} vs {ch_vec or 'no vector'}",
        })

    # support -- mapped onto one scale
    ev_s = SUPPORT_SCALE.get(ev_support)
    ch_s = ATTACK_SCALE.get(ch_attack)
    if ev_s is not None and ch_s is not None:
        dims.append({
            "dimension": "support",
            "evaluator": ev_support,
            "challenger": ch_attack,
            "agree": ev_s == ch_s,
            "known": True,
            "detail": f"scale {ev_s} vs {ch_s}",
        })
    else:
        dims.append({
            "dimension": "support",
            "evaluator": ev_support or "UNKNOWN",
            "challenger": ch_attack or "UNKNOWN",
            "agree": None,
            "known": False,
            "detail": "one side did not answer",
        })

    # boundary -- YES / NO
    ev_b = ev_boundary if ev_boundary in ("YES", "NO") else ""
    ch_b = ch_boundary if ch_boundary in ("YES", "NO") else ""
    if ev_b and ch_b:
        dims.append({
            "dimension": "boundary",
            "evaluator": ev_b,
            "challenger": ch_b,
            "agree": ev_b == ch_b,
            "known": True,
            "detail": "authorisation boundary crossed",
        })
    else:
        dims.append({
            "dimension": "boundary",
            "evaluator": ev_b or "UNKNOWN",
            "challenger": ch_b or "UNKNOWN",
            "agree": None,
            "known": False,
            "detail": "one side did not answer",
        })

    known = [d for d in dims if d["known"]]
    gaps = [d for d in dims if not d["known"]]
    disagreements = [d for d in known if not d["agree"]]

    # The SUPPORT scale decides promotion. Agreement on "inconclusive" is
    # agreement that there is no finding yet, so it must not promote.
    support_value = None
    for d in dims:
        if d["dimension"] != "support" or not d["known"]:
            continue
        ev_s = SUPPORT_SCALE.get(d["evaluator"])
        ch_s = ATTACK_SCALE.get(d["challenger"])
        support_value = ev_s if ev_s is not None else ch_s

    if disagreements:
        verdict = "CONTESTED"
    elif gaps:
        verdict = "INCOMPLETE"
    elif support_value == 1:
        verdict = "AGREED_SUPPORTED"
    elif support_value == 0:
        verdict = "AGREED_UNTESTED"
    else:
        verdict = "AGREED_REFUTED"

    return {
        "verdict": verdict,
        "promotable": verdict == "AGREED_SUPPORTED",
        "support_scale": support_value,
        "dimensions": dims,
        "disagreements": [d["dimension"] for d in disagreements],
        "gaps": [d["dimension"] for d in gaps],
        "evaluator_vector": ev_vec,
        "challenger_vector": ch_vec,
        "evaluator_band": ev_band,
        "challenger_band": ch_band,
        "evaluator_support": ev_support,
        "challenger_attack": ch_attack,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="evaluator vs challenger disagreement matrix")
    p.add_argument("--evaluator", required=True, help="evaluator answer (file)")
    p.add_argument("--challenger", required=True, help="challenger answer (file)")
    p.add_argument("--json", action="store_true", help="print only the JSON result")
    args = p.parse_args(argv)

    try:
        ev_blob = _load_json_blob(args.evaluator)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    try:
        ch_blob = _load_json_blob(args.challenger)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    ev_text = ""
    ch_text = ""
    for path, which in ((args.evaluator, "ev"), (args.challenger, "ch")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                t = fh.read()
        except OSError:
            t = ""
        if which == "ev":
            ev_text = t
        else:
            ch_text = t

    result = evaluate(ev_blob, ch_blob, ev_text, ch_text)

    if not args.json:
        print(f"  matrix ({result['verdict']}):", file=sys.stderr)
        for d in result["dimensions"]:
            mark = {True: "agree", False: "DISAGREE", None: "unknown"}[d["agree"]]
            print(f"    {d['dimension']:<9} evaluator={d['evaluator']:<12} "
                  f"challenger={d['challenger']:<12} {mark}", file=sys.stderr)
    print(json.dumps(result, indent=2))
    if result["verdict"] == "AGREED_SUPPORTED":
        return 0
    if result["verdict"] == "CONTESTED":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
