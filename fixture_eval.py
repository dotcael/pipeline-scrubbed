#!/usr/bin/env python3
"""fixture_eval.py — judge labelled evidence, deterministically, with no network.

WHY THIS EXISTS BEFORE ANY EXECUTOR
-----------------------------------
All four advisors in the 2026-10-30 round converged on the same failure: the
false positive that survives to a filed report is **the echoed marker**. A server
reflects your own path parameter back, or returns a 200 carrying an error body,
and every downstream stage is blind -- the committee scores a claim it was told
was reproduced, the challenger attacks the reasoning instead of the bytes.

The cheapest way to find out whether our judge can be fooled is to hand it
labelled evidence with no target, no credentials and no HTTP. If it promotes a
trap here, the design is dead and nothing after it is worth building.

WHAT IT ENFORCES (in code, because prompts get re-litigated every run)
  1. NO CONTROL, NO FINDING. The owner must still receive the object. If the
     control fails, the path is dead or the harness is broken -- that is INVALID,
     never a finding and never a negative.
  2. THE MARKER MUST NOT BE OURS. If the string also appears in our own request,
     the server may simply be echoing it. That is the trap, and it is REFUTED.
  3. A PUBLIC SHELL IS NOT DATA. If the authenticated body equals the
     unauthenticated body, we are looking at a page that is served to everyone.
  4. A 200 CARRYING AN ERROR SHAPE IS NOT A HIT.
  5. A COUNT CHANGE ALONE IS A LEAD, NOT A FINDING. It proves the query saw a
     row; it does not prove protected content crossed.

USAGE
    python3 fixture_eval.py --cases fixtures/cases.json          # table
    python3 fixture_eval.py --cases fixtures/cases.json --self  # exit 1 on any
                                                                # disagreement
    python3 fixture_eval.py --cases fixtures/cases.json --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CASES = HERE / "fixtures" / "cases.json"

# Verdict vocabulary is closed on purpose: a judge that can invent a new
# verdict cannot be compared against a fixture.
VERDICTS = ("reproduced", "refuted", "invalid", "insufficient")

_ERROR_SHAPE = re.compile(
    r'"(error|errors|message)"\s*:\s*"[^"]*(not found|forbidden|unauthori[sz]ed|'
    r'permission|denied|invalid|does not exist)',
    re.IGNORECASE,
)


def _body(req: dict | None) -> str:
    return (req or {}).get("body", "") or ""


def _status(req: dict | None) -> int:
    return int((req or {}).get("status", 0) or 0)


def evaluate(case: dict) -> tuple[str, str]:
    """Return (verdict, reason). Pure function of the case; never guesses."""
    marker = case.get("marker", "")
    reqs = case.get("requests") or {}
    test = reqs.get("test")
    control = reqs.get("control")

    # 1 -- a control is mandatory. Without it nothing can be concluded.
    if not control:
        return "invalid", "no control request: a 200 from the test proves nothing"

    if _status(control) >= 400:
        return (
            "invalid",
            f"control failed (HTTP {_status(control)}): the path is dead or the "
            "harness is broken -- not a finding, not a negative",
        )

    test_body = _body(test)
    control_body = _body(control)

    # 2 -- public shell: identical body with and without authentication.
    unauth = reqs.get("unauthenticated")
    if unauth is not None and test_body.strip() and test_body.strip() == _body(unauth).strip():
        return "refuted", "body matches the unauthenticated response: public shell, not data"

    # 3 -- 200 carrying an error shape.
    if _ERROR_SHAPE.search(test_body):
        return "refuted", "200 with an error shape in the body: the app refused, the status lied"

    if not marker:
        return "invalid", "no marker declared: nothing to look for"

    # 4 -- the trap: the marker is one we sent, so the server may be echoing it.
    if case.get("marker_source") == "own_request":
        return (
            "refuted",
            "marker appears in our own request: server echo, not another "
            "principal's data (the single most common false positive)",
        )

    # 5 -- the marker must actually be in the test response, and the control
    # must show it belongs to the owner's record.
    if marker not in test_body:
        counts = case.get("counts") or {}
        if counts.get("test", 0) > 0:
            return (
                "insufficient",
                "only a count changed and no protected value appeared: a lead, "
                "not a disclosure",
            )
        return "refuted", "marker absent from the test response"

    if marker not in control_body:
        return (
            "invalid",
            "marker absent from the CONTROL response: it is not in the owner's "
            "record either, so nothing was crossed",
        )

    return "reproduced", "marker present in the test response, absent from our request, present for the owner"


def run(cases: list[dict]) -> list[dict]:
    out = []
    for case in cases:
        verdict, reason = evaluate(case)
        expected = case.get("expected")
        out.append(
            {
                "id": case.get("id", "?"),
                "label": case.get("label", "?"),
                "expected": expected,
                "verdict": verdict,
                "pass": verdict == expected,
                "reason": reason,
            }
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(DEFAULT_CASES))
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--self",
        dest="self_check",
        action="store_true",
        help="exit non-zero if any fixture disagrees with its label",
    )
    args = ap.parse_args()

    path = Path(args.cases)
    if not path.exists():
        print(f"refused: no cases at {path}", file=sys.stderr)
        return 2
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        print("refused: cases file must be a non-empty list", file=sys.stderr)
        return 2

    results = run(cases)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        width = max(len(r["id"]) for r in results) + 2
        for r in results:
            flag = "ok  " if r["pass"] else "FAIL"
            print(f"  {flag} {r['id']:<{width}} {r['label']:<22} -> {r['verdict']}")
            if not r["pass"]:
                print(f"        expected {r['expected']}, got {r['verdict']}: {r['reason']}")
        bad = [r for r in results if not r["pass"]]
        print(f"\n{len(results) - len(bad)}/{len(results)} fixtures judged as labelled")

    if args.self_check:
        bad = [r for r in results if not r["pass"]]
        if bad:
            print(
                "\nFALSIFIED: the judge disagrees with labelled evidence. Do not "
                "build an executor on top of this.",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
