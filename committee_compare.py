#!/usr/bin/env python3
"""
committee_compare.py — Compares SEVERITY BANDS across committee models.

WHY BANDS, NOT SCORES
---------------------
The payout unit is the band, not the number. Abercrombie & Fitch pays Low $250 /
Medium $750 / High $2,600 / Critical $2,250, and CVSS 3.1 bands are Low <=3.9,
Medium <=6.9, High <=8.9, Critical above. A committee that answers 5.4 / 6.5 /
4.6 has NOT disagreed about anything that costs money -- all three are Medium,
all three are $750. The old numeric tolerance (+/-0.4) called that a "split" and
parked the finding, which is how a 2026-10-22 evidence packet for
`setDefaultAddress` (5.4/6.5/4.6) was parked while the whole committee agreed
on the band.

WHAT IS CALCULATED, WHAT IS ESTIMATED
--------------------------------------
A model estimates the CVSS *metrics* (AV/AC/PR/UI/S/C/I/A). The *score* is then
CALCULATED by tools/cvss31.py from that vector, and the *band* is read off the
score by the same module. The model never states a score, so there is no
free-text number to trust: "CALCULATE, never estimate" is satisfied by
construction, and the vector is kept in the summary so a human can audit the
metrics that produced the band.

LEGACY MEMBERS
--------------
A member that emits only {"base_score": X} is still counted, but its band is
derived from that estimated number and the member is marked
basis="estimated_score" in the summary, so the difference between a calculated
band and an estimated one is visible rather than silent. A member that emits
neither is a NON-VOTE, not a disagreement.

BAND "None" IS NOT A BAND
-------------------------
CVSS 3.1 "None" means score 0.0 -- the member does not think there is an
impact. Two members agreeing that nothing is wrong is not a severity
agreement, so None-band members are recorded as non-voting instead of forming
an agreeing pair.

Usage: echo -e "modelA:...\nmodelB:...\nmodelC:..." | python3 committee_compare.py
Prints "promote" or "park" to stdout. Exit code 0 either way (valid outcome,
not an error). Exit code 2 if the CVSS calculator is unavailable -- comparing
bands without it would mean guessing, and the pipeline must fail loudly rather
than silently fall back to a numeric tolerance.

Set COMMITTEE_SUMMARY=<path> to also write a JSON summary of the vote.
"""
import json
import os
import re
import sys
from decimal import Decimal
from itertools import combinations

_PIPELINE_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.dirname(_PIPELINE_DIR)
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

try:
    import cvss31
except ImportError:  # pragma: no cover - depends on deployment
    cvss31 = None

# Kept only so the summary can report the old rule; the band is what is
# compared now. The numeric spread is still RECORDED for human review.
NUMERIC_SPREAD = 0.4

# TWO ALTERNATIVES, TWO GROUPS. The second alternative had NO capturing group
# while the code read match.group(2), so any answer that quoted a bare vector
# (rather than the {"cvss_vector": "..."} JSON form) crashed the whole compare
# with `IndexError: no such group` -- the run died after the committee had
# already spent its calls, so the result was paid for and thrown away. The
# suite never caught it because every fixture used the JSON form, i.e. it only
# ever exercised the first alternative.
_VECTOR_RE = re.compile(
    r'"cvss_vector"\s*:\s*"([^"]+)"'
    r'|(CVSS:3\.1/[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])+)',
    re.IGNORECASE,
)
_SCORE_RE = re.compile(r'"base_score"\s*:\s*([0-9]+\.?[0-9]*)')


def extract_vector(text: str) -> str | None:
    """Pull a CVSS 3.1 vector out of a member's answer."""
    match = _VECTOR_RE.search(text)
    if not match:
        return None
    vector = match.group(1) or match.group(2)
    if not vector:
        return None
    vector = vector.strip()
    if not vector.upper().startswith("CVSS:3.1/"):
        vector = "CVSS:3.1/" + vector.lstrip("/")
    return vector


def extract_score(text: str) -> float | None:
    """Pull the numeric value out of a {"base_score": 6.5} fragment."""
    match = _SCORE_RE.search(text)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def band_for_vector(vector: str) -> tuple[str, str] | None:
    """CALCULATE the score and band from a vector. None if the vector is bad."""
    if cvss31 is None:
        return None
    try:
        metrics = cvss31.parse_vector(vector)
        result = cvss31.compute(metrics)
    except (ValueError, IndexError):
        return None
    base = result["base"]
    return str(base), cvss31.severity(base)


def band_for_score(score: float) -> tuple[str, str] | None:
    """Band from an ESTIMATED score. Recorded as such, never as calculated."""
    if cvss31 is None:
        return None
    try:
        base = Decimal(str(score))
    except Exception:
        return None
    return str(base), cvss31.severity(base)


def write_summary(summary):
    """Write a machine-readable summary so the stage can report the basis.

    Opt-in via COMMITTEE_SUMMARY env var; stdout stays exactly "promote"/"park".
    """
    path = os.environ.get("COMMITTEE_SUMMARY")
    if not path:
        return
    try:
        with open(path, "w") as fh:
            json.dump(summary, fh, indent=2)
    except OSError as exc:  # summary is best-effort; never fail the verdict
        print(f"[warn] could not write committee summary: {exc}", file=sys.stderr)


def split_record(line: str) -> tuple[str, str] | None:
    """Split a record into (model, text).

    Preferred format is TAB-delimited: "model<TAB>text". Model ids can contain
    colons -- e.g. "openrouter/minimax/minimax-m3.1-flash:free" -- and the JSON
    payload contains colons too, so a colon delimiter is ambiguous on both
    sides. A tab is safe: extract_text.py collapses ALL whitespace in the text
    (including tabs) before emitting it, and model ids never contain tabs.

    Falls back to the legacy colon format for the documented standalone test
    cases. For that path, try each colon position right-to-left and take the
    first split whose text yields a score, so a colon inside the model id is
    not mistaken for the delimiter.
    """
    if "\t" in line:
        model, text = line.split("\t", 1)
        return model, text

    if ":" not in line:
        return None
    positions = [i for i, ch in enumerate(line) if ch == ":"]
    fallback = None
    for pos in reversed(positions):
        model, text = line[:pos], line[pos + 1:]
        if fallback is None:
            fallback = (model, text)
        if extract_score(text) is not None or extract_vector(text) is not None:
            return model, text
    return fallback


def main() -> int:
    if cvss31 is None:
        print(
            f"[error] tools/cvss31.py not importable from {_TOOLS_DIR!r};"
            " band comparison requires the CVSS calculator",
            file=sys.stderr,
        )
        return 2

    members: dict[str, dict] = {}
    non_voting: list[str] = []

    for line in sys.stdin:
        line = line.rstrip("\n")
        if ":" not in line and "\t" not in line:
            # skip lines without a model/text separator
            continue
        parts = split_record(line)
        if parts is None:
            continue
        model, text = parts

        vector = extract_vector(text)
        if vector:
            computed = band_for_vector(vector)
            if computed is None:
                non_voting.append(model)
                print(f"[warn] unusable cvss_vector from {model}", file=sys.stderr)
                continue
            score, band = computed
            members[model] = {
                "score": score,
                "band": band,
                "vector": vector,
                "basis": "calculated_from_vector",
            }
            continue

        score = extract_score(text)
        if score is not None:
            computed = band_for_score(score)
            if computed is None:
                non_voting.append(model)
                print(f"[warn] unusable base_score from {model}", file=sys.stderr)
                continue
            s, band = computed
            members[model] = {
                "score": s,
                "band": band,
                "vector": None,
                "basis": "estimated_score",
            }
            continue

        # A member that errored or produced nothing usable is a NON-VOTE, not a
        # disagreement. Track it separately so the verdict can say whether the
        # committee was full or degraded.
        non_voting.append(model)
        print(f"[warn] no parseable severity from {model}", file=sys.stderr)

    total_members = len(members) + len(non_voting)

    # "None" is not a severity band -- it means the member does not believe
    # there is an impact. Two members agreeing on "nothing to see" is not a
    # severity agreement, so None-band members do not form agreeing pairs.
    band_votes = {m: v for m, v in members.items() if v["band"] != "None"}
    none_banded = [m for m, v in members.items() if v["band"] == "None"]

    # Agreement = SAME BAND. That is the comparison the payout cares about.
    agreeing_pairs = []
    for (m1, v1), (m2, v2) in combinations(band_votes.items(), 2):
        if v1["band"] == v2["band"]:
            agreeing_pairs.append((m1, m2, v1["band"], v1["score"], v2["score"]))

    spreads = []
    for (m1, v1), (m2, v2) in combinations(members.items(), 2):
        try:
            spreads.append(abs(float(v1["score"]) - float(v2["score"])))
        except (TypeError, ValueError):
            continue

    print(
        "[info] bands: "
        + str({m: f"{v['band']}({v['score']})" for m, v in members.items()}),
        file=sys.stderr,
    )
    print(
        f"[info] agreeing pairs (same band): "
        + str([(a, b, band) for a, b, band, _s1, _s2 in agreeing_pairs]),
        file=sys.stderr,
    )
    if spreads:
        print(
            f"[info] numeric spread (recorded, NOT the criterion): "
            f"max={max(spreads):.1f} min={min(spreads):.1f}",
            file=sys.stderr,
        )
    print(
        f"[info] votes: {len(band_votes)}/{total_members}"
        + (f" (non-voting: {', '.join(non_voting)})" if non_voting else "")
        + (f" (None-band, not counted: {', '.join(none_banded)})" if none_banded else ""),
        file=sys.stderr,
    )

    summary = {
        "verdict": "park",
        "basis": "insufficient",
        "criterion": "same CVSS 3.1 severity band",
        "votes": len(band_votes),
        "total_members": total_members,
        "members": members,
        "non_voting": non_voting,
        "none_banded": none_banded,
        "agreeing_pairs": [
            {"model_a": a, "model_b": b, "band": band, "score_a": s1, "score_b": s2}
            for a, b, band, s1, s2 in agreeing_pairs
        ],
        "numeric_spread_max": (round(max(spreads), 2) if spreads else None),
        "numeric_tolerance_recorded": NUMERIC_SPREAD,
    }

    if len(band_votes) < 2:
        # Need at least two different models to compare
        print("park", file=sys.stdout)
        print(
            f"[info] fewer than 2 band votes ({len(band_votes)}); parking",
            file=sys.stderr,
        )
        summary["verdict"] = "park"
        summary["basis"] = "insufficient"
        write_summary(summary)
        return 0

    verdict = "promote" if agreeing_pairs else "park"

    # A degraded committee is NOT the same as a genuine split. With 3 configured
    # members, "2 of 3 agree" needs one agreeing pair. If a member dropped out,
    # agreement becomes unanimous among whoever responded -- a stricter bar on
    # weaker evidence. The operator needs to tell those apart.
    if total_members and len(band_votes) < total_members:
        basis = "degraded"
        print(
            f"[info] committee DEGRADED: {len(band_votes)} of {total_members} members voted;"
            " agreement is unanimous among responders, not 2-of-3",
            file=sys.stderr,
        )
    else:
        basis = "full"

    print(verdict)
    summary["verdict"] = verdict
    summary["basis"] = basis
    if agreeing_pairs:
        summary["consensus_band"] = agreeing_pairs[0][2]
    write_summary(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
