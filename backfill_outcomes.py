#!/usr/bin/env python3
"""backfill_outcomes.py -- recover the repo's hunting history into the ledger.

WHY THIS EXISTS
---------------
`research/outcomes.jsonl` is the ledger `rank_patterns.py` reads, and on
2026-10-30 it held ONE record. The repo meanwhile holds 16 lanes, 5 findings,
a dozen logged negatives, 8 submissions and a dupe registry -- written as
PROSE, in files no tool reads. So the pipeline was "learning" from 1 data
point while 95% of the evidence sat on disk.

WHAT IT READS (structured shapes only)
--------------------------------------
  findings.md                     the Findings table (outcome from Status) and
                                  the Negatives tables (tested-and-solid)
  platforms/**/SUBMISSION*.md      filed reports: `> **Filed:** <date>` + id
  research/dupe-registry.json      capability classes already filed/duped

WHAT IT REFUSES TO DO
---------------------
  * It does not guess an outcome. A row whose Status it cannot classify is
    SKIPPED and printed, never defaulted to "no bug" (which would invent a
    miss) or to "pending" (which would invent a hit).
  * A MISSING SOURCE IS NOT AN EMPTY SOURCE. If findings.md is absent, that is
    reported as MISSING and `--strict` fails; it does not become "0 rows".
  * It is idempotent: every backfilled record gets a DETERMINISTIC id derived
    from its source location, and a row already in the ledger is skipped.

CLASS INFERENCE IS LABELLED
---------------------------
`class_id` comes from keywords in taxonomy.yaml. Every such row is written
with `class_source: "inferred"` so a machine guess is never presented as a
declaration. A row matching nothing becomes OTHER with the reason printed.

USAGE
-----
    python3 backfill_outcomes.py                  # dry run: plan + reconciliation
    python3 backfill_outcomes.py --write          # append to the ledger
    python3 backfill_outcomes.py --strict         # exit 1 on any missing source
                                                  # or any skipped row
EXIT
    0 ok, 1 reconciliation problem (--strict), 2 bad invocation
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parents[1]
LEDGER = REPO / "research" / "outcomes.jsonl"
TAXONOMY = TOOLS / "taxonomy.yaml"
FINDINGS = REPO / "findings.md"
DUPE_REGISTRY = REPO / "research" / "dupe-registry.json"
PLATFORMS = REPO / "platforms"

sys.path.insert(0, str(TOOLS))
import log_outcome  # noqa: E402

PLATFORM_WORDS = ("program-a", "program-b")


# ── helpers ───────────────────────────────────────────────────────────────
def load_taxonomy() -> list:
    import yaml

    data = yaml.safe_load(TAXONOMY.read_text(encoding="utf-8")) or {}
    out = []
    for cls in data.get("classes") or []:
        if not isinstance(cls, dict) or not cls.get("id"):
            continue
        kws = [str(k).lower() for k in (cls.get("keywords") or []) if str(k).strip()]
        cwes = [str(c).upper() for c in (cls.get("cwe") or []) if str(c).strip()]
        # Longest first: "cross-account write" must win over "write".
        out.append(
            {"id": cls["id"], "keywords": sorted(kws, key=len, reverse=True), "cwe": cwes}
        )
    return out


def score_text(text: str, taxonomy: list, headline: str = "") -> tuple[str, str | None, int]:
    """Return (class_id, best_matched_keyword).

    Scored, weighted by WHERE the words appear. A hit in the finding's own
    HEADLINE counts 3 and a hit in the supporting prose counts 1: the title
    says what the finding IS, while the impact column says what it would
    cost. Unweighted, the CoinDesk row classified as RATE_LIMIT_QUOTA because
    its impact text mentions "x-ratelimit" headers and an "unmetered channel"
    more often than the headline says "authentication".

    Not first-match-wins either: order-based routing gave the unico finding
    (sourcemaps + a hardcoded sign_id) the class AUTH_BYPASS purely because
    "sign token" is listed before "source map" in taxonomy.yaml.
    """
    head, body = headline.lower(), text.lower()
    best_id, best_kw, best_key = "OTHER", None, None
    for order, cls in enumerate(taxonomy):
        score, kw = 0, None
        for word in cls["keywords"]:
            if not word:
                continue
            hit_h = word in head
            hit_b = word in body
            if hit_h:
                score += 3
            if hit_b:
                score += 1
            if (hit_h or hit_b) and (kw is None or len(word) > len(kw)):
                kw = word
        if score == 0:
            continue
        key = (score, len(kw or ""), -order)
        if best_key is None or key > best_key:
            best_id, best_kw, best_key = cls["id"], kw, key
    return best_id, best_kw, (best_key[0] if best_key else 0)


def classify(text: str, taxonomy: list, headline: str = "") -> tuple[str, str | None]:
    best_id, kw, _ = score_text(text, taxonomy, headline)
    return best_id, kw


def classify_cwe(weakness: str, taxonomy: list) -> tuple[str | None, str | None]:
    """CWE id -> class, when the source declares one. None when it does not."""
    found = re.findall(r"CWE-(\d+)", weakness.upper())
    for number in found:
        for cls in taxonomy:
            if f"CWE-{number}" in cls.get("cwe", []):
                return cls["id"], f"CWE-{number}"
    return None, None


def decide_dupe_class(capability: str, weakness: str, taxonomy: list) -> tuple[str, str | None]:
    """Class for a dupe-registry entry.

    The registry often declares SEVERAL CWEs ("CWE-200 / CWE-321 / CWE-798")
    and taking the first is an accident of how the author ordered them: it
    sent the unico entry (sourcemaps + a hardcoded sign_id) to
    INFO_DISCLOSURE while the SAME finding in findings.md was
    DEPLOY_ARTEFACT, so one finding appeared under two classes.

    So: a single CWE decides. Several CWEs are disambiguated by the
    capability TEXT, and only if the text agrees with one of the candidate
    classes -- otherwise the declaration wins.
    """
    # CWE-200 ("information exposure") is true of almost anything that leaks
    # something, so it says nothing about which class a finding BELONGS to.
    # It is kept only as a fallback when the text offers nothing more specific.
    GENERIC = {"INFO_DISCLOSURE"}
    specific, generic = [], []
    for number in re.findall(r"CWE-(\d+)", weakness.upper()):
        for cls in taxonomy:
            if f"CWE-{number}" in cls.get("cwe", []):
                target = generic if cls["id"] in GENERIC else specific
                if cls["id"] not in target:
                    target.append(cls["id"])
    candidates = specific if specific else generic
    if candidates:
        from_text, kw, strength = score_text(capability, taxonomy)
        # Precedence: a DECLARED CWE wins unless the capability text matches a
        # class strongly (>=2 distinct keywords). The CWE field is a
        # dupe-matching tag typed by hand; the capability sentence is the
        # substance of what was filed.
        if strength >= 2 and from_text:
            return from_text, kw
        if from_text in candidates:
            return from_text, kw
        return candidates[0], None
    return classify(capability, taxonomy)


def norm_program(raw: str) -> str:
    """'**Example Program**' -> 'example-program'."""
    s = raw.replace("*", "").strip()
    s = re.sub(r"\((?:%s)\)" % "|".join(PLATFORM_WORDS), "", s, flags=re.I)
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "unknown"


def det_id(source_loc: str) -> str:
    """Deterministic id: same source row -> same id -> idempotent re-runs."""
    return "bf-" + hashlib.sha1(source_loc.encode("utf-8")).hexdigest()[:14]


def split_row(line: str) -> list:
    """Split a markdown table row on pipes that are NOT inside a code span.

    `findings.md` contains curl commands in backticks with `|` in them. A naive
    split turns one row into eleven and silently misaligns every column after
    it -- which reads exactly like "unparseable row".
    """
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    cells, buf, in_code = [], [], False
    for ch in body:
        if ch == "`":
            in_code = not in_code
            buf.append(ch)
        elif ch == "|" and not in_code:
            cells.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    cells.append("".join(buf).strip())
    return cells


# ── source: findings.md ───────────────────────────────────────────────────
FINDING_STATUS_RULES = (
    # (regex, final_outcome)  -- order matters, most specific first.
    (r"\bpaid\b|payout (?:received|confirmed)", "paid"),
    (r"\bduplicate\b|\bdup of\b", "duplicate"),
    (r"not applicable|\bn/a\b|informative only", "not_applicable"),
    (r"refuted|not reproduced|could not reproduce", "not_reproduced"),
    (r"unreachable|scope denied|identity gate|capacity gate", "unreachable"),
    (r"accepted|submitted|awaiting triage|triage", "pending"),
    (r"active|in progress|no finding yet|testing phase", "pending"),
)


def parse_findings(taxonomy: list) -> tuple[list, list]:
    """Parse the findings table and the negatives tables in findings.md.

    Shape is keyed off the ROW ID, not off a header sniff. The file's
    negatives section begins with rows and no header at all (the header lives
    in an earlier section), so any parser that waits for a header will treat
    the first negative as the header and then report every real negative as
    "no result text" -- silence that looks like an empty source.

    Two schemas, both fixed by the file's own convention:
        <digits>  -> | # | Program | Severity | Finding | Location/URL |
                      Evidence | Reproduction | Impact | Status |
        N-<n>     -> | # | Program | Checked | Result | Evidence |
    """
    records, skipped = [], []
    if not FINDINGS.exists():
        return records, skipped

    lines = FINDINGS.read_text(encoding="utf-8", errors="replace").splitlines()

    for idx, line in enumerate(lines, 1):
        if not line.strip().startswith("|"):
            continue
        cells = split_row(line)
        if not cells or not cells[0]:
            continue
        rid = cells[0]
        if set(rid) <= set("-: "):
            continue                                    # separator row
        if rid.lower().lstrip("#").strip() in ("#", "n-#", ""):
            continue                                    # header row

        is_negative = bool(re.match(r"^N-\d+$", rid, re.I))
        is_finding = bool(re.match(r"^\d+$", rid))
        if not (is_negative or is_finding):
            continue

        if is_finding:
            if len(cells) < 9:
                skipped.append(
                    (f"findings.md:{idx}", f"finding row has {len(cells)} cells, expected 9")
                )
                continue
            _, program, severity, finding, location, evidence, _repro, impact, status = cells[:9]
            text = " ".join(filter(None, [finding, impact, severity]))
            location = location or "see findings.md"
            headline = finding
        else:
            if len(cells) < 5:
                skipped.append(
                    (f"findings.md:{idx}", f"negative row has {len(cells)} cells, expected 5")
                )
                continue
            program, checked, result, evidence = cells[1], cells[2], cells[3], cells[4]
            text = " ".join(filter(None, [checked, result]))
            location = checked or "see findings.md"
            headline = checked
            status = ""

        if not text.strip():
            skipped.append((f"findings.md:{idx}", "row has no finding/result text"))
            continue

        class_id, kw = classify(text + " " + location, taxonomy, headline=headline)
        prog = norm_program(program)

        if is_negative:
            # A negative row is a MISS: tested, and the surface held.
            records.append(
                {
                    "loc": f"findings.md:{idx}:{rid}",
                    "program": f"findings:{prog}",
                    "class_id": class_id,
                    "keyword": kw,
                    "class_inferred": True,
                    "final_outcome": "not_applicable",
                    "asset": location[:300],
                    "weakness_class": text.strip()[:200],
                    "evidence": f"findings.md negative {rid}: {evidence[:200]}",
                    "resolved_at": None,
                    "payout_band": None,
                }
            )
            continue

        outcome = None
        for pattern, mapped in FINDING_STATUS_RULES:
            if re.search(pattern, status, re.I):
                outcome = mapped
                break
        if outcome is None:
            skipped.append(
                (f"findings.md:{idx}", f"unclassifiable Status: {status[:70]!r}")
            )
            continue

        dated = re.search(r"(20\d{2}-\d{2}-\d{2})", status) or re.search(
            r"(20\d{2}-\d{2}-\d{2})", line
        )
        # `resolved_at` is forbidden on a pending record by the schema, and
        # correctly so: a submission date is not a resolution.
        resolved = None if outcome == "pending" else (f"{dated.group(1)}T00:00:00Z" if dated else None)
        if outcome == "paid" and not dated:
            resolved = None
        records.append(
            {
                "loc": f"findings.md:{idx}:{rid}",
                "program": f"findings:{prog}",
                "class_id": class_id,
                "keyword": kw,
                "class_inferred": True,
                "final_outcome": outcome,
                "asset": location[:300],
                "weakness_class": text.strip()[:200],
                "evidence": f"findings.md #{rid}: {(status or 'no status')[:180]}",
                "resolved_at": resolved,
                # Required by the schema when paid; the real band is filled in
                # by hand later. Never a dollar figure.
                "payout_band": "Medium" if outcome == "paid" else None,
            }
        )
    return records, skipped


# ── source: submissions ───────────────────────────────────────────────────
FILED_RE = re.compile(r"\*\*Filed:\*\*\s*([0-9]{4}-[0-9]{2}-[0-9]{2})")
ID_RE = re.compile(r"`([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`")
FILENAME_DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2})")


def parse_submissions(taxonomy: list) -> tuple[list, list]:
    records, skipped = [], []
    if not PLATFORMS.exists():
        return records, skipped
    for path in sorted(PLATFORMS.rglob("SUBMISSION*.md")):
        rel = path.relative_to(REPO).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            skipped.append((rel, f"unreadable: {exc}"))
            continue
        m = FILED_RE.search(text)
        # Revision rank: "…-mask.md" is the original, "…-mask-V3.md" the
        # newest. Alphabetical sort puts uppercase "V" before lowercase "m",
        # so filename order is NOT chronological and cannot decide this.
        rev_match = re.search(r"-V(\d+)\.md$", path.name, re.I)
        rev = int(rev_match.group(1)) if rev_match else 0
        filed = None
        if m:
            filed = f"{m.group(1)}T00:00:00Z"
        else:
            # No Filed line. The artefact NAME still carries a date, which is
            # evidence from the file itself rather than a guess -- use it and
            # say so. Only when neither exists is the row skipped.
            n = FILENAME_DATE_RE.search(path.name)
            if n:
                filed = f"{n.group(1)}T00:00:00Z"
        if not filed:
            skipped.append((rel, "no '**Filed:** <date>' line and no date in the filename"))
            continue
        sid = ID_RE.search(text)
        program = path.parent.name
        # A submission filed under <lane>/hunt-records/ belongs to <lane>.
        if program == "hunt-records":
            program = path.parent.parent.name
        heading = next((l for l in text.splitlines() if l.startswith("# ")), path.stem)
        class_id, kw = classify(heading + " " + text[:4000], taxonomy)
        # "duplicate" must mean the report WAS closed as a duplicate. A
        # submission that merely discusses duplicate risk is still a live
        # filing -- the loose match labelled the CoinDesk report a dupe.
        closed_dupe = re.search(
            r"closed as (?:a )?duplicate|marked as (?:a )?duplicate|duplicate of #",
            text[:5000],
            re.I,
        )
        outcome = "duplicate" if closed_dupe else "pending"
        # The schema forbids `resolved_at` on a pending record, and it is
        # right to: the filing date is not a resolution. It goes in the
        # evidence string, where it belongs.
        resolved = None if outcome == "pending" else filed
        dated = "filed" if m else "dated from filename"
        records.append(
            {
                "loc": f"{rel}",
                "program": f"filed:{norm_program(program)}",
                "class_id": class_id,
                "keyword": kw,
                "class_inferred": True,
                "final_outcome": outcome,
                "asset": heading.lstrip("# ").strip()[:300],
                "weakness_class": heading.lstrip("# ").strip()[:200],
                "evidence": "submitted %s (%s)%s"
                % (filed[:10], dated, f", id {sid.group(1)}" if sid else ", id not recorded"),
                "resolved_at": resolved,
                "payout_band": None,
                "_date": filed[:10],
                "_rev": rev,
            }
        )
    # FOLD REVISIONS. Octopus has a base, a V2 and a V3 of the SAME report;
    # counted three times it makes one finding look like three and, worse, its
    # class drifts between revisions (the V2 text hits "credential", the base
    # hits "discloses"). The unit of the pattern map is the FINDING, so keep
    # the newest revision per (program, title) and report the rest as folded.
    def title_key(rec: dict) -> str:
        t = rec["asset"].lower()
        t = re.sub(r"\bv\d+\b", "", t)
        t = re.sub(r"[^a-z0-9]+", " ", t).strip()
        return f"{rec['program']}|{t[:60]}"

    kept: dict = {}
    for rec in records:
        key = title_key(rec)
        prev = kept.get(key)
        rank = (rec.get("_date") or "", rec.get("_rev") or 0)
        prev_rank = ((prev.get("_date") or "", prev.get("_rev") or 0) if prev else None)
        if prev is None or rank >= prev_rank:
            if prev is not None:
                skipped.append((prev["loc"], f"revision superseded by {rec['loc']}"))
            kept[key] = rec
        else:
            skipped.append((rec["loc"], f"revision superseded by {prev['loc']}"))
    return list(kept.values()), skipped


# ── source: dupe registry ─────────────────────────────────────────────────
def parse_dupes(taxonomy: list) -> tuple[list, list]:
    records, skipped = [], []
    if not DUPE_REGISTRY.exists():
        return records, skipped
    try:
        data = json.loads(DUPE_REGISTRY.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        skipped.append(("research/dupe-registry.json", f"unreadable: {exc}"))
        return records, skipped
    for i, cls in enumerate(data.get("classes") or []):
        if not isinstance(cls, dict):
            skipped.append((f"dupe-registry[{i}]", "not an object"))
            continue
        cap = (cls.get("capability") or "").strip()
        if not cap:
            skipped.append((f"dupe-registry[{i}]", "no capability text"))
            continue
        # A CWE id is a DECLARATION, and it beats keyword inference. The
        # registry's `class_terms` are dupe-MATCHING terms, not a
        # classification: feeding them in made the CoinDesk entry (CWE-290,
        # plainly an auth bypass) classify as RATE_LIMIT because its terms
        # mention rate-limit headers.
        weakness = str(cls.get("weakness") or "")
        class_id, kw = decide_dupe_class(cap, weakness, taxonomy)
        records.append(
            {
                "loc": f"dupe-registry[{i}]",
                "program": f"dupe:{norm_program(str(cls.get('program') or 'unknown'))}",
                "class_id": class_id,
                "keyword": kw,
                "class_inferred": True,
                "final_outcome": "duplicate",
                "asset": str(cls.get("asset") or "see dupe-registry.json")[:300],
                "weakness_class": cap[:200],
                "evidence": "research/dupe-registry.json capability class",
                "resolved_at": None,
                "payout_band": None,
            }
        )
    return records, skipped


# ── emit ──────────────────────────────────────────────────────────────────
def existing_records(ledger: Path) -> dict:
    """id -> latest record (the ledger is append-only; latest wins)."""
    out = {}
    if not ledger.exists():
        return out
    for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        prev = out.get(rec.get("id"))
        if prev is None or str(rec.get("logged_at", "")) >= str(prev.get("logged_at", "")):
            out[rec["id"]] = rec
    return out


def same_meaning(old: dict, new: dict) -> bool:
    """Does a re-derived row agree with what the ledger already holds?

    Compared on the fields the BACKFILL derives. Everything else (hours,
    impact, operator notes) belongs to a human and is never touched by a
    refresh.
    """
    keys = ("program", "asset", "weakness_class", "class_id", "final_outcome",
            "payout_band", "resolved_at", "evidence_summary")
    return all(str(old.get(k)) == str(new.get(k)) for k in keys)


def to_record(rec: dict) -> dict:
    ns = argparse.Namespace(
        source="backfill",
        program=rec["program"],
        asset=rec["asset"],
        weakness_class=rec["weakness_class"],
        evidence=rec["evidence"],
        pipeline_verdict="n/a",
        operator_decision="submitted" if rec["final_outcome"] in ("pending", "paid", "duplicate") else "n/a",
        final_outcome=rec["final_outcome"],
        payout_band=rec.get("payout_band"),
        resolved_at=rec.get("resolved_at"),
        impact_class="n/a",
        gate_outcome="n/a",
        band_predicted=None,
        hours_spent=None,
        hypotheses_tested=None,
        discriminating_tests=None,
        id=det_id(rec["loc"]),
        class_id=rec["class_id"],
    )
    out = log_outcome.build_record(ns)
    # Provenance of the CLASS, not just the row: an inferred class must be
    # distinguishable from a declared one forever.
    out["class_source"] = "inferred" if rec.get("class_inferred") else "declared"
    out["backfill_source"] = rec["loc"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument(
        "--refresh",
        action="store_true",
        help="append a corrected record (same id) where the re-derived row "
        "differs from what the ledger holds. Never rewrites a line.",
    )
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--file", default=str(LEDGER))
    ap.add_argument(
        "--root",
        default=str(REPO),
        help="repository root to backfill FROM (a fixture needs to point this "
        "somewhere other than the live tree, or the test tests nothing)",
    )
    args = ap.parse_args()

    taxonomy = load_taxonomy()
    if not taxonomy:
        print("refused: taxonomy.yaml is empty or unreadable", file=sys.stderr)
        return 2

    root = Path(args.root)
    global FINDINGS, DUPE_REGISTRY, PLATFORMS
    FINDINGS = root / "findings.md"
    DUPE_REGISTRY = root / "research" / "dupe-registry.json"
    PLATFORMS = root / "platforms"

    ledger = Path(args.file)
    known = existing_records(ledger)

    sources = []
    for name, parser, path in (
        ("findings.md", parse_findings, FINDINGS),
        ("submissions", parse_submissions, PLATFORMS),
        ("dupe-registry", parse_dupes, DUPE_REGISTRY),
    ):
        if not path.exists():
            sources.append((name, None, [], [], "MISSING"))
            continue
        recs, skips = parser(taxonomy)
        sources.append((name, path, recs, skips, "ok"))

    print(f"taxonomy: {len(taxonomy)} classes")
    print(f"ledger  : {ledger} ({len(known)} existing ids)\n")
    header = f"{'source':<16}{'rows':>6}{'new':>6}{'dup':>6}{'skip':>6}  status"
    print(header)
    print("-" * len(header))

    total_new = total_skip = 0
    missing = []
    written = 0
    for name, path, recs, skips, status in sources:
        if status == "MISSING":
            missing.append(name)
            print(f"{name:<16}{'-':>6}{'-':>6}{'-':>6}{'-':>6}  MISSING (not zero -- unknown)")
            continue
        new, dup = [], 0
        for rec in recs:
            rid = det_id(rec["loc"])
            try:
                built = to_record(rec)
            except log_outcome.Rejected as exc:
                skips.append((rec["loc"], f"schema: {exc}"))
                continue
            if rid in known:
                if args.refresh and not same_meaning(known[rid], built):
                    new.append(built)
                    continue
                dup += 1
                continue
            new.append(built)
        # A folded REVISION is correct behaviour, not a problem. Counting it
        # as a skip would make --strict permanently red and train everyone to
        # ignore it.
        folds = [(loc, why) for loc, why in skips if why.startswith("revision superseded")]
        problems = [(loc, why) for loc, why in skips if not why.startswith("revision superseded")]
        print(f"{name:<16}{len(recs):>6}{len(new):>6}{dup:>6}{len(problems):>6}  {status}"
              + (f"  ({len(folds)} revision(s) folded)" if folds else ""))
        total_new += len(new)
        total_skip += len(problems)
        for loc, why in problems:
            print(f"    skip {loc}: {why}")
        for loc, why in folds:
            print(f"    fold {loc}: {why}")
        if args.write:
            for rec in new:
                log_outcome.append_line(ledger, rec)
                written += 1
            known.update({r["id"]: r for r in new})

    print(f"\npipeline.md: NOT PARSED (prose lane blocks, v1). It is not zero rows -- it is")
    print("             a known gap, and it is printed so nobody reads silence as absence.")
    if missing:
        print(f"MISSING SOURCES: {', '.join(missing)} -- reported as UNKNOWN, never as empty.")

    if args.write:
        print(f"\nwrote {written} record(s) to {ledger}")
    else:
        print(f"\nDRY RUN: {total_new} record(s) would be written (use --write)")

    if args.strict and (missing or total_skip):
        print("\nSTRICT: failing because something was missing or skipped", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
