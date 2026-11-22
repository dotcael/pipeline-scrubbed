#!/usr/bin/env python3
"""pattern_map.py -- what we hit, what we missed, and what we never touched.

THE QUESTION IT ANSWERS
-----------------------
"This programme, this weakness class: did we file something, did we test it and
find nothing, or did we never look?" That grid is the thing the operator asked
for on 2026-10-30, and it is computed -- not remembered.

WHAT IT IS NOT
--------------
IT IS NOT A GATE. It dispatches nothing, parks nothing, reorders nothing, and
writes nothing any gate reads. A novel finding matches no pattern BY
DEFINITION, so a system that let this influence dispatch would be blind to
exactly the findings worth the most. The suite enforces the separation
("pattern_map is never wired into a gate"), the same way it does for
rank_patterns.py.

THE HONESTY RULES, IN CODE
---------------------------
1. A rate over an EMPTY set is not 0% -- it is printed as "no data". A number
   invented from zero rows is an assertion that cannot fail.
2. Rows with no `class_id` are COUNTED AND NAMED as "uncounted". They are the
   pre-taxonomy rows; dropping them silently would make coverage look better
   than it is.
3. Every programme key the alias file cannot resolve is REPORTED, not merged
   by guesswork.
4. Provenance survives: a row that came from backfill says so, and a class
   that was INFERRED from prose is marked with `~` in the table.

USAGE
    python3 pattern_map.py                        # human table
    python3 pattern_map.py --json                 # machine readable
    python3 pattern_map.py --markdown OUT.md      # write the report
    python3 pattern_map.py --program coindesk-data
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parents[1]
LEDGER = REPO / "research" / "outcomes.jsonl"
TAXONOMY = TOOLS / "taxonomy.yaml"
ALIASES = TOOLS / "program-aliases.yaml"

# HIT = we put something in front of a programme (filed, accepted, paid, duped).
# MISS = we tested and the surface held / the target refused us.
# These are the payout-relevant halves of the ledger's outcome vocabulary.
HIT = {"paid", "duplicate", "pending", "informative"}
MISS = {"not_applicable", "not_reproduced", "unreachable", "scope_denied", "no_reply"}


def load_yaml(path: Path) -> dict:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_aliases() -> tuple[dict, set]:
    """Return (lookup: alias -> canonical, known_canonical: set)."""
    data = load_yaml(ALIASES)
    lookup, canonical = {}, set()
    for name, spec in (data.get("programmes") or {}).items():
        canonical.add(name)
        lookup[name] = name
        for alias in (spec or {}).get("aliases") or []:
            lookup[str(alias).lower()] = name
    return lookup, canonical


def load_ledger(path: Path) -> tuple[list, list]:
    """Fold the append-only ledger by id (latest logged_at wins)."""
    by_id, malformed = {}, []
    if not path.exists():
        return [], [f"{path} does not exist"]
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            malformed.append(f"line {n}: not JSON")
            continue
        if not isinstance(rec, dict) or "id" not in rec:
            malformed.append(f"line {n}: no id")
            continue
        prev = by_id.get(rec["id"])
        if prev is None or str(rec.get("logged_at", "")) >= str(prev.get("logged_at", "")):
            by_id[rec["id"]] = rec
    return list(by_id.values()), malformed


def strip_source_prefix(program: str) -> str:
    """`filed:coindesk-data-api` -> `coindesk-data-api`."""
    return program.split(":", 1)[1] if ":" in program else program


def build(ledger_path: Path) -> dict:
    taxonomy = load_yaml(TAXONOMY)
    classes = [c["id"] for c in (taxonomy.get("classes") or []) if isinstance(c, dict)]
    lookup, canonical = load_aliases()
    records, malformed = load_ledger(ledger_path)

    grid = defaultdict(lambda: defaultdict(lambda: {"hit": 0, "miss": 0, "inferred": 0}))
    uncounted, unresolved = [], set()
    for rec in records:
        class_id = rec.get("class_id")
        if not class_id:
            uncounted.append(rec)
            continue
        raw = strip_source_prefix(str(rec.get("program") or "")).lower()
        prog = lookup.get(raw)
        if prog is None:
            unresolved.add(raw)
            prog = raw  # visible under its own name, never merged by guesswork
        outcome = rec.get("final_outcome")
        bucket = "hit" if outcome in HIT else "miss" if outcome in MISS else None
        if bucket is None:
            continue
        grid[prog][class_id][bucket] += 1
        if rec.get("class_source") == "inferred":
            grid[prog][class_id]["inferred"] += 1

    # Columns: only classes that appear somewhere, so the table stays readable;
    # the untouched list is computed against the FULL taxonomy.
    used_classes = [c for c in classes if any(c in row for row in grid.values())]
    programs = sorted(grid)

    untouched = {
        p: [c for c in classes if grid[p].get(c) is None] for p in programs
    }
    never_hit = [
        c
        for c in classes
        if not any(grid[p].get(c, {}).get("hit") for p in programs)
    ]

    return {
        "rows_total": len(records),
        "rows_uncounted": len(uncounted),
        "uncounted_ids": [r.get("id") for r in uncounted],
        "malformed": malformed,
        "programs": programs,
        "classes": classes,
        "classes_used": used_classes,
        "grid": {p: {c: dict(v) for c, v in row.items()} for p, row in grid.items()},
        "untouched": untouched,
        "never_hit_anywhere": never_hit,
        "unresolved_programmes": sorted(unresolved),
        "canonical_known": sorted(canonical),
    }


def render_table(data: dict) -> str:
    if data["rows_total"] == 0:
        return ("NO DATA: the ledger is empty. That is 'we have measured nothing',\n"
                "which is NOT the same as 'we hit 0%'. Fill it (backfill_outcomes.py)\n"
                "before reading anything into this report.")

    used = data["classes_used"]
    if not used:
        return ("NO COUNTABLE DATA: {rows} row(s) in the ledger and none carries a\n"
                "class_id. Nothing can be grouped until they do.").format(
            rows=data["rows_total"]
        )

    out = []
    head = f"{'program':<26}" + "".join(f"{c[:11]:>12}" for c in used)
    out.append(head)
    out.append("-" * len(head))
    for prog in data["programs"]:
        row = f"{prog:<26}"
        for c in used:
            cell = data["grid"].get(prog, {}).get(c)
            if not cell:
                row += f"{'.':>12}"
                continue
            mark = "~" if cell.get("inferred") and not (cell["hit"] or cell["miss"]) else ""
            if cell["hit"] and cell["miss"]:
                txt = f"H{cell['hit']}/M{cell['miss']}{mark}"
            elif cell["hit"]:
                txt = f"hit {cell['hit']}{mark}"
            else:
                txt = f"miss {cell['miss']}{mark}"
            row += f"{txt:>12}"
        out.append(row)

    out.append("")
    out.append("legend: hit N = filed/accepted/duped rows   miss N = tested, surface held")
    out.append("        .  = never touched for this programme   ~ = class inferred from prose")
    out.append("")
    out.append(f"rows counted {data['rows_total'] - data['rows_uncounted']}"
               f" / {data['rows_total']}"
               f"   (uncounted, no class_id: {data['rows_uncounted']})")
    if data["rows_uncounted"]:
        out.append("  uncounted ids: " + ", ".join(str(i) for i in data["uncounted_ids"][:8])
                   + (" …" if data["rows_uncounted"] > 8 else ""))
    if data["malformed"]:
        out.append("  MALFORMED LINES: " + "; ".join(data["malformed"][:5]))
    if data["unresolved_programmes"]:
        out.append("  UNRESOLVED programme keys (reported, not merged): "
                   + ", ".join(data["unresolved_programmes"]))
    out.append("")
    out.append("NEVER HIT ANYWHERE (these are the live options):")
    out.append("  " + (", ".join(data["never_hit_anywhere"]) or "none"))
    out.append("")
    out.append("UNTOUCHED PER PROGRAMME (the gap list):")
    for prog in data["programs"]:
        gap = data["untouched"].get(prog) or []
        out.append(f"  {prog:<26} {len(gap):>2} untouched: {', '.join(gap[:8])}"
                   + (" …" if len(gap) > 8 else ""))
    return "\n".join(out)


def render_markdown(data: dict) -> str:
    body = render_table(data)
    return (
        "# Pattern map — what we hit, what we missed, what we never touched\n\n"
        "> Generated by `tools/pipeline/pattern_map.py`. **Advisory only** — it "
        "gates nothing.\n"
        "> Every cell is derived from `research/outcomes.jsonl`; `~` marks a class "
        "inferred from prose by the backfill.\n\n"
        "```\n" + body + "\n```\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(LEDGER))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--markdown")
    ap.add_argument("--program")
    args = ap.parse_args()

    data = build(Path(args.file))

    if args.program:
        p = args.program.lower()
        if p not in data["grid"]:
            print(f"no rows for programme {p!r}. Known: {', '.join(data['programs']) or '(none)'}",
                  file=sys.stderr)
            return 1
        data = dict(data)
        data["grid"] = {p: data["grid"][p]}
        data["programs"] = [p]

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(render_table(data))

    if args.markdown:
        Path(args.markdown).write_text(render_markdown(data), encoding="utf-8")
        print(f"\nwrote {args.markdown}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
