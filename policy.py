#!/usr/bin/env python3
"""
policy.py — engagement policy gate (Stage 0).

Program eligibility is enforced OUTSIDE the models. A model must never be the
thing that decides whether an engagement may be touched; that is a rule
question with a rule answer, stored in targets.yaml and checked here before
any stage runs.

`targets.yaml` was documentation for a long time — the
`huntr_blind_trust: automation: forbidden` rule existed only as a comment that
no executable code read. This module is the enforcement.

Resolution
  The operator passes free-text targets ("A&F setDefaultAddress BOLA"), so a
  program is resolved by ALIAS MATCH against targets.yaml. Each program block
  may declare aliases; the program key itself is always an implicit alias with
  underscores widened to spaces. No match falls through to the `default`
  block, whose `policy_status` is `unconfirmed` — allowed, because every stage
  here is passive/model-only and the operator holds the live-testing gate, but
  recorded as unconfirmed in the evidence packet so it is visible later.

Refusal is hard
  `automation: forbidden`, `policy_status: forbidden/suspended/expired`, an
  `uncertain` policy, or an engaged kill switch stops the stage. It does not
  fall back to another model, another stage, or a queue.

Kill switch
  A file in .state/. `KILLSWITCH` blocks every engagement;
  `KILLSWITCH-<program>` blocks one. It stops queued work too (drain.py
  checks the same files).

CLI
  policy.py resolve <target>          # print the resolved policy as JSON
  policy.py decision <target>         # print JSON; exit 0 permitted / 1 refused
  policy.py status                    # every program's resolved state
"""
import json
import sys
from pathlib import Path

import yaml

TOOLS = Path(__file__).resolve().parent
TARGETS = TOOLS / "targets.yaml"
STATE_DIR = TOOLS / ".state"

REFUSAL_STATES = {"forbidden", "suspended", "expired", "uncertain"}


def load() -> dict:
    # utf-8-sig: Windows PowerShell's Set-Content -Encoding UTF8 writes a BOM,
    # and json/yaml readers reject it.
    return yaml.safe_load(TARGETS.read_text(encoding="utf-8-sig")) or {}


def resolve(target: str, cfg: dict | None = None) -> dict:
    cfg = cfg if cfg is not None else load()
    t = (target or "").lower()
    default = cfg.get("default") or {}
    chosen, key = default, "default"

    for name, block in cfg.items():
        if name == "default" or not isinstance(block, dict):
            continue
        aliases = {name.lower().replace("_", " ")}
        for a in block.get("aliases") or []:
            aliases.add(str(a).lower())
        if any(a and a in t for a in aliases):
            chosen, key = block, name
            break

    return {
        "program": key,
        "policy_status": chosen.get("policy_status", "unconfirmed"),
        "automation": chosen.get("automation", "allowed"),
        "live_touch": chosen.get("live_touch", "permitted"),
        "policy_source": chosen.get("policy_source", "default block (unlisted program)"),
        "verified": chosen.get("verified", ""),
        "aliases": sorted(
            {name.lower().replace("_", " ") for name, block in cfg.items()
             if name != "default" and isinstance(block, dict)}
        ) if key == "default" else [
            str(a) for a in (chosen.get("aliases") or [])
        ] + [key.replace("_", " ")],
    }


def kill_switch(target: str = "", program: str = "") -> str | None:
    """Return the engaged kill switch description, or None."""
    if (STATE_DIR / "KILLSWITCH").exists():
        return "global kill switch engaged"
    if program and (STATE_DIR / f"KILLSWITCH-{program}").exists():
        return f"kill switch engaged for {program}"
    return None


def decision(target: str, cfg: dict | None = None) -> dict:
    p = resolve(target, cfg)
    ks = kill_switch(target, p["program"])
    if ks:
        p.update({"permitted": False, "reason": ks})
    elif p["automation"] == "forbidden":
        p.update({
            "permitted": False,
            "reason": (f"program '{p['program']}' forbids agent automation "
                       f"(policy_status={p['policy_status']})"),
        })
    elif p["policy_status"] in REFUSAL_STATES:
        p.update({
            "permitted": False,
            "reason": (f"program '{p['program']}' policy_status="
                       f"'{p['policy_status']}' — operator must resolve it"),
        })
    else:
        p.update({"permitted": True, "reason": ""})
    return p


def status() -> dict:
    cfg = load()
    programs = {}
    for name, block in cfg.items():
        if name == "default" or not isinstance(block, dict):
            continue
        probe = resolve(name, cfg)
        d = decision(name, cfg)
        programs[name] = {
            "policy_status": probe["policy_status"],
            "automation": probe["automation"],
            "live_touch": probe["live_touch"],
            "permitted": d["permitted"],
            "reason": d["reason"],
        }
    return {
        "default": resolve("", cfg),
        "programs": programs,
        "kill_switch": kill_switch(),
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "resolve":
        if not args:
            print("usage: resolve <target>", file=sys.stderr)
            return 2
        print(json.dumps(resolve(" ".join(args))))
    elif cmd == "decision":
        if not args:
            print("usage: decision <target>", file=sys.stderr)
            return 2
        d = decision(" ".join(args))
        print(json.dumps(d))
        sys.exit(0 if d["permitted"] else 1)
    elif cmd == "status":
        print(json.dumps(status(), indent=2))
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
