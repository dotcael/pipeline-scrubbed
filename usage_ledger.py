#!/usr/bin/env python3
"""usage_ledger.py -- the pipeline's spend gate. A real one, now.

WHAT THIS USED TO BE
  A stub. `check_daily_cap()` computed nothing and returned True on every path,
  including the "unknown model" one, and `record_call()` appended a line with
  `calls_today: 0` in it, so the counter could never reach a cap. The pipeline
  read that True as "live" and dispatched. It had a gate in the shape of a gate.

  That is the exact failure AGENTS.md names: an assertion that cannot fail is
  worse than no assertion, because it reports safety it never checked.

WHAT IT IS NOW
  A thin adapter over tools/budget.py, which reads the usage database the
  OpenCode client itself writes. Two independent ceilings, both real:

    1. the per-model DAILY CALL CAP in tools/pipeline/models.yaml (`daily_caps`)
    2. the per-provider MONTHLY USD CEILING in tools/budget-policy.yaml

  Either one refusing parks the lane. And a source that cannot be read is a
  refusal, not a pass: half a month silently measured reads exactly like a
  cheap month.

  `record_call()` survives only so orchestrate.sh keeps working. It writes
  nothing, because the database already has the call: a second hand-kept
  counter would be a cache that drifts, and a drifted counter that gates
  spending is how a bill happens.
"""
from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent          # tools/pipeline
REPO_TOOLS = TOOLS.parent                        # tools
if str(REPO_TOOLS) not in sys.path:
    sys.path.insert(0, str(REPO_TOOLS))

MODELS_YAML = TOOLS / "models.yaml"

try:
    import budget  # noqa: E402
    _BUDGET_ERROR = None
except Exception as exc:                          # pragma: no cover - import guard
    budget = None
    _BUDGET_ERROR = f"{type(exc).__name__}: {exc}"


def _load_daily_caps() -> dict:
    try:
        import yaml
        data = yaml.safe_load(MODELS_YAML.read_text()) or {}
        return data.get("daily_caps") or {}
    except Exception:
        return {}


def _db_paths() -> list[str]:
    """One database per machine. BUDGET_DBS adds the other box when it is mounted."""
    import os
    paths = [str(budget.DEFAULT_DB)] if budget else []
    for extra in os.environ.get("BUDGET_DBS", "").split(os.pathsep):
        if extra:
            paths.append(extra)
    return paths


def check_daily_cap(model_key: str) -> bool:
    """True means LIVE. False means do not call this lane.

    Fails CLOSED. If the metre cannot answer, the answer is no: the caller
    records the model as at-cap and moves to the next lane.
    """
    if budget is None:
        # No metre, no spending. Say it loudly, once, because this now parks
        # rather than quietly allowing.
        print(f"[usage_ledger] budget.py unavailable ({_BUDGET_ERROR}) -> refusing to spend",
              file=sys.stderr)
        return False

    paths = _db_paths()

    # 1. monthly provider ceiling
    pol = budget.load_policy()
    prov = budget.provider_of(model_key)
    entry = pol["providers"].get(prov)
    if entry is None:
        print(f"[usage_ledger] UNPRICED provider {prov} for {model_key} -> refusing "
              f"(add it to tools/budget-policy.yaml)", file=sys.stderr)
        return False
    cap = entry.get("monthly_usd")
    billing = entry.get("billing", "unpriced")
    if billing == "free":
        pass  # no dollar ceiling to check
    elif cap is None:
        print(f"[usage_ledger] {prov} has no monthly_usd ceiling -> refusing", file=sys.stderr)
        return False
    elif cap == 0:
        # cap 0 means PARKED: the lane may not spend at all, before or after a
        # call. Allowing it while spent == 0 would let the first call through
        # and then park the lane with a bill attached.
        print(f"[usage_ledger] {prov} is PARKED at 0 USD -> refusing", file=sys.stderr)
        return False
    else:
        win = budget.month_window()
        data = budget.collect_all(paths, win)
        if not any(d["ok"] for d in data["dbs"]):
            print(f"[usage_ledger] no readable usage database -> refusing to spend on {prov}",
                  file=sys.stderr)
            return False
        spent = float(data["providers"].get(prov, {}).get("cost", 0.0))
        if cap == 0 and spent > 0:
            print(f"[usage_ledger] {prov} is PARKED and {spent:.4f} was spent this month -> refusing",
                  file=sys.stderr)
            return False
        if cap > 0 and spent >= cap:
            print(f"[usage_ledger] {prov} at {spent:.2f} of {cap:.2f} for {win['label']} -> refusing",
                  file=sys.stderr)
            return False

    # 2. daily call cap, measured from the same database
    daily = _load_daily_caps().get(model_key)
    # `is not None`, not truthiness: a cap of 0 means RETIRED, and `if 0:`
    # would skip the check entirely and report a retired lane as live.
    if daily is not None:
        win = budget.day_window()
        calls, readable = budget.count_model_calls(paths, model_key, win)
        if not readable:
            print(f"[usage_ledger] cannot count today's calls for {model_key} -> refusing",
                  file=sys.stderr)
            return False
        if calls >= daily:
            what = "retired by a daily cap of 0" if daily == 0 else f"at {calls}/{daily} calls today"
            print(f"[usage_ledger] {model_key} {what} -> refusing", file=sys.stderr)
            return False

    return True


def record_call(model_key: str, tokens_estimate: int = 0) -> None:
    """No-op by design. The usage database is the ledger.

    Kept only because orchestrate.sh calls it. Writing here would create a
    second counter that can only disagree with the real one.
    """
    return None


if __name__ == "__main__":
    import sys as _sys
    if len(_sys.argv) < 2:
        print("Usage: python3 usage_ledger.py <model_key> | --selftest")
        _sys.exit(2)
    if _sys.argv[1] == "--selftest":
        fails = []

        def check(name, cond, detail=""):
            print(f"  {'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"  {detail}"))
            if not cond:
                fails.append(name)

        # a free lane is allowed
        check("free lane allowed", check_daily_cap("fcc-nim/nvidia_nim/x") is True)
        # an unlisted provider is refused, not assumed free
        check("unpriced provider refused", check_daily_cap("mystery/model") is False)
        # a parked provider is refused even with zero spend
        check("parked provider refused at zero spend", check_daily_cap("zai/glm-5.3") is False)
        # no database at all -> refuse
        saved = budget.DEFAULT_DB
        budget.DEFAULT_DB = Path("/nonexistent/opencode.db")
        try:
            check("missing database refuses", check_daily_cap("deepseek/deepseek-flash") is False)
        finally:
            budget.DEFAULT_DB = saved
        # at the daily cap -> refuse
        saved_caps = _load_daily_caps
        globals()["_load_daily_caps"] = lambda: {"fcc-nim/nvidia_nim/x": 1}
        try:
            budget_obj = budget
            real_count = budget_obj.count_model_calls
            budget_obj.count_model_calls = lambda paths, m, w: (5, True)
            try:
                check("daily cap reached refuses", check_daily_cap("fcc-nim/nvidia_nim/x") is False)
            finally:
                budget_obj.count_model_calls = real_count
        finally:
            globals()["_load_daily_caps"] = saved_caps
        # an uncountable day is a refusal, not a pass
        globals()["_load_daily_caps"] = lambda: {"fcc-nim/nvidia_nim/x": 1}
        try:
            real_count = budget.count_model_calls
            budget.count_model_calls = lambda paths, m, w: (0, False)
            try:
                check("unreadable day refuses", check_daily_cap("fcc-nim/nvidia_nim/x") is False)
            finally:
                budget.count_model_calls = real_count
        finally:
            globals()["_load_daily_caps"] = saved_caps
        print()
        if fails:
            print(f"FAILED: {', '.join(fails)}")
            _sys.exit(1)
        print("all checks passed")
        _sys.exit(0)
    key = _sys.argv[1]
    ok = check_daily_cap(key)
    print(f"{'LIVE' if ok else 'REFUSED'} {key}")
    _sys.exit(0 if ok else 3)
