#!/usr/bin/env python3
"""cost_estimate.py -- what this run will cost, BEFORE it runs.

OPERATOR REQUIREMENT (2026-10-30): "always lmk how much it'll cost me before I
run it." A number printed after the fact is a receipt; this is a quote.

WHAT IT DOES
  Reads the roster for a stage, drops the models that cannot be billed (free
  lanes), and prices the rest against the DeepSeek price table with the
  CURRENT peak/off-peak rate. Then it compares the quote to the prepaid
  balance and to today's remaining daily cap.

WHAT IT DOES NOT DO
  It does not call a model, and it does not decide anything. It cannot block a
  run: `check_daily_cap` and the balance probe already gate spending, and
  duplicating a gate in a second place is how the two drift apart.

THE NUMBER IS AN ESTIMATE, AND SAYS SO
  Token counts are MEASURED constants (evidence packets run ~3k in / ~1.5k
  out), not a guess per prompt. Peak/off-peak is computed from the clock at
  the moment of asking, because the same call costs double inside the peak
  window.

USAGE
  python3 cost_estimate.py --stage hypothesis --calls 3
  python3 cost_estimate.py --stage reporter            # calls defaults to 1
  python3 cost_estimate.py --stage hypothesis --json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parents[1]

# Measured, not guessed: the last packet's prompt was 1,012 bytes (~300
# tokens) but opencode adds a system prompt and an agent loop, and DeepSeek's
# thinking mode is on by default. 3k in / 1.5k out is the working bucket.
IN_TOKENS = 3000
OUT_TOKENS = 1500

# USD per 1M tokens. SOURCE: https://api-docs.deepseek.com/quick_start/pricing
# read 2026-10-30. Peak = weekdays 01:00-04:00 and 06:00-10:00 UTC; everything
# else (including both weekend days) is off-peak at half price.
PRICES = {
    "deepseek-flash": {
        "off": {"in": 0.15, "out": 0.60},
        "peak": {"in": 0.30, "out": 1.20},
    },
    "deepseek-v4-pro": {
        "off": {"in": 0.66, "out": 1.98},
        "peak": {"in": 1.32, "out": 3.96},
    },
}


def is_peak(now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if now.weekday() >= 5:  # Saturday/Sunday are off-peak all day
        return False
    hour = now.hour
    return (1 <= hour < 4) or (6 <= hour < 10)


def roster(stage: str) -> list:
    import yaml

    data = yaml.safe_load((TOOLS / "models.yaml").read_text(encoding="utf-8")) or {}
    cfg = data.get(stage) or {}
    return list(cfg.get("models") or [])


def selected(stage: str, want: int | None) -> list:
    """What the selector would pick right now (availability included)."""
    import subprocess

    n = want or 1
    try:
        out = subprocess.run(
            [sys.executable, str(TOOLS / "select_models.py"), str(TOOLS / "models.yaml"), stage, str(n)],
            capture_output=True, text=True, timeout=90, check=True,
        )
        picked = [m for m in out.stdout.split("\n") if m.strip()]
        if picked:
            return picked
    except Exception:
        pass
    return roster(stage)[:n]


def balance() -> tuple[float | None, float | None]:
    """(total_balance, floor) from the free balance endpoint, or (None, None)."""
    sys.path.insert(0, str(TOOLS))
    try:
        import provider_health as ph

        probe = ph.probe_provider("deepseek")
        if probe and isinstance(probe.get("total_balance"), (int, float)):
            return float(probe["total_balance"]), ph._DEEPSEEK_FLOOR_DEFAULT
    except Exception:
        pass
    return None, None


def daily_usage(model: str) -> tuple[int | None, int | None]:
    """(calls today, daily cap). None means UNKNOWN -- never 0 by default.

    A fabricated zero would read as "nothing spent today", which is exactly the
    kind of comfortable number this project keeps having to retract.

    Read from the usage database, not from the old
    ~/.config/opencode/usage/ledger.jsonl: that file is no longer written (see
    usage_ledger.record_call) and reading a file nobody updates would report
    "0 calls today" forever, which is the comfortable number again.
    """
    try:
        import yaml

        caps = (yaml.safe_load((TOOLS / "models.yaml").read_text(encoding="utf-8")) or {}).get(
            "daily_caps"
        ) or {}
        cap = caps.get(model)
        sys.path.insert(0, str(REPO / "tools"))
        import budget  # noqa: PLC0415
        calls, readable = budget.count_model_calls(
            [str(budget.DEFAULT_DB)], model, budget.day_window()
        )
        return (calls if readable else None), cap
    except Exception:
        return None, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", required=True)
    ap.add_argument("--calls", type=int, default=None, help="how many model calls this stage makes")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    models = selected(args.stage, args.calls)
    calls = args.calls or 1
    peak = is_peak()
    band = "peak" if peak else "off-peak"   # for humans
    rate_key = "peak" if peak else "off"    # for the price table

    planned = []
    for i, model in enumerate(models):
        provider, _, name = model.partition("/")
        price = PRICES.get(name)
        billable = price is not None
        per_call = (
            (IN_TOKENS * price[rate_key]["in"] + OUT_TOKENS * price[rate_key]["out"]) / 1_000_000
            if billable
            else 0.0
        )
        planned.append(
            {
                "model": model,
                "provider": provider,
                "billable": billable,
                "per_call_usd": round(per_call, 6),
                "calls": 1,
            }
        )

    # A committee re-uses one model per seat; a single stage calls its first.
    extra = max(0, calls - len(planned))
    if extra and planned:
        # Extra calls land on the first billable model if there is one,
        # otherwise on the first model (and therefore cost nothing).
        target = next((p for p in planned if p["billable"]), planned[0])
        target["calls"] += extra

    total = sum(p["per_call_usd"] * p["calls"] for p in planned)
    bal, floor = balance()
    today = {}
    for p in planned:
        if p["billable"]:
            used, cap = daily_usage(p["model"])
            today[p["model"]] = {"calls_today": used, "daily_cap": cap}

    out = {
        "stage": args.stage,
        "rate_window": band,
        "utc_now": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "calls": calls,
        "plan": planned,
        "estimated_usd": round(total, 5),
        "balance_usd": bal,
        "balance_floor_usd": floor,
        "daily_usage": today,
        "token_bucket": {"in": IN_TOKENS, "out": OUT_TOKENS},
        "price_source": "https://api-docs.deepseek.com/quick_start/pricing (read 2026-10-30)",
    }

    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    free = [p["model"] for p in planned if not p["billable"]]
    paid = [p for p in planned if p["billable"]]
    print(f"COST ESTIMATE — stage '{args.stage}', {calls} call(s), {band} rate"
          f" ({out['utc_now']})")
    if free:
        print(f"  free  : {', '.join(free)}")
    if paid:
        for p in paid:
            print(f"  PAID  : {p['model']} — {p['calls']} × ${p['per_call_usd']:.5f}"
                  f" = ${p['per_call_usd'] * p['calls']:.5f}")
    print(f"  TOTAL : ${total:.5f}" + ("  (nothing is billed)" if total == 0 else ""))
    if bal is not None:
        print(f"  balance: ${bal:.2f} prepaid, parks below ${floor:.2f}")
    for model, u in today.items():
        used = "unknown" if u["calls_today"] is None else u["calls_today"]
        print(f"  {model}: {used} call(s) today, cap {u['daily_cap'] or 'none'}")
    print(f"  prices: {out['price_source']}")
    print("  (estimate; the packet records what was actually spent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
