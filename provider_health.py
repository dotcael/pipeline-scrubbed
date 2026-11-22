#!/usr/bin/env python3
"""
provider_health.py — deterministic circuit breaker for model providers.

A state machine, deliberately NOT an LLM. Deciding "is this provider
currently refusing calls" needs no reasoning, and putting a model in that
loop would add latency, cost and non-determinism to a question that is
already exactly answerable. Model judgement is reserved for the security
content; the plumbing stays auditable.

WHAT THIS IS FOR
  Free-tier providers reject calls when their quota is exhausted
  (opencode emits `provider.quota` / HTTP 429 / `FreeUsageLimitError`).
  Without a breaker the pipeline re-probes a known-dead provider on every
  run, burning minutes per call and producing noisy, misleading logs.

HOW IT KEYS
  A "provider" is the model id prefix before "/". So "opencode" and
  "opencode-alt" are DIFFERENT providers with different quotas and
  different cooldowns -- which is exactly why a second OpenCode account
  has to be registered under its own provider id rather than as a key
  swap on the built-in one.

STATE
  tools/pipeline/.state/provider_health.json  (gitignored)

Cooldown durations are policy, not code: they live under `providers:` in
models.yaml, so tuning is a config edit.

CLI
  python3 provider_health.py status
  python3 provider_health.py is_healthy <model-or-provider>
  python3 provider_health.py fail <model> <raw-error-text>
  python3 provider_health.py ok   <model>
  python3 provider_health.py cooldown_remaining <model-or-provider>
"""
import json
import os
import re
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
# Overridable so tests (and a per-machine state dir) do not pollute the real
# breaker state. The selftest was putting fake providers into cooldown in the
# live state file, which then made a real run skip a healthy provider.
STATE_DIR = Path(os.environ.get("PIPELINE_STATE_DIR") or (TOOLS / ".state"))
STATE_FILE = STATE_DIR / "provider_health.json"
MODELS_YAML = TOOLS / "models.yaml"

# Fallback policy when models.yaml has no entry for a provider.
DEFAULT_POLICY = {
    "quota_cooldown": 600,
    "auth_cooldown": 3600,
    "unavailable_cooldown": 3600,
    "timeout_cooldown": 60,
    "server_cooldown": 60,
}

# Patterns that classify a failure. Order matters: most specific first.
PATTERNS = [
    # "model unavailable" / "no route" is a CONFIG problem: the provider or
    # model id is not present on this machine. It will not self-heal, so it
    # needs the operator -- but it must not be mistaken for a quota event.
    ("unavailable", re.compile(r"no-route|model unavailable|no route|model not found|unknown model", re.I)),
    ("quota", re.compile(r"quota|rate.?limit|freeusagelimit|429|too many requests", re.I)),
    ("auth", re.compile(r"unauthoriz|invalid.?api.?key|forbidden|401|403|api key", re.I)),
    ("timeout", re.compile(r"timeout|timed out|etimedout|deadline", re.I)),
    ("server", re.compile(r"50[0-9]|internal server|bad gateway|service unavailable|503", re.I)),
]


def provider_of(model_id: str) -> str:
    """Provider bucket for a model id: "opencode/x" -> "opencode"."""
    return model_id.split("/", 1)[0] if "/" in model_id else model_id


def classify(error_text: str) -> str:
    """Classify a raw error string into a failure class."""
    for name, pattern in PATTERNS:
        if pattern.search(error_text or ""):
            return name
    return "unknown"


def load_policy() -> dict:
    """Per-provider cooldown policy from models.yaml, with defaults merged in."""
    policy = {}
    try:
        import yaml

        data = yaml.safe_load(MODELS_YAML.read_text()) or {}
        for name, cfg in (data.get("providers") or {}).items():
            if isinstance(cfg, dict):
                policy[name] = {**DEFAULT_POLICY, **cfg}
    except Exception:
        pass
    return policy


def cooldown_for(provider: str, kind: str) -> int:
    policy = load_policy().get(provider, DEFAULT_POLICY)
    return int(
        policy.get(
            f"{kind}_cooldown",
            policy.get("quota_cooldown", DEFAULT_POLICY["quota_cooldown"]),
        )
    )


def _read_state() -> dict:
    if not STATE_FILE.exists():
        return {"providers": {}}
    try:
        with open(STATE_FILE) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {"providers": {}}
        data.setdefault("providers", {})
        return data
    except (OSError, json.JSONDecodeError):
        return {"providers": {}}


def _write_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".json.tmp")
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)


def record_failure(model_id: str, error_text: str) -> dict:
    """Record a failure and put the provider into cooldown.

    Returns the state entry, which includes `newly_cooled` so the caller can
    fire a notification on the TRANSITION only -- notifying on every skipped
    call would spam.
    """
    provider = provider_of(model_id)
    kind = classify(error_text)
    seconds = cooldown_for(provider, kind)
    now = int(time.time())

    state = _read_state()
    entry = state["providers"].get(provider, {})
    already_cooling = int(entry.get("cooldown_until", 0)) > now
    until = now + seconds

    # A failure while already cooling extends the cooldown rather than
    # shortening it -- otherwise a probe that fails mid-cooldown would reset
    # the clock and let the pipeline keep hammering.
    if already_cooling:
        until = max(until, int(entry.get("cooldown_until", 0)) + seconds // 2)

    state["providers"][provider] = {
        "cooldown_until": until,
        "cooldown_seconds": seconds,
        "last_error_kind": kind,
        "last_error_at": now,
        "last_error_model": model_id,
        "last_error_excerpt": (error_text or "")[:400],
        "failure_count": int(entry.get("failure_count", 0)) + 1,
        "needs_operator": kind in ("auth", "unavailable"),
    }
    _write_state(state)

    return {
        "provider": provider,
        "kind": kind,
        "cooldown_seconds": seconds,
        "cooldown_until": until,
        "newly_cooled": not already_cooling,
        "needs_operator": kind in ("auth", "unavailable"),
    }


def record_success(model_id: str) -> None:
    """Clear the cooldown for a provider after a successful call."""
    provider = provider_of(model_id)
    state = _read_state()
    entry = state["providers"].get(provider)
    if not entry:
        return
    state["providers"][provider] = {
        **entry,
        "cooldown_until": 0,
        "last_success_at": int(time.time()),
    }
    _write_state(state)


def is_healthy(model_or_provider: str) -> bool:
    """True if the provider is not in cooldown."""
    name = model_or_provider
    if "/" in name:
        name = provider_of(name)
    entry = _read_state()["providers"].get(name)
    if not entry:
        return True
    return int(entry.get("cooldown_until", 0)) <= int(time.time())


def cooldown_remaining(model_or_provider: str) -> int:
    """Seconds of cooldown left (0 if healthy)."""
    name = model_or_provider
    if "/" in name:
        name = provider_of(name)
    entry = _read_state()["providers"].get(name)
    if not entry:
        return 0
    return max(0, int(entry.get("cooldown_until", 0)) - int(time.time()))


def status() -> dict:
    state = _read_state()
    now = int(time.time())
    out = {}
    for provider, entry in state["providers"].items():
        remaining = max(0, int(entry.get("cooldown_until", 0)) - now)
        out[provider] = {
            "healthy": remaining == 0,
            "cooldown_remaining": remaining,
            "last_error_kind": entry.get("last_error_kind"),
            "last_error_at": entry.get("last_error_at"),
            "last_error_model": entry.get("last_error_model"),
            "failure_count": entry.get("failure_count", 0),
            "needs_operator": entry.get("needs_operator", False),
        }
    return out



# ── proactive quota probes ────────────────────────────────────────────────
# Some providers expose a real usage/quota API, so the pipeline can see
# exhaustion COMING instead of discovering it from a failed call.
#
#   openrouter  GET /api/v1/key      -> limit_remaining, usage_daily
#              GET /api/v1/credits  -> total_credits, total_usage
#   beatapi     GET /v1/usage        -> credit_balance, total_tasks, per-key
#   opencode    NO API (confirmed: an unresolved feature request upstream;
#              `opencode stats` is local session cost, not the server's
#              rolling limit) -> reactive detection only.
#
# A probe must never break the pipeline: a network error or an unexpected
# payload means "assume healthy" and let the call itself find out.

PROBE_TTL = int(os.environ.get("PIPELINE_PROBE_TTL", "60"))
# Paid-lane guardrail: park the pipeline when the PREPAID balance drops below
# this. The account has no card on file, so the true ceiling is the balance
# itself -- this floor is what stops a run starting with pennies left and
# then dying mid-committee, which would burn the free seats for nothing.
_DEEPSEEK_FLOOR_DEFAULT = float(os.environ.get("DEEPSEEK_BALANCE_FLOOR", "1.00"))
SECRETS_DIR = Path(
    os.environ.get("OPENCODE_SECRETS_DIR") or (Path.home() / ".secrets" / "opencode")
)


def _key_for(provider: str) -> str | None:
    """Read the provider's API key from the same secret file opencode uses."""
    path = SECRETS_DIR / f"{provider}.key"
    try:
        if path.exists():
            key = path.read_text().strip()
            if key:
                return key
    except OSError:
        pass
    return None


def _ssl_context():
    """An SSL context that trusts the right roots.

    Python's default trust store is not always usable: on this Mac urllib
    failed with CERTIFICATE_VERIFY_FAILED because it does not see the
    system keychain, while curl did. certifi (if installed) is the clean
    fix and keeps the token in-process rather than in a subprocess argv.
    """
    import ssl

    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    # macOS ships a CA bundle curl also uses.
    for candidate in ("/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem"):
        if Path(candidate).exists():
            try:
                return ssl.create_default_context(cafile=candidate)
            except Exception:
                continue
    return None


def _http_json(url: str, key: str, timeout: int = 15):
    """Minimal JSON GET with a bearer token. Returns None on any failure."""
    import urllib.error
    import urllib.request

    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}

    ctx = _ssl_context()
    if ctx is not None:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            pass

    # Fall back to curl: present on macOS and Windows, and it uses the OS
    # trust store. The token ends up in argv, so this path is a fallback
    # rather than the default.
    try:
        import subprocess

        out = subprocess.run(
            [
                "curl", "-sS", "-m", str(timeout),
                "-H", f"Authorization: Bearer {key}",
                "-H", "Accept: application/json",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception:
        pass
    return None


def _probe_openrouter(key: str) -> dict | None:
    payload = _http_json("https://openrouter.ai/api/v1/key", key)
    if not isinstance(payload, dict):
        return None
    data = payload.get("data") or {}
    remaining = data.get("limit_remaining")
    out = {
        "provider": "openrouter",
        "limit": data.get("limit"),
        "limit_remaining": remaining,
        "usage_daily": data.get("usage_daily"),
        "usage_weekly": data.get("usage_weekly"),
        "is_free_tier": data.get("is_free_tier"),
    }
    # Paid balance, if this key has one.
    credits = _http_json("https://openrouter.ai/api/v1/credits", key)
    if isinstance(credits, dict):
        cdata = credits.get("data") or {}
        out["total_credits"] = cdata.get("total_credits")
        out["total_usage"] = cdata.get("total_usage")
    # Exhausted if the request limit is used up. A paid key with no credits
    # AND spend at/over the purchased total is also exhausted.
    if isinstance(remaining, int) and remaining <= 0:
        out["exhausted"] = True
        out["reason"] = f"openrouter request limit exhausted (limit_remaining={remaining})"
    elif (
        isinstance(out.get("total_credits"), (int, float))
        and out["total_credits"] > 0
        and isinstance(out.get("total_usage"), (int, float))
        and out["total_usage"] >= out["total_credits"]
    ):
        out["exhausted"] = True
        out["reason"] = "openrouter credits exhausted"
    else:
        out["exhausted"] = False
    return out


def _probe_beatapi(key: str) -> dict | None:
    payload = _http_json("https://api.beatapi.io/v1/usage", key)
    if not isinstance(payload, dict):
        return None
    data = payload.get("data") or {}
    balance = data.get("credit_balance")
    out = {
        "provider": "beatapi",
        "credit_balance": balance,
        "total_tasks": data.get("total_tasks"),
        "credits_settled": data.get("credits_settled"),
        "by_model": data.get("by_model"),
        "by_api_key": data.get("by_api_key"),
    }
    if isinstance(balance, (int, float)) and balance <= 0:
        out["exhausted"] = True
        out["reason"] = f"beatapi credit balance exhausted ({balance})"
    else:
        out["exhausted"] = False
    return out


def deepseek_decision(payload, floor=_DEEPSEEK_FLOOR_DEFAULT):
    """Pure decision: given a /user/balance payload, is the paid lane usable?

    Split out of the probe ON PURPOSE. The probe needs a network call, so it
    cannot be tested with a known-bad input; this function can. The suite
    feeds it a near-zero balance and requires `exhausted` -- a guardrail that
    has never been shown to fire is not a guardrail.

    Returns (exhausted: bool, reason: str|None, balance: float|None,
    currency: str|None). `balance` is None when the payload carries no
    readable balance record -- that is "cannot tell", which callers must
    treat as healthy, never as broke.
    """
    if not isinstance(payload, dict):
        return (None, None, None, None)

    infos = payload.get("balance_infos") or []
    if not isinstance(infos, list) or not infos:
        return (None, None, None, None)

    # Prefer the USD record. Summing across currencies would add yuan to
    # dollars and produce a number that is wrong in a direction nobody can
    # see, so we take ONE record and report which currency it is in.
    chosen = None
    for info in infos:
        if isinstance(info, dict) and str(info.get("currency", "")).upper() == "USD":
            chosen = info
            break
    if chosen is None:
        chosen = next((i for i in infos if isinstance(i, dict)), None)
    if chosen is None:
        return (None, None, None, None)

    try:
        balance = float(chosen.get("total_balance"))
    except (TypeError, ValueError):
        return (None, None, None, None)

    currency = chosen.get("currency")
    if payload.get("is_available") is False:
        return (True, "deepseek account reports is_available=false", balance, currency)
    if balance < float(floor):
        return (
            True,
            f"deepseek balance {balance:.2f} {currency} below floor {float(floor):.2f}",
            balance,
            currency,
        )
    return (False, None, balance, currency)


def _probe_deepseek(key: str) -> dict | None:
    """Paid lane: the question is "is there money left", not "is quota left".

    /user/balance is free, so this costs nothing and is consulted before
    every run. Without it a zero balance is only discovered by the NEXT
    completion returning 402, which classifies as auth and parks the role --
    correct, but after the committee has already burned its other seats.
    """
    payload = _http_json("https://api.deepseek.com/user/balance", key)
    exhausted, reason, balance, currency = deepseek_decision(payload)
    if exhausted is None and balance is None:
        return None
    out = {
        "provider": "deepseek",
        "is_available": (payload or {}).get("is_available"),
        "total_balance": balance,
        "currency": currency,
        "exhausted": bool(exhausted),
    }
    if reason:
        out["reason"] = reason
    return out


PROBES = {
    "openrouter": _probe_openrouter,
    "beatapi": _probe_beatapi,
    "deepseek": _probe_deepseek,
    # opencode / opencode-alt: no usage API upstream. Reactive only.
    # fcc-*: no usage API behind the proxy. Reactive only.
}


def probe_provider(provider: str, force: bool = False) -> dict | None:
    """Probe a provider's real quota state. Cached for PROBE_TTL seconds.

    Returns None when the provider has no known probe (or the probe failed
    to produce usable data) -- callers must treat that as "assume healthy".
    """
    probe = PROBES.get(provider)
    if probe is None:
        return None

    state = _read_state()
    entry = state["providers"].get(provider, {})
    cached = entry.get("last_probe")
    if not force and isinstance(cached, dict):
        age = int(time.time()) - int(cached.get("at", 0))
        if age < PROBE_TTL:
            return cached.get("result")

    key = _key_for(provider)
    if not key:
        return None
    result = probe(key)
    if result is None:
        return None

    state = _read_state()
    entry = state["providers"].setdefault(provider, {})
    entry["last_probe"] = {"at": int(time.time()), "result": result}
    _write_state(state)
    return result


def precheck(model_id: str) -> dict:
    """Is this model usable RIGHT NOW, per the provider's own quota API?

    Never blocks: if there is no probe, or the probe fails, the answer is
    "healthy" and the call itself becomes the detector.
    """
    provider = provider_of(model_id)
    result = probe_provider(provider)
    if result is None:
        return {"provider": provider, "exhausted": False, "probed": False}
    out = dict(result)
    out["probed"] = True
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "status":
        print(json.dumps(status(), indent=2))
    elif cmd == "is_healthy":
        if not args:
            print("usage: is_healthy <model-or-provider>", file=sys.stderr)
            return 2
        sys.exit(0 if is_healthy(args[0]) else 1)
    elif cmd == "cooldown_remaining":
        if not args:
            print("usage: cooldown_remaining <model-or-provider>", file=sys.stderr)
            return 2
        print(cooldown_remaining(args[0]))
    elif cmd == "fail":
        if len(args) < 2:
            print("usage: fail <model> <raw-error-text>", file=sys.stderr)
            return 2
        # Emitted as shell-parsable key=value lines rather than JSON, so
        # orchestrate.sh can read it without a nested quoting minefield.
        result = record_failure(args[0], args[1])
        for key in ("provider", "kind", "cooldown_seconds", "cooldown_until", "needs_operator"):
            print(f"{key}={result.get(key)}")
        print(f"newly_cooled={result.get('newly_cooled')}")
    elif cmd == "fail_json":
        if len(args) < 2:
            print("usage: fail_json <model> <raw-error-text>", file=sys.stderr)
            return 2
        print(json.dumps(record_failure(args[0], args[1])))
    elif cmd == "precheck":
        if not args:
            print("usage: precheck <model>", file=sys.stderr)
            return 2
        result = precheck(args[0])
        print(json.dumps(result))
        sys.exit(1 if result.get("exhausted") else 0)
    elif cmd == "probe":
        if not args:
            print("usage: probe <provider> [--force]", file=sys.stderr)
            return 2
        force = "--force" in args
        result = probe_provider(args[0], force=force)
        print(json.dumps(result, indent=2) if result else "{}")
    elif cmd == "ok":
        if not args:
            print("usage: ok <model>", file=sys.stderr)
            return 2
        record_success(args[0])
        print("ok")
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
