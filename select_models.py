#!/usr/bin/env python3
"""
select_models.py — pick the live models for a role from its priority list.

Deterministic. No LLM: "which providers are currently refusing calls" is a
state question, not a reasoning question.

A model is LIVE if:
  - its provider is not in cooldown (provider_health.py), AND
  - it is not at a known cap (usage_ledger.check_daily_cap)

The role's priority list is walked in order and the first `want` live models
win. Models that are skipped are reported with a reason, so the log can say
WHY the committee was short rather than just that it was.

If fewer than `min_votes` models are live, the caller is expected to park
with INSUFFICIENT CAPACITY rather than dispatch a thin committee.

Usage: select_models.py <models.yaml> <role> <want> [--json <outpath>]
Prints the selected model ids, one per line, on stdout.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import provider_health  # noqa: E402
from usage_ledger import check_daily_cap  # noqa: E402

# Providers that opencode knows natively (their models come from the
# models.dev catalog), so they are available on any machine with a credential.
# Everything else must be declared in the local opencode.json.
BUILTIN_PROVIDERS = {"opencode", "opencode-go", "openrouter", "google"}

CONFIG_CANDIDATES = (
    Path.home() / ".config" / "opencode" / "opencode.json",
    Path.home() / ".config" / "opencode" / "opencode.jsonc",
)


def _local_config() -> dict:
    """The machine's opencode.json, or {} if it cannot be read."""
    for path in CONFIG_CANDIDATES:
        if not path.exists():
            continue
        try:
            import yaml  # json is a subset of yaml; yaml handles json too

            # utf-8-sig: a BOM must not break the read. Windows PowerShell's
            # `Set-Content -Encoding UTF8` writes a BOM, and opencode.json on
            # X is edited that way -- which silently made every
            # config-based check report "not configured".
            data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return {}


def model_is_configured(model_id: str) -> tuple[bool, str]:
    """Is this model actually usable on THIS machine?

    A custom provider (e.g. "opencode-alt", the second OpenCode account)
    only exists where its provider block has been added to opencode.json --
    and a custom provider is not in the models.dev catalog, so its model ids
    must be declared in that block's `models:` map. Selecting a model that
    cannot possibly work wastes a call and a whole retry cycle.
    """
    provider, _, model = model_id.partition("/")
    if provider in BUILTIN_PROVIDERS:
        return True, ""

    config = _local_config()
    block = (config.get("provider") or {}).get(provider)
    if not isinstance(block, dict):
        return False, f"provider '{provider}' not configured on this machine"

    models = block.get("models")
    if isinstance(models, dict) and models:
        if model not in models:
            return False, f"model '{model}' not declared for provider '{provider}'"
    return True, ""



def load_role(models_yaml: Path, role: str) -> dict:
    import yaml

    data = yaml.safe_load(models_yaml.read_text()) or {}
    cfg = data.get(role)
    if not isinstance(cfg, dict):
        raise SystemExit(f"role {role!r} not found in {models_yaml}")
    return cfg


def select(cfg: dict, want: int, exclude_models=None, exclude_providers=None) -> dict:
    candidates = cfg.get("models") or []
    min_votes = int(cfg.get("min_votes", 1))
    exclude_models = set(exclude_models or ())
    exclude_providers = set(exclude_providers or ())

    selected = []
    skipped = []

    for model in candidates:
        if len(selected) >= want:
            break
        provider = provider_health.provider_of(model)

        # The evaluator/challenger pair must be genuinely INDEPENDENT. If both
        # roles pick the same model, "two reviewers" is one reviewer asked
        # twice -- and if they share a provider, one quota event removes both
        # and the matrix can never be built at all. Exclusion is applied
        # BEFORE the liveness checks so the walk continues to the next
        # candidate rather than stopping.
        if model in exclude_models or provider in exclude_providers:
            skipped.append(
                {
                    "model": model,
                    "provider": provider,
                    "reason": "excluded (independence)",
                    "detail": "same model or provider as another role in the pair",
                }
            )
            continue

        configured, why = model_is_configured(model)
        if not configured:
            skipped.append(
                {
                    "model": model,
                    "provider": provider,
                    "reason": "not configured on this machine",
                    "detail": why,
                }
            )
            continue

        if not provider_health.is_healthy(model):
            remaining = provider_health.cooldown_remaining(model)
            skipped.append(
                {
                    "model": model,
                    "provider": provider,
                    "reason": "provider in cooldown",
                    "detail": f"{remaining}s remaining",
                }
            )
            continue

        # Proactive quota check: ask the provider's own usage API whether it
        # is exhausted, so we skip it BEFORE spending a call to find out.
        pre = provider_health.precheck(model)
        if pre.get("exhausted"):
            skipped.append(
                {
                    "model": model,
                    "provider": provider,
                    "reason": "provider quota exhausted (probed)",
                    "detail": pre.get("reason", ""),
                }
            )
            continue

        try:
            under_cap = check_daily_cap(model)
            detail = "" if under_cap else "budget gate refused (see stderr for the reason)"
        except Exception as exc:
            # A gate that THROWS must not become a pass. The old code did
            # `except Exception: under_cap = True`, which turned any bug in the
            # metre into permission to spend.
            under_cap = False
            detail = f"budget gate errored: {type(exc).__name__}: {exc}"
        if not under_cap:
            skipped.append(
                {
                    "model": model,
                    "provider": provider,
                    "reason": "budget gate refused",
                    "detail": detail,
                }
            )
            continue

        selected.append(model)

    return {
        "role": cfg.get("_role", ""),
        "want": want,
        "min_votes": min_votes,
        "selected": selected,
        "skipped": skipped,
        "live_count": len(selected),
        "candidate_count": len(candidates),
    }


def main() -> int:
    # --configured <model>: exit 0 if the model is usable on this machine.
    # The committee's backfill needs the same check the selector uses, or it
    # will dispatch a model whose provider was never configured here.
    # Handled BEFORE the positional parsing, which would otherwise choke on
    # the model id.
    if "--configured" in sys.argv:
        idx = sys.argv.index("--configured")
        if idx + 1 < len(sys.argv):
            ok, why = model_is_configured(sys.argv[idx + 1])
            if not ok:
                print(why, file=sys.stderr)
            sys.exit(0 if ok else 1)

    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2

    models_yaml = Path(sys.argv[1])
    role = sys.argv[2]
    want = int(sys.argv[3])

    json_out = None
    if "--json" in sys.argv:
        idx = sys.argv.index("--json")
        if idx + 1 < len(sys.argv):
            json_out = Path(sys.argv[idx + 1])

    cfg = load_role(models_yaml, role)
    cfg["_role"] = role

    # --exclude-model <id> / --exclude-provider <id> (repeatable): keep a
    # role off a model or provider another role in the same pair already has.
    # Used by the evaluator/challenger pair, where picking the same model
    # twice would make "two independent reviewers" one reviewer asked twice.
    exclude_models = []
    exclude_providers = []
    for flag, sink in (("--exclude-model", exclude_models),
                       ("--exclude-provider", exclude_providers)):
        while flag in sys.argv:
            idx = sys.argv.index(flag)
            if idx + 1 < len(sys.argv):
                sink.append(sys.argv[idx + 1])
                del sys.argv[idx:idx + 2]
            else:
                break

    result = select(cfg, want, exclude_models, exclude_providers)

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(result, indent=2))

    for model in result["selected"]:
        print(model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
