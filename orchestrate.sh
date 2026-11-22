#!/usr/bin/env bash
# orchestrate.sh — Bug-bounty pipeline orchestrator (runs on Windows X)
#
# Routing is a deterministic state machine, not a model judgement:
#   models.yaml gives each role a PRIORITY LIST of models.
#   select_models.py walks it and takes the first N LIVE models, where live
#   means "provider not in cooldown" AND "not at a known cap".
#   provider_health.py is the circuit breaker: a provider that returns a
#   quota rejection is put in cooldown and skipped on later runs.
#
# Three distinct park reasons, because they mean different things to the
# operator:
#   INSUFFICIENT CAPACITY  - fewer than min_votes live models; nothing ran.
#                             Actionable: quota, accounts, providers.
#   INSUFFICIENT COMMITTEE - the committee ran, members failed to answer.
#   COMMITTEE SPLIT        - the committee ran and disagreed. Not a failure.

set -euo pipefail

# ── paths derived from this script's location ───────────────────────────────
# NOT hardcoded: this script is meant to run on the Windows gaming PC, where
# <home>/... does not exist.
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$TOOLS/../.." && pwd)"
MODELS="$TOOLS/models.yaml"
LEDGER="$TOOLS/usage_ledger.py"
HEALTH="$TOOLS/provider_health.py"
SELECTOR="$TOOLS/select_models.py"
EXTRACT="$TOOLS/extract_text.py"
NOTIFY="$TOOLS/notify.sh"
POLICY="$TOOLS/policy.py"
DEDUPE_GATE="$TOOLS/dedupe_gate.py"
QUEUE_DIR="$TOOLS/queue"
STATE_DIR="$TOOLS/.state"
EVIDENCE_DIR="$TOOLS/evidence"
# The shared outcomes ledger. Read ONLY by rank_patterns.py, and only to
# populate the advisory `historical_signal` field in the evidence packet.
OUTCOMES_FILE="$REPO/research/outcomes.jsonl"

mkdir -p "$QUEUE_DIR/pending" "$QUEUE_DIR/in_progress" "$QUEUE_DIR/completed"
mkdir -p "$STATE_DIR"


# ── helpers ───────────────────────────────────────────────────────────────
log() { echo "[$(date +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

# Locate a working python. Shared with selftest.sh via pyenv.sh -- the
# interpreter name cannot be trusted (on Windows the PATH `python3` is a
# Microsoft Store stub), and duplicating that logic in two files is the same
# drift risk as any other copy.
# shellcheck source=pyenv.sh
source "$TOOLS/pyenv.sh"
log "python: ${PY[*]}"

STAGE="${1:-}"
TARGET="${2:-}"
PROMPT="${3:-}"

# Hard ceiling on ONE model call. 300s is ~4x the slowest healthy call
# measured (deepseek ~5s, gemini-lite ~2s); anything beyond it is a hang, and
# a hang must not become the pipeline's total runtime.
MODEL_TIMEOUT="${PIPELINE_MODEL_TIMEOUT:-300}"

# ── notification: ONE entry point, every failure path calls it ────────────
notify() {
  local priority="$1" title="$2" body="$3"
  # Never let a notification problem break the pipeline.
  bash "$NOTIFY" "$priority" "$title" "$body" >/dev/null 2>&1 || true
}

# ── crash handler ─────────────────────────────────────────────────────────
_CRASH_GUARD=0
on_crash() {
  local rc="$1" line="$2"
  [[ "$_CRASH_GUARD" -eq 1 ]] && return 0
  _CRASH_GUARD=1
  log "💥 pipeline crash (rc=$rc) at line $line"
  notify 5 "PIPELINE CRASH: ${STAGE:-?}/${TARGET:-?}" \
    "orchestrate.sh exited rc=$rc at line $line. See the pipeline log."
}
trap 'on_crash $? $LINENO' ERR
trap 'on_crash 130 $LINENO' INT TERM

# ── provider health (circuit breaker) ─────────────────────────────────────
provider_healthy() {
  "${PY[@]}" "$HEALTH" is_healthy "$1" >/dev/null 2>&1
}

# Is this model usable on THIS machine (provider configured, model declared)?
model_configured() {
  "${PY[@]}" "$SELECTOR" "$MODELS" --configured "$1" >/dev/null 2>&1
}

# Does the provider's OWN usage API say it is exhausted? This is a proactive
# check: we skip the provider instead of spending a call to discover it.
# Providers with no usage API (opencode) report healthy and rely on the
# reactive breaker.
provider_exhausted() {
  ! "${PY[@]}" "$HEALTH" precheck "$1" >/dev/null 2>&1
}

cooldown_remaining() {
  "${PY[@]}" "$HEALTH" cooldown_remaining "$1" 2>/dev/null || echo 0
}

# Record a provider failure and put that provider into cooldown.
# Fires a notification only on the TRANSITION into cooldown, so a provider
# that flaps cannot spam the phone.
record_provider_failure() {
  local model="$1" raw="$2"
  # One python call, emitting shell-parsable key=value lines. Parsing the
  # breaker\'s JSON with four separate one-liners is how the previous version
  # ended up with a typo\'d variable name that killed the run under set -u.
  local parsed
  parsed=$("${PY[@]}" "$HEALTH" fail "$model" "$raw" 2>/dev/null) || return 0

  # provider_health.py emits shell-parsable key=value lines for exactly this
  # reason: no JSON re-parsing in bash, no nested quoting.
  local kind="" entered_cooldown="" provider="" secs=""
  local key value
  while IFS='=' read -r key value; do
    case "$key" in
      kind)             kind="$value" ;;
      newly_cooled)     entered_cooldown="$value" ;;
      provider)         provider="$value" ;;
      cooldown_seconds) secs="$value" ;;
    esac
  done <<< "$parsed"

  log "🔌 provider $provider in cooldown ($kind, ${secs}s) after failure of $model"
  # Notify only on the TRANSITION into cooldown. A provider that flaps
  # in and out must not spam the phone.
  if [[ "$entered_cooldown" == "True" ]]; then
    if [[ "$kind" == "auth" ]]; then
      notify 5 "PROVIDER AUTH FAILED: $provider" \
        "Model $model failed with an auth error. The key for provider '$provider' needs operator attention. Cooldown ${secs}s."
    else
      notify 3 "PROVIDER IN COOLDOWN: $provider" \
        "Model $model hit a $kind rejection. Provider '$provider' skipped for ${secs}s. Detail: ${raw:0:200}"
    fi
  fi
}

record_provider_success() {
  "${PY[@]}" "$HEALTH" ok "$1" >/dev/null 2>&1 || true
}

# ── durable evidence packet ──────────────────────────────────────────────
# A hypothesis run must leave a versioned record: prompt, per-model output,
# scores, verdict, and the policy state it ran under. Without this, "why did
# the committee promote this?" is unanswerable later, and the evidence trail
# the audit convention depends on evaporates.
# ── advisory historical signal (NEVER a gate) ─────────────────────────────
# How this (program, weakness_class) has resolved historically, for the
# OPERATOR to read when deciding whether to act on a promoted finding.
#
# This is the only place rank_patterns.py is ever called, and what it returns
# goes into the packet and nowhere else. It must never reach dedupe_gate.py,
# policy.py, select_models.py or committee_run -- a novel finding matches no
# historical pattern by definition, so wiring this into dispatch would blind
# the pipeline to exactly the findings worth the most. The suite enforces the
# separation (`rank_patterns is never wired into a gate`).
#
# BEST-EFFORT BY CONSTRUCTION: a missing ledger, an unreadable ledger, or a
# broken ranker must never affect the packet, the verdict, or the run.
hypothesis_weakness() {
  local recs="${HYPOTHESIS_RECORDS:-}"
  [[ -n "$recs" && -f "$recs" ]] || return 0
  "${PY[@]}" -c "
import sys
sys.path.insert(0, sys.argv[1])
import records

for n, raw in enumerate(open(sys.argv[2], encoding='utf-8'), 1):
    line = raw.strip()
    if not line or line.startswith('#'):
        continue
    try:
        rec = records.parse_record(line, n)
    except Exception:
        continue
    if rec.kind == records.HYPOTHESIS and rec.weakness:
        print(rec.weakness)
        break
" "$TOOLS" "$recs" 2>/dev/null || true
}

territory_block() {
  # Territory from this repo's own history, prepended to a hypothesis prompt.
  #
  # IT IS CONTEXT, NOT A CONSTRAINT. The block says which classes this
  # programme has already filed and which it has never touched. It does NOT
  # filter, rank or suppress a hypothesis -- a genuinely novel finding matches
  # no historical pattern by definition, and a gate built on history would be
  # blind to exactly the findings worth the most. The prompt says so in words,
  # so a model cannot read the list as a prohibition.
  #
  # Silently no-ops when the map is unavailable: a missing map must not stop a
  # run, and it must not be dressed up as "no history either".
  local program="${POLICY_PROGRAM:-}"
  [[ -n "$program" && -f "$TOOLS/pattern_map.py" ]] || return 0
  "${PY[@]}" - "$TOOLS" "$OUTCOMES_FILE" "$program" <<'TERRPY' 2>/dev/null || true
import json, subprocess, sys

tools, ledger, program = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    out = subprocess.run(
        [sys.executable, f"{tools}/pattern_map.py", "--file", ledger, "--json"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    data = json.loads(out.stdout)
except Exception:
    sys.exit(0)               # no map -> no block. Never invent one.

key = program.lower().replace(" ", "-")
row = data.get("grid", {}).get(key)
if not row:
    print()
    sys.exit(0)

filed, held = [], []
for cls, cell in sorted(row.items()):
    if cell.get("hit"):
        filed.append(f"{cls}({cell['hit']})")
    if cell.get("miss"):
        held.append(f"{cls}({cell['miss']})")

untouched = data.get("untouched", {}).get(key, [])
print()
print("TERRITORY from this repository's own history -- context, NOT a constraint:")
if filed:
    print("  this programme has ALREADY had a report filed: " + ", ".join(filed))
if held:
    print("  tested here and the surface HELD (do not re-propose without new evidence): " + ", ".join(held))
if untouched:
    print("  never attempted on this programme: " + ", ".join(untouched[:12]))
print("  NOVELTY OUTRANKS HISTORY. If the evidence points at a class listed as")
print("  already filed, say what is NEW about this instance (different asset,")
print("  different boundary, different consequence) instead of switching class")
print("  just to look untried.")
TERRPY
}

historical_signal_json() { # -> prints one JSON object; prints nothing on failure
  local program="${POLICY_PROGRAM:-}" weakness=""
  [[ -n "$program" ]] || return 0
  weakness="$(hypothesis_weakness || true)"

  "${PY[@]}" - "$TOOLS" "$OUTCOMES_FILE" "$program" "$weakness" <<'SIGPY' 2>/dev/null || true
import json, subprocess, sys

tools, ledger, program, weakness = sys.argv[1:]

cmd = [sys.executable, f"{tools}/rank_patterns.py", "--file", ledger,
       "--json", "--program", program]

try:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
    groups = json.loads(out.stdout).get("groups", {})
except Exception:
    sys.exit(0)          # ranking unavailable -> omit the field, do not invent one

# EXACT pattern match only. A program may have history for a DIFFERENT
# weakness class, and attributing that history to this one would be a lie
# that reads like evidence. When there is no history for the exact pattern,
# the other weakness classes that DO have history are named, so the operator
# can see "no history here, but history there" without the report borrowing
# a number it does not own.
#
# The weakness filter is deliberately NOT passed to the ranker: filtering
# there would hide the sibling classes this block is trying to name.
key = f"{program}/{weakness}" if weakness else None
group = groups.get(key) if key else None

if group is None:
    # EXACT pattern match only. A program may have history for a DIFFERENT
    # weakness class, and attributing that history to this one would be a lie
    # that reads like evidence. When there is no history for the exact
    # pattern, the other weakness classes that DO have history are named, so
    # the operator can see "no history here, but history there" without the
    # report borrowing a number it does not own.
    others = sorted({g["weakness_class"] for g in groups.values()})
    print(json.dumps({
        "program": program,
        "weakness_class": weakness or None,
        "confidence": "insufficient data",
        "agreement_rate": None,
        "outcome_breakdown": {},
        "history_exists_for_other_weakness_classes": others or None,
        "note": "no history for this exact (program, weakness_class) pattern",
    }))
else:
    print(json.dumps({
        "program": group["program"],
        "weakness_class": group["weakness_class"],
        "confidence": group["confidence"],
        "agreement_rate": group["agreement"]["rate"],
        "outcome_breakdown": group["outcome_breakdown"],
    }))
SIGPY
}

write_evidence_packet() {
  local packet_dir
  packet_dir="$EVIDENCE_DIR/$(date +%Y-%m-%d)/${STAGE}-$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-40)-$(date +%s)"
  mkdir -p "$packet_dir" 2>/dev/null || return 0
  # Publish the packet path so a later stage can add to THIS packet (the
  # adversarial matrix lands here after the severity committee has voted).
  printf '%s' "$packet_dir" > "$STATE_DIR/last_packet_dir" 2>/dev/null || true

  local prompt_file="$packet_dir/prompt.txt"
  printf '%s' "${PROMPT:-}" > "$prompt_file" 2>/dev/null || true

  # Policy state this run operated under — provenance for everything else.
  cp "$POLICY_JSON" "$packet_dir/policy.json" 2>/dev/null || true

  local verdict="$1"
  local basis="$2" votes="$3" total="$4"
  local summary_file="${5:-}"

  # The committee's severity detail -- each member's vector, the CALCULATED
  # score, the band, and whether that band was calculated or estimated -- is
  # part of the deliverable, not a log line. A payout claim is checked against
  # exactly this, so the packet must stand alone without the pipeline log.
  if [[ -n "$summary_file" && -f "$summary_file" ]]; then
    cp "$summary_file" "$packet_dir/severity.json" 2>/dev/null || true
  fi

  # The function\'s stdin IS the per-model records. Persist them FIRST: this
  # file is the durable raw copy, and parsing a file (rather than stdin)
  # leaves the heredoc free to carry the script. `python - <<EOF` would make
  # the heredoc both the program and stdin, and the records would vanish.
  cat > "$packet_dir/results.tsv" 2>/dev/null || true

  # Advisory historical signal for this (program, weakness_class). Written
  # next to the packet so it is auditable, and included in packet.json so
  # the operator sees it without chasing files.
  #
  # BEST-EFFORT: if the ranker cannot run, the field is OMITTED rather than
  # filled with a placeholder. "We looked and there is nothing" and "we could
  # not look" are different claims, and only the ranker knows which one is
  # true.
  local hs_json
  hs_json="$(historical_signal_json || true)"
  if [[ -n "$hs_json" ]]; then
    printf '%s' "$hs_json" > "$packet_dir/historical_signal.json" 2>/dev/null || true
  else
    log "  historical signal unavailable (advisory field omitted)"
  fi

  "${PY[@]}" - "$packet_dir" "$verdict" "$basis" "$votes" "$total" <<'EVDPY' 2>/dev/null || true
import json, sys, hashlib
from pathlib import Path

packet_dir, verdict, basis, votes, total = sys.argv[1:6]
p = Path(packet_dir)

results = []
tsv = p / "results.tsv"
for line in tsv.read_text().splitlines():
    if "\t" not in line:
        continue
    model, text = line.split("\t", 1)
    results.append({"model": model, "output": text[:4000]})

prompt_path = p / "prompt.txt"
prompt = prompt_path.read_text() if prompt_path.exists() else ""

packet = {
    "verdict": verdict,
    "basis": basis,
    "votes": votes,
    "total_members": total,
    "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
    "results": results,
}

# Advisory only: how this (program, weakness_class) has historically
# resolved. It informs the operator's decision; it never influenced the
# verdict above, and nothing downstream of this file reads it back.
hist_path = p / "historical_signal.json"
if hist_path.exists():
    try:
        packet["historical_signal"] = json.loads(hist_path.read_text())
    except Exception:
        packet["historical_signal"] = {"error": "historical_signal.json unreadable"}

# Severity detail: per-member vector, calculated score, band, and whether the
# band was CALCULATED from a vector or ESTIMATED from a bare score. Absent for
# stages that do not run a committee.
sev_path = p / "severity.json"
if sev_path.exists():
    try:
        packet["severity"] = json.loads(sev_path.read_text())
    except Exception:
        packet["severity"] = {"error": "severity.json unreadable"}

(p / "packet.json").write_text(json.dumps(packet, indent=2))
EVDPY
  log "  evidence packet: $packet_dir"
}

# ── record a call after an opencode run ───────────────────────────────────
record_call() {
  local model="$1"
  "${PY[@]}" -c "
import sys
sys.path.insert(0, '$TOOLS')
from usage_ledger import record_call
record_call('$model')
" 2>/dev/null || true
}

# ── model selection: priority walk ────────────────────────────────────────
# select_models <role> <want> -> writes $STATE_DIR/selection_<role>.json
# and echoes the selected model ids, one per line.
select_models() {
  local role="$1" want="$2"; shift 2
  # Extra args are forwarded (e.g. --exclude-model / --exclude-provider), so
  # the state file still records exactly what was selected.
  "${PY[@]}" "$SELECTOR" "$MODELS" "$role" "$want" --json "$STATE_DIR/selection_$role.json" "$@"
}

model_with_timeout() {
  # run one model call with a HARD ceiling.  usage:
  #   model_with_timeout <seconds> <model> <prompt>   -> stdout, exit code
  #
  # WHY THIS EXISTS (measured 2026-10-30): some free upstreams behind the FCC
  # proxy return 200-with-no-content or never return at all -- groq
  # gpt-oss-120b was still silent after ten minutes through `opencode run` on
  # X. `opencode run` has no client timeout of its own, so ONE hanging seat
  # blocks the whole pipeline indefinitely, inside a loop that was only
  # designed for fast failures. A hang is not a slow success: it is a failed
  # call, and it must cost seconds and be classified (timeout -> cooldown ->
  # next lane), exactly like a 429.
  #
  # `timeout(1)` is not available on stock macOS or in Git Bash, so the
  # watchdog is built out of kill(1) and a poll loop.
  local limit="$1" model="$2" prompt="$3"
  local out="$STATE_DIR/model_call.$$.out"
  : > "$out"
  opencode run -m "$model" --format json -- "$prompt" > "$out" 2>&1 &
  local pid=$! waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited >= limit )); then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      cat "$out" 2>/dev/null || true
      rm -f "$out" 2>/dev/null || true
      printf 'TIMEOUT: model %s produced no result within %ss\n' "$model" "$limit" >&2
      return 124
    fi
    sleep 2
    waited=$((waited + 2))
  done
  wait "$pid"; local rc=$?
  cat "$out" 2>/dev/null || true
  rm -f "$out" 2>/dev/null || true
  return $rc
}

cost_preflight() { # cost_preflight <stage> <calls>
  # Operator requirement: the price is stated BEFORE the call, not after.
  # Advisory only -- it does not block; the daily cap and the balance probe
  # are the gates, and a second copy of a gate is how two gates drift.
  local stage="$1" calls="${2:-1}"
  [[ -f "$TOOLS/cost_estimate.py" ]] || return 0
  "${PY[@]}" "$TOOLS/cost_estimate.py" --stage "$stage" --calls "$calls" 2>/dev/null \
    | while IFS= read -r _line; do log "  $_line"; done
  return 0
}

# ── one model call, with breaker integration ──────────────────────────────
# call_model <model> <prompt> -> prints the extracted answer on stdout.
# Returns non-zero if the call failed. The raw error text is printed to
# stderr so the caller can classify it.
call_model() {
  local model="$1" prompt="$2"
  local raw rc output
  set +e
  raw=$(model_with_timeout "$MODEL_TIMEOUT" "$model" "$prompt" 2>&1)
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    log "⚠️ model $model failed (exit $rc): ${raw:-<none>}"
    printf '%s' "$raw" >&2
    return $rc
  fi
  output=$(printf '%s\n' "$raw" | "${PY[@]}" "$EXTRACT")
  printf '%s' "$output"
  return 0
}

# ── single-model stage (scout / recon / triage / reporter) ───────────────
run_single_stage() {
  local role="$1" prompt="$2"
  local want min_votes
  want=$("${PY[@]}" -c "
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))[sys.argv[2]].get('committee_size', 1))" "$MODELS" "$role")
  min_votes=$("${PY[@]}" -c "
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))[sys.argv[2]].get('min_votes', 1))" "$MODELS" "$role")

  local selected
  selected=$(select_models "$role" "$want")
  local live
  live=$(printf '%s' "$selected" | grep -c . || true)

  log "  role=$role live=$live/$want min_votes=$min_votes"

  if [[ "$live" -lt "$min_votes" ]]; then
    log "⛔ INSUFFICIENT CAPACITY for $role: $live live model(s), need $min_votes"
    log "  $("${PY[@]}" -c "
import json, sys
d = json.load(open(sys.argv[1]))
for s in d['skipped']: print(f\"skipped {s['model']}: {s['reason']} {s['detail']}\")
" "$STATE_DIR/selection_$role.json" 2>/dev/null)"
    notify 4 "PIPELINE: insufficient capacity for $role" \
      "Role '$role' has $live live model(s) but needs $min_votes. Stage=$STAGE target=$TARGET. No models were called."
    echo "PARKED (insufficient capacity $live/$min_votes): $prompt"
    return 3
  fi

  local model
  model=$(printf '%s\n' "$selected" | head -n 1)
  log "  using model: $model"
  cost_preflight "$role" 1

  local answer raw
  set +e
  answer=$(call_model "$model" "$prompt" 2>"$STATE_DIR/last_error.txt")
  local rc=$?
  set -e
  raw=$(cat "$STATE_DIR/last_error.txt" 2>/dev/null || echo "")

  if [[ $rc -ne 0 ]]; then
    record_provider_failure "$model" "$raw"
    notify 3 "PIPELINE: $role stage failed" \
      "Stage=$STAGE target=$TARGET model=$model failed (rc=$rc). Detail: ${raw:0:200}"
    log "⚠️ $role stage failed on $model"
    echo "PARKED (stage failure on $model): $prompt"
    return 1
  fi

  record_provider_success "$model"
  record_call "$model"
  echo "$answer"
  return 0
}

# ── committee runner ──────────────────────────────────────────────────────
# Usage: committee_run "prompt" "role" "model1 model2 model3"
# Prints the verdict ("promote" / "park") on stdout. All diagnostics go to
# stderr so the caller's stdout capture is exactly the verdict.
committee_run() {
  local prompt="$1"; shift
  local role="$1"; shift
  local want="$1"; shift
  local candidates=("$@")
  local results=()
  local votes=0
  local used=" "

  # Goal is `want` VOTES, not `want` attempts. A member that fails or is
  # found cooling consumes a candidate but NOT a seat: the next healthy
  # candidate in the priority list backfills it. Without this, a provider
  # cooling mid-committee silently shrinks the committee instead of moving
  # to the next provider.
  while [[ $votes -lt $want ]]; do
    m=""
    for c in "${candidates[@]}"; do
      [[ "$used" == *" $c "* ]] && continue
      if ! model_configured "$c"; then
        log "  ⛔ $c not configured on this machine; skipping"
        used="$used $c "
        continue
      fi
      if provider_exhausted "$c"; then
        log "  ⛔ $(printf '%s' "$c" | sed 's|/.*||') reports exhausted quota (probed); skipping"
        used="$used $c "
        continue
      fi
      if provider_healthy "$c"; then
        m="$c"; break
      fi
      log "  ⛔ provider $(printf '%s' "$c" | sed 's|/.*||') in cooldown ($(( $(cooldown_remaining "$c") ))s); skipping $c"
      used="$used $c "
    done

    if [[ -z "$m" ]]; then
      log "  no further healthy candidates in the priority list"
      break
    fi
    used="$used $m "
    log "  committee member: $m"
    {
      # Retry once on transient failure (free-tier flakiness)
      set +e
      attempt=0
      while [[ $attempt -lt 2 ]]; do
        attempt=$((attempt + 1))
        raw=$(model_with_timeout "$MODEL_TIMEOUT" "$m" "$prompt" 2>&1)
        rc=$?
        output=$(printf '%s\n' "$raw" | "${PY[@]}" "$EXTRACT")
        # AN EMPTY ANSWER IS NOT A VOTE. Some free upstreams return 200 with no
        # text content at all (measured 2026-10-30: groq gpt-oss through
        # opencode). rc==0 on that would consume a committee SEAT with a blank,
        # and committee_compare would then park for "insufficient committee"
        # while the log looked like a full committee. Treat it as a failed
        # call so the retry path handles it and the reason is recorded.
        if [[ $rc -eq 0 && -z "${output//[[:space:]]/}" ]]; then
          rc=1
          raw="empty response: rc=0 but the model returned no text content"
        fi
        if [[ $rc -eq 0 ]]; then
          results+=("$m"$'\t'"$output")
          record_call "$m"
          record_provider_success "$m"
          votes=$((votes + 1))
          set -e
          continue 2  # next committee member
        else
          if [[ $attempt -lt 2 ]]; then
            # Backoff before retry. A quota rejection needs a full minute to
            # clear (free tier is 1 req/min); anything else gets a short pause.
            if printf '%s' "$raw" | grep -qiE 'quota|rate limit|FreeUsageLimit'; then
              sleep 65
              log "⚠️ model $m attempt $attempt failed (quota); retrying in 65s..."
            else
              sleep 5
              log "⚠️ model $m attempt $attempt failed; retrying in 5s..."
            fi
          else
            log "⚠️ model $m failed (exit $rc): ${raw:-<none>}"
            log "⚠️ committee member $m errored after 2 attempts — recorded as non-vote"
            record_provider_failure "$m" "$raw"
            set -e
            results+=("$m"$'\t'"ERROR")
          fi
        fi
      done
      set -e
    }
  done

  SUMMARY="$QUEUE_DIR/last_committee.json"
  rm -f "$SUMMARY"
  result=$(printf '%s\t\n' "${results[@]}" \
    | COMMITTEE_SUMMARY="$SUMMARY" "${PY[@]}" "$TOOLS/committee_compare.py")

  # Every outcome leaves a record, inside committee_run where the per-model
  # results actually live. Verdicts are exactly when provenance matters —
  # including (especially) the parks nobody would revisit.
  local ev_basis="full" ev_votes="" ev_total=""
  if [[ -f "$SUMMARY" ]]; then
    ev_basis=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['basis'])" "$SUMMARY" 2>/dev/null || echo "full")
    ev_votes=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['votes'])" "$SUMMARY" 2>/dev/null || echo "")
    ev_total=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['total_members'])" "$SUMMARY" 2>/dev/null || echo "")
  fi
  write_evidence_packet "$result" "$ev_basis" "$ev_votes" "$ev_total" "$SUMMARY" <<< "$(printf '%s\t\n' "${results[@]}")"

  echo "$result"
}

# ── adversarial pair: evaluator + independent challenger ──────────────────
# The severity committee says what a finding is WORTH. It says nothing about
# whether the finding EXISTS. These two roles answer that, independently.
#
# INDEPENDENCE IS THE POINT: neither prompt contains the other's answer. A
# challenger that can see the evaluator's verdict anchors on it and
# rubber-stamps it, which is the same failure as asking one model twice.
#
# The disagreement matrix is computed by tools/pipeline/disagreement.py, which
# compares CALCULATED severity BANDS (not the numbers the models wrote).
adversarial_prompt() { # adversarial_prompt <role> <hypothesis prompt>
  local role="$1" hypothesis="$2"
  case "$role" in
    evaluator)
      cat <<EOF
You are the EVALUATOR for a bug-bounty hypothesis. You do NOT see any other
reviewer's opinion, and you must not try to guess it.

HYPOTHESIS AND ITS EVIDENCE:
$hypothesis

Decide, using only the evidence named above:
- support: SUPPORTED (the evidence shows the claim), REFUTED (the evidence
  shows it does not hold), or UNTESTED (the evidence does not settle it).
- boundary: YES or NO -- did a test actually cross an authorisation boundary,
  or only produce a response that merely looks unusual?
- cvss_vector: the CVSS 3.1 base vector for the severity IF the claim holds.
  State the METRICS, never a number: the score is calculated from the vector.

Reply with ONE JSON object and nothing else:
{"support":"SUPPORTED|REFUTED|UNTESTED","boundary":"YES|NO","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","note":"one sentence"}
EOF
      ;;
    challenger)
      cat <<EOF
You are the INDEPENDENT CHALLENGER for a bug-bounty hypothesis. Your job is to
BREAK the claim, not to confirm it. You do NOT see any other reviewer's
opinion, and you must not try to guess it.

HYPOTHESIS AND ITS EVIDENCE:
$hypothesis

Attack it. Look for the control that was never run, the parameter whose
meaning was never established, the boundary that was never crossed, the
refused write that proves nothing, the response that is not proof of a
backend effect. Decide:
- attack: HOLDS (the claim survives your attack), INCONCLUSIVE (the evidence
  does not settle it), or FALLS (the claim is wrong).
- boundary: YES or NO -- did a test actually cross an authorisation boundary?
- cvss_vector: the CVSS 3.1 base vector you believe is correct. State the
  METRICS, never a number: the score is calculated from the vector.

Reply with ONE JSON object and nothing else:
{"attack":"HOLDS|INCONCLUSIVE|FALLS","boundary":"YES|NO","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","note":"your strongest counter-argument"}
EOF
      ;;
  esac
}

# Record the pipeline's FINAL outcome in the packet.
#
# The packet's top-level "verdict" is the SEVERITY COMMITTEE's verdict. That
# is not the pipeline's answer: a committee that agrees on a Medium band is
# still not a finding if the evaluator and the challenger say the evidence
# does not settle it. A reviewer reading packet.json must not have to
# reconstruct the decision from three files, so the final outcome goes in the
# packet too, and "promoted" is explicit.
packet_finalize() { # packet_finalize <verdict> <reason>
  local verdict="$1" reason="$2" pdir
  pdir=$(cat "$STATE_DIR/last_packet_dir" 2>/dev/null || true)
  [[ -n "$pdir" && -d "$pdir" ]] || return 0
  "${PY[@]}" - "$pdir" "$verdict" "$reason" <<'PYFIN' 2>/dev/null || true
import json, sys, os
p = os.path.join(sys.argv[1], "packet.json")
verdict, reason = sys.argv[2], sys.argv[3]
try:
    with open(p) as fh:
        packet = json.load(fh)
    packet["final_verdict"] = verdict
    packet["final_reason"] = reason
    packet["promoted"] = verdict == "PROMOTED"
    with open(p, "w") as fh:
        json.dump(packet, fh, indent=2)
except Exception:
    pass
PYFIN
}

# Read the adversarial verdict out of the matrix JSON.
#
# ONE SOURCE OF TRUTH. The first version of this derived the verdict from
# disagreement.py's EXIT CODE and never actually captured it, so rc stayed at
# its initial 0 and every run came back "AGREED_SUPPORTED" -- every
# hypothesis was promoted, including one where the evaluator had said
# UNTESTED and the challenger INCONCLUSIVE. The exit code is now only a
# cross-check; the verdict string in the JSON is what counts.
#
# Fails CLOSED: an unreadable matrix, or a matrix that claims success while
# the tool exited non-zero, both yield INCOMPLETE (park).
adversarial_verdict() { # adversarial_verdict <matrix.json> <tool-rc>
  local file="$1" rc="${2:-0}" verdict
  verdict=$("${PY[@]}" -c "
import json,sys
try:
    print(json.load(open(sys.argv[1])).get('verdict','INCOMPLETE'))
except Exception:
    print('INCOMPLETE')" "$file" 2>/dev/null || echo "INCOMPLETE")
  if [[ "$verdict" == "INCOMPLETE" ]]; then
    echo "INCOMPLETE"
    return 0
  fi
  if [[ "$rc" -ne 0 && "$verdict" == "AGREED_SUPPORTED" ]]; then
    echo "INCOMPLETE"
    return 0
  fi
  echo "$verdict"
}

# Runs both roles, builds the matrix, stores it in the evidence packet, and
# echoes the verdict (AGREED_SUPPORTED | AGREED_UNTESTED | AGREED_REFUTED |
# CONTESTED | INCOMPLETE).
run_adversarial_pair() { # run_adversarial_pair <hypothesis prompt>
  local hypothesis="$1"
  local ev_model ch_model ev_out ch_out matrix rc=0

  ev_model=$(select_models evaluator 1 2>/dev/null | head -1)
  if [[ -z "$ev_model" ]]; then
    log "  adversarial: SKIPPED (no live model for evaluator)"
    echo "SKIPPED"
    return 0
  fi

  # The challenger must be a DIFFERENT model AND a different provider. Two
  # roles picking the same model is one reviewer asked twice; two roles
  # sharing a provider means one quota event removes both and the matrix can
  # never be built at all.
  local ev_provider="${ev_model%%/*}"
  ch_model=$(select_models challenger 1 \
      --exclude-model "$ev_model" --exclude-provider "$ev_provider" 2>/dev/null | head -1)
  if [[ -z "$ch_model" ]]; then
    log "  adversarial: SKIPPED (no live challenger model distinct from $ev_model/$ev_provider)"
    echo "SKIPPED"
    return 0
  fi
  log "  adversarial: evaluator=$ev_model challenger=$ch_model (independent: different model, different provider)"

  ev_out=$(call_model "$ev_model" "$(adversarial_prompt evaluator "$hypothesis")" 2>/dev/null) || ev_out=""
  ch_out=$(call_model "$ch_model" "$(adversarial_prompt challenger "$hypothesis")" 2>/dev/null) || ch_out=""

  local workdir="$STATE_DIR/adversarial"
  mkdir -p "$workdir" 2>/dev/null || true
  printf '%s' "$ev_out" > "$workdir/evaluator.json" 2>/dev/null || true
  printf '%s' "$ch_out" > "$workdir/challenger.json" 2>/dev/null || true

  matrix=""
  rc=0
  matrix=$("${PY[@]}" "$TOOLS/disagreement.py" \
      --evaluator "$workdir/evaluator.json" \
      --challenger "$workdir/challenger.json" 2>"$workdir/matrix.log") || rc=$?
  # Keep the matrix on disk: the verdict string is what the park reason is
  # built from, and it is also what a reviewer reads.
  printf '%s' "$matrix" > "$workdir/matrix.json" 2>/dev/null || true

  # Land the matrix in the evidence packet, and inside packet.json, so the
  # packet is the single artifact a reviewer reads.
  if [[ -f "$STATE_DIR/last_packet_dir" ]]; then
    local pdir
    pdir=$(cat "$STATE_DIR/last_packet_dir" 2>/dev/null || true)
    if [[ -n "$pdir" && -d "$pdir" ]]; then
      printf '%s' "$matrix" > "$pdir/disagreement.json" 2>/dev/null || true
      "${PY[@]}" - "$pdir" <<'PYDIS' 2>/dev/null || true
import json, sys, os
p = os.path.join(sys.argv[1], "packet.json")
try:
    with open(p) as fh:
        packet = json.load(fh)
    with open(os.path.join(sys.argv[1], "disagreement.json")) as fh:
        packet["disagreement"] = json.load(fh)
    with open(p, "w") as fh:
        json.dump(packet, fh, indent=2)
except Exception:
    pass
PYDIS
    fi
  fi

  # The VERDICT comes from the matrix JSON, not from the exit code. One source
  # of truth: the first version of this read the exit code and never actually
  # captured it, so every run came back "AGREED_SUPPORTED" and every hypothesis
  # was promoted -- including one where both reviewers had said the evidence
  # was inconclusive. The exit code is now only a cross-check.
  verdict=$(adversarial_verdict "$workdir/matrix.json" "$rc")
  if [[ "$verdict" == "INCOMPLETE" ]]; then
    log "  adversarial: INCOMPLETE (matrix unreadable or inconsistent, rc=$rc) — failing closed"
  else
    log "  adversarial: $verdict (rc=$rc)"
  fi
  echo "$verdict"
}

# ── main ─────────────────────────────────────────────────────────────────
if [[ -z "$STAGE" || -z "$TARGET" ]]; then
  echo "Usage: orchestrate.sh <stage> <target> [prompt]" >&2
  echo "Stages: scout, recon, hypothesis, triage, reporter" >&2
  exit 2
fi

log "=== pipeline start: STAGE=$STAGE TARGET=$TARGET ==="

# ── Stage 0: engagement policy gate ─────────────────────────────────────
# Program eligibility is enforced here, OUTSIDE the models. Refusal is hard:
# no fallback model, no fallback stage, no queueing. A kill switch stops new
# work AND queued work (drain.py checks the same files).
POLICY_JSON="$STATE_DIR/policy_current.json"
mkdir -p "$STATE_DIR"
policy_rc=0
"${PY[@]}" "$POLICY" decision "$TARGET" > "$POLICY_JSON" 2>/dev/null || policy_rc=$?

POLICY_PROGRAM=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['program'])" "$POLICY_JSON" 2>/dev/null || echo "default")
POLICY_STATUS=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['policy_status'])" "$POLICY_JSON" 2>/dev/null || echo "unknown")
POLICY_SOURCE=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['policy_source'])" "$POLICY_JSON" 2>/dev/null || echo "")

if [[ $policy_rc -ne 0 ]]; then
  POLICY_REASON=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1])).get('reason',''))" "$POLICY_JSON" 2>/dev/null || echo "policy refused")
  log "⛔ POLICY REFUSED: $POLICY_REASON"
  notify 5 "PIPELINE: POLICY REFUSED — ${STAGE}/${TARGET}" \
    "Engagement policy gate refused stage=$STAGE program=$POLICY_PROGRAM status=$POLICY_STATUS. Reason: $POLICY_REASON. Nothing ran. Resolve targets.yaml or clear the kill switch."
  echo "REFUSED (policy): $POLICY_REASON"
  exit 5
fi

log "  policy: program=$POLICY_PROGRAM status=$POLICY_STATUS"

# ── Stage 0b: PRE-DISPATCH duplicate gate ─────────────────────────────────
# A duplicate must never reach a model. The A&F setDefaultAddress hypothesis
# was already a confirmed duplicate (H1 #4132187, dupe of #2649524) and the
# pipeline still spent a committee on it, because the only dedup gate ran at
# FILING time. This one is cheap (local files only) and runs BEFORE any
# dispatch.
#
# It is OPT-IN: the caller passes a typed records file in HYPOTHESIS_RECORDS.
# Without one there is nothing to key the gate on, and refusing everything
# would be a worse failure than the one this fixes.
GATE_JSON="$STATE_DIR/dedupe_gate.json"
GATE_DECISION="DISPATCH"
if [[ -n "${HYPOTHESIS_RECORDS:-}" ]]; then
  gate_rc=0
  "${PY[@]}" "$DEDUPE_GATE" \
    --records "$HYPOTHESIS_RECORDS" \
    --evidence-index "${EVIDENCE_INDEX:-}" \
    --repo-root "$REPO" \
    > "$GATE_JSON" 2>"$STATE_DIR/dedupe_gate.log" || gate_rc=$?

  GATE_DECISION=$("${PY[@]}" -c "
import json,sys
try:
    print(json.load(open(sys.argv[1]))['decision'])
except Exception:
    print('UNRESOLVED')" "$GATE_JSON" 2>/dev/null || echo "UNRESOLVED")
  GATE_VERDICT=$("${PY[@]}" -c "
import json,sys
try:
    print(json.load(open(sys.argv[1]))['verdict'])
except Exception:
    print('unknown')" "$GATE_JSON" 2>/dev/null || echo "unknown")

  if [[ "$GATE_DECISION" != "DISPATCH" ]]; then
    GATE_REASON=$("${PY[@]}" -c "
import json,sys
try:
    d = json.load(open(sys.argv[1]))
    rs = d.get('results') or []
    out = []
    for r in rs:
        for m in r.get('matches', []):
            out.append(m.get('source','') + ' ' + str(m.get('row_id') or m.get('program') or '')[:60])
    print('; '.join(out[:3]) or '; '.join(d.get('reasons', [])) or d.get('verdict',''))
except Exception:
    print('gate produced no report')" "$GATE_JSON" 2>/dev/null || echo "gate produced no report")
    log "⛔ DEDUPE GATE: $GATE_DECISION ($GATE_VERDICT) — $GATE_REASON"
    notify 5 "PIPELINE: duplicate gate stopped the dispatch — ${STAGE}/${TARGET}" \
      "The pre-dispatch gate returned $GATE_DECISION ($GATE_VERDICT). Match: $GATE_REASON. No model was called. Report: $GATE_JSON"
    case "$GATE_DECISION" in
      DROP)      echo "REFUSED (dedupe DROP): $GATE_REASON"; exit 3 ;;
      HOLD)      echo "REFUSED (dedupe HOLD): $GATE_REASON"; exit 4 ;;
      *)         echo "REFUSED (dedupe UNRESOLVED): $GATE_REASON"; exit 6 ;;
    esac
  fi
  log "  dedupe gate: $GATE_DECISION ($GATE_VERDICT) — no duplicate found"
fi

case "$STAGE" in
  scout|recon|triage|reporter)
    if [[ -z "$PROMPT" ]]; then
      echo "ERROR: $STAGE stage requires a prompt" >&2
      exit 1
    fi
    set +e
    run_single_stage "$STAGE" "$PROMPT"
    rc=$?
    set -e
    exit $rc
    ;;

  hypothesis)
    log "Hypothesis committee run for $TARGET"

    want=$("${PY[@]}" -c "
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))['hypothesis'].get('committee_size', 3))" "$MODELS")
    min_votes=$("${PY[@]}" -c "
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))['hypothesis'].get('min_votes', 2))" "$MODELS")

    SELECTED=$(select_models hypothesis "$want")
    LIVE=$(printf '%s' "$SELECTED" | grep -c . || true)

    log "  roster (priority order): $("${PY[@]}" -c "
import sys, yaml
print(' '.join(yaml.safe_load(open(sys.argv[1]))['hypothesis']['models']))" "$MODELS")"
    log "  selected: ${SELECTED//$'\n'/ }"
    log "  live=$LIVE/$want min_votes=$min_votes"

    # INSUFFICIENT CAPACITY: too few live models to form a committee. Park
    # without calling anything -- limping forward on one voice is not a
    # committee, and it would look like a result.
    if [[ "$LIVE" -lt "$min_votes" ]]; then
      log "⛔ INSUFFICIENT CAPACITY: only $LIVE live model(s), need $min_votes"
      "${PY[@]}" -c "
import json, sys
d = json.load(open(sys.argv[1]))
for s in d['skipped']: print(f\"  skipped {s['model']}: {s['reason']} {s['detail']}\")
" "$STATE_DIR/selection_hypothesis.json" 2>/dev/null || true
      notify 4 "PIPELINE: insufficient capacity for hypothesis" \
        "Hypothesis stage has $LIVE live model(s) but needs $min_votes. Target=$TARGET. No models were called."
      echo "PARKED (insufficient capacity $LIVE/$min_votes): ${TARGET}"
      exit 3
    fi

    # Pass the FULL priority list, not the pre-selected subset: the committee
    # re-checks health per seat and backfills from the remaining candidates,
    # so a provider that cools mid-run costs a candidate, not a seat.
    CANDIDATES=()
    while IFS= read -r m; do
      [[ -n "$m" ]] && CANDIDATES+=("$m")
    done < <("${PY[@]}" -c "
import sys, yaml
for m in yaml.safe_load(open(sys.argv[1]))['hypothesis']['models']:
    print(m)
" "$MODELS")

    # History is attached as CONTEXT to the hypothesis only. It is never read
    # by a gate, and a run with no map behaves exactly as before.
    TERRITORY="$(territory_block || true)"
    if [[ -n "$TERRITORY" ]]; then
      log "  territory: attached ($(printf '%s' "$TERRITORY" | grep -c .) lines of repo history)"
      PROMPT="$PROMPT$TERRITORY"
    fi

    cost_preflight "$STAGE" "$want"
    result=$(committee_run "$PROMPT" "$STAGE" "$want" "${CANDIDATES[@]}")

    # Read the vote detail so a degraded committee is not reported as a split.
    basis="full"; votes=""; total=""
    if [[ -f "$QUEUE_DIR/last_committee.json" ]]; then
      basis=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['basis'])" "$QUEUE_DIR/last_committee.json" 2>/dev/null || echo "full")
      votes=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['votes'])" "$QUEUE_DIR/last_committee.json" 2>/dev/null || echo "")
      total=$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['total_members'])" "$QUEUE_DIR/last_committee.json" 2>/dev/null || echo "")
    fi


    if [[ "$result" == "promote" ]]; then
      # Severity is settled; existence is not. Run the adversarial pair before
      # anything is called "promoted".
      ADJ_VERDICT=$(run_adversarial_pair "$PROMPT")
      if [[ "$ADJ_VERDICT" != "AGREED_SUPPORTED" ]]; then
        # ONLY a supported, agreed claim is promoted. Agreement on "the
        # evidence does not settle this" is agreement that there is no finding
        # YET -- promoting that would be promoting an untested hypothesis.
        case "$ADJ_VERDICT" in
          CONTESTED)
            log "🅿️ Hypothesis CONTESTED — evaluator and challenger disagree; not promoting"
            notify 4 "PIPELINE: hypothesis contested — evaluator vs challenger disagree" \
              "Target=$TARGET. The severity committee agreed, but the evaluator and the independent challenger DISAGREE (severity band and/or support and/or boundary). Not promoted. The matrix is in the evidence packet."
            packet_finalize "PARKED" "CONTESTED: evaluator and challenger disagree"
            echo "PARKED (contested: evaluator vs challenger disagree): $PROMPT"
            ;;
          AGREED_UNTESTED)
            log "🅿️ Hypothesis UNTESTED — both reviewers agree the evidence does not settle it; not promoting"
            notify 4 "PIPELINE: hypothesis untested — evidence does not settle the claim" \
              "Target=$TARGET. The evaluator and the challenger AGREED, but their verdict is UNTESTED/INCONCLUSIVE: the evidence does not establish the claim. Not promoted. Their reasoning is in the evidence packet."
            packet_finalize "PARKED" "UNTESTED: the evidence does not settle the claim"
            echo "PARKED (untested: evidence does not settle the claim): $PROMPT"
            ;;
          AGREED_REFUTED)
            log "💀 Hypothesis REFUTED — both reviewers agree the claim fails; not promoting"
            notify 4 "PIPELINE: hypothesis refuted — evaluator and challenger agree it fails" \
              "Target=$TARGET. The evaluator and the challenger agree the claim does not hold. Not promoted. Their reasoning is in the evidence packet."
            packet_finalize "PARKED" "REFUTED: evaluator and challenger agree the claim fails"
            echo "PARKED (refuted: evaluator and challenger agree it fails): $PROMPT"
            ;;
          *)
            log "🅿️ Hypothesis not promoted — adversarial pair returned $ADJ_VERDICT"
            packet_finalize "PARKED" "adversarial pair returned $ADJ_VERDICT"
            echo "PARKED (adversarial pair: $ADJ_VERDICT): $PROMPT"
            ;;
        esac
        exit 0
      fi
      log "  adversarial: $ADJ_VERDICT (supported and agreed)"
      if [[ "$basis" == "degraded" ]]; then
        log "✅ Hypothesis promoted — but committee DEGRADED ($votes/$total voted; agreement is unanimous among responders, not 2-of-3)"
        notify 3 "PIPELINE: hypothesis promoted (degraded $votes/$total)" \
          "Target=$TARGET. Committee DEGRADED: $votes of $total members voted, so agreement is unanimous among responders rather than 2-of-3. Scores in the pipeline log."
        packet_finalize "PROMOTED" "severity band agreed by $votes/$total; evaluator and challenger agree the claim is supported"
        echo "PROMOTED (degraded committee $votes/$total): $PROMPT"
      else
        log "✅ Hypothesis promoted (2/3 agreement via CVSS severity band)"
        notify 3 "PIPELINE: hypothesis promoted" \
          "Target=$TARGET. Committee agreed on a severity band ($votes/$total voted). The band, the vector and the calculated score are in the evidence packet."
        packet_finalize "PROMOTED" "severity band agreed by $votes/$total; evaluator and challenger agree the claim is supported"
        echo "PROMOTED: $PROMPT"
      fi
    elif [[ "$result" == "park" ]]; then
      if [[ "$votes" == "0" || "$votes" == "" ]]; then
        log "💀 TOTAL COMMITTEE LOSS: no member produced a score"
        notify 5 "PIPELINE: total committee loss" \
          "Hypothesis stage for $TARGET had ZERO usable votes out of $total members. Every provider is refusing calls. See the pipeline log."
        echo "PARKED (total committee loss 0/$total): $PROMPT"
      elif [[ "$basis" == "degraded" || "$basis" == "insufficient" ]]; then
        log "🅿️ Hypothesis parked — INSUFFICIENT COMMITTEE ($votes/$total voted), not a 3-way split; retry when quota resets"
        echo "PARKED (insufficient committee $votes/$total): ${TARGET}"
      else
        log "🅿️ Hypothesis parked (committee split across CVSS severity bands)"
        echo "PARKED (committee split across CVSS bands): ${TARGET}"
      fi
    else
      log "⚠️ Hypothesis committee error: $result"
      notify 4 "PIPELINE: hypothesis committee error" \
        "Stage=$STAGE target=$TARGET produced an unexpected verdict: $result"
      echo "ERROR: $result"
    fi
    ;;

  *)
    echo "Unknown stage: $STAGE" >&2
    exit 2
    ;;
esac

log "=== pipeline stage complete: STAGE=$STAGE ==="
