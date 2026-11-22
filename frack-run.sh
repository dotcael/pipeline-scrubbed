#!/usr/bin/env bash
# frack-run.sh — the REMOTE half of `X frack`: run one pipeline stage and report.
#
# WHY THIS FILE EXISTS
# `X frack <target> "<prompt>"` starts this on X and returns immediately. The
# terminal must not be the thing holding the run open, and the report must not
# depend on the Mac still being awake -- so the summary notification is sent
# from HERE, on the machine that did the work. If the Mac sleeps, the phone
# still hears about it.
#
# NO ARGUMENTS EXCEPT A JOB NAME, ON PURPOSE.
# This command crosses zsh -> ssh/offload -> PowerShell -> cmd -> Git Bash.
# Every one of those layers has mangled quotes at some point (see AGENTS.md:
# the -EncodedCommand ceiling, `Invalid model reference: $m`). So the prompt
# is never passed on a command line and never expanded by an outer shell: it
# arrives in a file, and the only argument is a name matching [a-z0-9-]+.
#
# LAYOUT (created by the Mac side, under the operator's home on X):
#   ~/.frack/jobs/<job>/conf        STAGE=... / TARGET=... (shell assignments)
#   ~/.frack/jobs/<job>/prompt.txt  the hypothesis prompt, verbatim
#   ~/.frack/jobs/<job>/run.log     full pipeline output (also on stdout)
#
# OUTPUT CONTRACT (parsed by the Mac watcher -- do not reword casually):
#   FRACK_RESULT rc=<n> verdict="<text>" cost=<usd> elapsed=<secs> stage=<s> target=<t>
#   FRACK_DONE rc=<n>
# FRACK_DONE is the "the remote reported" marker: if the Mac watcher never sees
# it, the run died in a way it could not describe, and the watcher escalates.

set -uo pipefail

JOB="${1:-}"
if [[ -z "$JOB" ]]; then
  echo "usage: frack-run.sh <job>" >&2
  exit 2
fi
if [[ ! "$JOB" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "refused: job name may only contain letters, digits, dot, underscore, hyphen: $JOB" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
JOBDIR="${HOME:-/c/Users/Gaming PC}/.frack/jobs/$JOB"
CONF="$JOBDIR/conf"
PROMPT_FILE="$JOBDIR/prompt.txt"
RUNLOG="$JOBDIR/run.log"

mkdir -p "$JOBDIR"

fail_fast() { # a missing input is not an empty input
  echo "FRACK_RESULT rc=2 verdict=\"$1\" cost=0 elapsed=0 stage=unknown target=unknown"
  echo "FRACK_DONE rc=2"
  exit 2
}

[[ -f "$CONF" ]] || fail_fast "no conf at $CONF"
[[ -f "$PROMPT_FILE" ]] || fail_fast "no prompt file at $PROMPT_FILE"

# The conf is written by our own Mac side into the operator's home; it holds
# nothing but the two assignments below.
# shellcheck disable=SC1090
source "$CONF"
STAGE="${STAGE:-hypothesis}"
TARGET="${TARGET:-unnamed}"
PROMPT="$(cat "$PROMPT_FILE")"

if [[ -z "${PROMPT//[[:space:]]/}" ]]; then
  fail_fast "empty prompt"
fi

# The committee compares BANDS, and a band comes from a CVSS 3.1 vector the model
# has to state. A prompt that never asks for one produces answers the parser
# cannot score, so the run parks with "total committee loss" while every model
# answered fine -- measured 2026-11-02, and it looks exactly like a dead roster.
# Append the contract here rather than trusting the caller to remember it.
if ! grep -qi 'cvss' <<< "$PROMPT"; then
  PROMPT="$PROMPT

OUTPUT CONTRACT (required by the comparator, one line per hypothesis):
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
State the metrics only. The score and the band are computed by the pipeline from
that vector. A hypothesis with no vector cannot vote."
fi
if [[ ! -f "$REPO/tools/pipeline/orchestrate.sh" ]]; then
  fail_fast "no orchestrate.sh under $REPO"
fi

echo "=== frack $JOB ==="
echo "stage=$STAGE target=$TARGET host=$(hostname 2>/dev/null || echo x)"
echo "repo=$REPO"
echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "------------------------------------------------------------"

START=$(date +%s)
# tee so the log exists on disk even if the outer runner truncates stdout.
bash "$REPO/tools/pipeline/orchestrate.sh" "$STAGE" "$TARGET" "$PROMPT" 2>&1 | tee "$RUNLOG"
rc=${PIPESTATUS[0]}
ELAPSED=$(( $(date +%s) - START ))

# ── summarise ────────────────────────────────────────────────────────────────
# The verdict is the LAST `PIPELINE:` line orchestrate emitted: every outcome
# path (promote / refute / contested / insufficient capacity / policy refusal)
# writes exactly one, so this does not need to know the list of them.
VERDICT="$(grep -a 'PIPELINE:' "$RUNLOG" 2>/dev/null | tail -1 | sed -e 's/^\[[^]]*\][[:space:]]*//' -e 's/^PIPELINE:[[:space:]]*//')"
if [[ -z "$VERDICT" ]]; then
  # Only the hypothesis stage writes a `PIPELINE:` verdict. For scout / recon /
  # reporter the useful thing on the banner is what the model actually SAID, so
  # fall back to the last non-log line (the pipeline prefixes its own lines with
  # a [timestamp], the model's answer arrives bare).
  LAST_ANSWER="$(grep -av '^\[' "$RUNLOG" 2>/dev/null | grep -av '^[[:space:]]*$' | tail -1)"
  # The pipeline often echoes the hypothesis back after its verdict. The banner
  # should say what HAPPENED, not repeat what was asked, so cut at the echo.
  if [[ -n "${PROMPT:0:20}" && "$LAST_ANSWER" == *"${PROMPT:0:20}"* ]]; then
    LAST_ANSWER="${LAST_ANSWER%%"${PROMPT:0:20}"*}"
  fi
  LAST_ANSWER="$(printf '%s' "$LAST_ANSWER" | sed -e 's/[[:space:]:,-]*$//')"
  [[ -n "$LAST_ANSWER" ]] || LAST_ANSWER="no output"
  VERDICT="$STAGE completed: ${LAST_ANSWER}"
fi
[[ ${#VERDICT} -le 160 ]] || VERDICT="${VERDICT:0:157}..."

# Cost actually quoted across the run. The estimates are printed with a
# `TOTAL : $x.xxxxx` line each; summing them is the honest total of what this
# stage said it would cost.
# The pipeline logs with a `[timestamp]` prefix, so `TOTAL` is NOT field 1 --
# reading $3 there grabbed the ":" and summed zero, which is how a run that
# spent money reported $0.00000. Find the colon and take the token after it.
COST="$(awk '/TOTAL : \$/ { for (i=1;i<=NF;i++) if ($i==":") { v=$(i+1); gsub(/[^0-9.]/,"",v); s+=v; break } } END { printf "%.5f", s+0 }' "$RUNLOG" 2>/dev/null)"
[[ -n "$COST" ]] || COST="0"
[[ -n "$COST" ]] || COST="0"

echo "------------------------------------------------------------"
echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ) rc=$rc elapsed=${ELAPSED}s"
echo "FRACK_RESULT rc=$rc verdict=\"$VERDICT\" cost=$COST elapsed=$ELAPSED stage=$STAGE target=$TARGET"

# A SENTINEL THE MAC CAN TRUST. The Mac polls this file instead of parsing
# PowerShell's manifest JSON or trusting a Syncthing mirror (which we have
# already caught being minutes stale). Its presence means "this job reached a
# conclusion and described it"; its absence means the run died mid-flight.
{
  echo "job=$JOB"
  echo "stage=$STAGE"
  echo "target=$TARGET"
  echo "rc=$rc"
  echo "elapsed=$ELAPSED"
  echo "cost=$COST"
  echo "verdict=$VERDICT"
} > "$JOBDIR/result.txt"

# ── no notification from here ────────────────────────────────────────────────
# OPERATOR DIRECTIVE (2026-10-30): notifications go to the MAC, not the phone.
# X cannot post to the Mac's Notification Centre, so the notifier is the Mac
# watcher that started this job -- it is already polling and it knows the Mac
# is awake (it is running on it). An ntfy/phone push from here was the earlier
# design and was removed: a channel the operator does not want is worse than no
# channel, because it splits where the truth lives.
#
# The consequence is honest and worth stating plainly: if that watcher dies,
# this run finishes silently. That is why the watcher writes a status line on
# the Mac and `X frack status` reads it.

echo "FRACK_DONE rc=$rc"
exit "$rc"
