#!/usr/bin/env bash
# frack-status.sh — one machine-readable line about a frack job, read on X.
#
# WHY A SEPARATE SCRIPT
# The Mac watcher polls this every 15s. Doing that with an inline ssh command
# would mean nesting quotes through zsh -> ssh -> cmd -> Git Bash five times a
# minute, and that is exactly the layer stack that has eaten quotes before
# (`Invalid model reference: $m`). Here the quoting is written once, tested
# once, and the Mac only ever sends a bare job name.
#
# WHAT IT REPORTS
#   state=running   the run started and has not concluded
#   state=done      result.txt exists: the run concluded and described itself
#   state=missing   nothing for this job -- it never started (or was cleaned)
#
# Absence of state=done is meaningful on its own: it is how the Mac knows to
# escalate instead of reporting a verdict it never received.

set -uo pipefail

JOB="${1:-}"
if [[ -z "$JOB" ]]; then
  echo "state=missing reason=no-job-name"
  exit 2
fi
if [[ ! "$JOB" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "state=missing reason=bad-job-name"
  exit 2
fi

JOBDIR="${HOME:-/c/Users/Gaming PC}/.frack/jobs/$JOB"

if [[ -f "$JOBDIR/result.txt" ]]; then
  echo "state=done"
  # Re-emit the result as key=value, except the verdict, which may contain
  # spaces and quotes and is therefore emitted last and alone.
  grep -aE '^(rc|elapsed|cost|stage|target|job)=' "$JOBDIR/result.txt" 2>/dev/null
  verdict="$(grep -a '^verdict=' "$JOBDIR/result.txt" 2>/dev/null | head -1 | sed 's/^verdict=//')"
  echo "verdict_len=${#verdict}"
  printf 'verdict=%s\n' "$verdict"
  exit 0
fi

if [[ -f "$JOBDIR/run.log" ]]; then
  echo "state=running"
  echo "log_bytes=$(wc -c < "$JOBDIR/run.log" 2>/dev/null | tr -d ' ')"
  # The last thing we heard, so a stuck run is visible rather than silent.
  tail_line="$(grep -a . "$JOBDIR/run.log" 2>/dev/null | tail -1)"
  printf 'last=%s\n' "${tail_line:0:160}"
  exit 0
fi

echo "state=missing"
exit 0
