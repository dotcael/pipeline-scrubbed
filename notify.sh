#!/usr/bin/env bash
# notify.sh — push a notification to the operator's phone via ntfy.sh.
#
# ONE function, called by every failure path. Alerts scattered ad hoc
# through the code are how you end up with gaps later: someone adds a new
# failure mode, forgets the alert, and the pipeline goes quiet for a week.
#
# Usage: notify.sh <priority> <title> <body>
#   priority: 1=min 2=low 3=default 4=high 5=max/urgent
#
# Topic: $NTFY_TOPIC, else the first line of ~/.secrets/opencode/ntfy.key
#        (chmod 600). The topic IS the secret -- anyone holding it can read
#        everything posted to it, so use a random one.
#
# A NOTIFICATION FAILURE MUST NEVER BREAK THE PIPELINE. Every failure here
# is swallowed and reported on stderr; the caller's exit status is always 0.
#
# Dedupe: the same event signature is suppressed within DEDUP_WINDOW
# seconds, so a provider that flaps in and out of cooldown cannot spam the
# phone. Use a distinct signature for genuinely distinct events.

set -uo pipefail

PRIORITY="${1:-3}"
TITLE="${2:-pipeline notice}"
BODY="${3:-}"
EVENT_ID="${4:-}"
DEDUP_WINDOW="${NTFY_DEDUP_WINDOW:-900}"   # 15 min

TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$TOOLS/.state"
DEDUP_FILE="$STATE_DIR/notify_dedup"

log() { echo "[$(date +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

# ── resolve topic ────────────────────────────────────────────────────────────
resolve_topic() {
  if [[ -n "${NTFY_TOPIC:-}" ]]; then
    printf '%s' "$NTFY_TOPIC"
    return 0
  fi
  local keyfile="${NTFY_KEY_FILE:-$HOME/.secrets/opencode/ntfy.key}"
  if [[ -f "$keyfile" ]]; then
    head -n 1 "$keyfile" | tr -d '\r\n'
    return 0
  fi
  return 1
}

# ── resolve the access token ─────────────────────────────────────────────────
# The ntfy account's access token. Sending it makes our publishes
# AUTHENTICATED and attributable, and it is REQUIRED the moment the topic is
# reserved with "everyone: none" (a private topic) — without the token the
# publish would start failing. So it is wired in now, ahead of the upgrade.
#
# NOTE ON WHAT AUTH DOES AND DOES NOT BUY (free tier, 2026-10-22):
# a token authenticates US. On a PUBLIC topic anyone can still subscribe and
# publish, so the topic NAME remains the security boundary until the topic is
# reserved. See research/NTFY-CHANNEL-2026-10-22.md.
resolve_token() {
  if [[ -n "${NTFY_TOKEN:-}" ]]; then
    printf '%s' "$NTFY_TOKEN"
    return 0
  fi
  local tokfile="${NTFY_TOKEN_FILE:-$HOME/.secrets/opencode/ntfy.token}"
  if [[ -f "$tokfile" ]]; then
    head -n 1 "$tokfile" | tr -d '\r\n'
    return 0
  fi
  return 1
}

# ── dedupe ───────────────────────────────────────────────────────────────────
# Signature is the title plus the first line of the body: same event, same
# suppression. Different events get different titles.
signature() {
  printf '%s|%s|%s' "${EVENT_ID:-}" "$TITLE" "${BODY%%$'\n'*}" | shasum -a 256 | cut -c1-16
}

is_duplicate() {
  local sig="$1" now
  now=$(date +%s)
  [[ -f "$DEDUP_FILE" ]] || return 1
  # Keep the file tidy while we're here.
  local tmp="$DEDUP_FILE.tmp"
  : > "$tmp"
  local found=0
  while IFS='|' read -r s t; do
    [[ -z "${s:-}" ]] && continue
    if (( now - t < DEDUP_WINDOW )); then
      printf '%s|%s\n' "$s" "$t" >> "$tmp"
      [[ "$s" == "$sig" ]] && found=1
    fi
  done < "$DEDUP_FILE"
  mv "$tmp" "$DEDUP_FILE"
  [[ $found -eq 1 ]]
}

record_signature() {
  local sig="$1"
  mkdir -p "$STATE_DIR" 2>/dev/null || true
  printf '%s|%s\n' "$sig" "$(date +%s)" >> "$DEDUP_FILE" 2>/dev/null || true
}

# ── main ────────────────────────────────────────────────────────────────────
main() {
  local topic
  if ! topic=$(resolve_topic); then
    log "notify: no ntfy topic configured (set NTFY_TOPIC or ~/.secrets/opencode/ntfy.key) — skipping"
    return 0
  fi
  if [[ -z "$topic" ]]; then
    log "notify: ntfy topic is empty — skipping"
    return 0
  fi

  local sig
  sig=$(signature)
  if is_duplicate "$sig"; then
    log "notify: duplicate suppressed ($TITLE)"
    return 0
  fi

  local base="${NTFY_URL:-https://ntfy.sh}"
  local resp
  local token
  token="$(resolve_token || true)"

  # BUILD THE ARGUMENT LIST, then expand it once.
  #
  # The previous form expanded a possibly-EMPTY array inline:
  #     ... -H "Tags: computer,bug" \
  #     "${auth_args[@]}" --data ...
  # On bash 3.2 -- what macOS ships -- an empty array under `set -u` is an
  # unbound-variable ERROR, so every notification sent without a token died
  # before reaching the network. (The "fix" of wrapping it in
  # ${arr[@]+"${arr[@]}"} then hit a second, sillier wall: a comment cannot sit
  # inside a backslash-continued command, because the comment ENDS the logical
  # line and splits curl's arguments.) An array that always has at least its
  # base arguments is non-empty by construction, so neither failure exists.
  local args=(
    -sS -m 10 -o /dev/null -w '%{http_code}'
    -H "Title: $TITLE"
    -H "Priority: $PRIORITY"
    -H "Tags: computer,bug"
  )
  [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")
  args+=(--data "$BODY" "$base/$topic")

  resp=$(curl "${args[@]}" 2>&1)

  if [[ "$resp" =~ ^2 ]]; then
    record_signature "$sig"
    log "notify: sent ($resp) — $TITLE"
  else
    log "notify: FAILED (${resp:-no response}) — $TITLE"
  fi
  # Never propagate a failure to the caller.
  return 0
}

main
exit 0
