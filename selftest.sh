#!/usr/bin/env bash
# selftest.sh — one-command regression suite for the bug-bounty pipeline.
#
#   bash tools/pipeline/selftest.sh
#
# Every case here was a real bug that shipped at least once:
#   - committee_compare.py's promotion threshold drifting from "if agreeing_pairs:"
#   - a member erroring aborting the whole committee (return 1 on first failure)
#   - the record format breaking on multi-line model output
#   - a colon in the model id truncating the name
#   - a one-letter variable-name mismatch between the breaker's emitted key
#     and the shell that consumed it (killed the run under set -u)
#   - primary_for being called but never defined, so four of five stages were
#     dead code
#   - hardcoded macOS paths in a script meant to run on Windows
#   - nemotron (answers by recall, not computation) sitting in a scoring role
#
# The point of this file: those must not be findable by reading code again.
#
# The orchestrator's shell functions are TESTED BY EXTRACTION from
# orchestrate.sh, never by copying them here -- a copy would drift and the
# test would keep passing against code that is no longer what ships.

set -uo pipefail

TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCH="$TOOLS/orchestrate.sh"

# The python snippets below locate the pipeline modules relative to the
# CURRENT WORKING DIRECTORY, because a Git Bash POSIX path (/c/Users/...)
# cannot be resolved by native Windows Python. So run from the repo root.
cd "$(dirname "$(dirname "$TOOLS")")" || exit 1   # repo root
PASS=0
FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Same interpreter discovery as orchestrate.sh -- on Windows the PATH
# `python3` is a Microsoft Store stub that runs nothing.
# shellcheck source=pyenv.sh
source "$TOOLS/pyenv.sh"

# The breaker writes real state. Point it at a throwaway directory so the
# selftest cannot put fake providers into cooldown in the live state file --
# which previously made a REAL run skip a healthy provider.
export PIPELINE_STATE_DIR="$TMP/state"
mkdir -p "$PIPELINE_STATE_DIR"

ok()    { PASS=$((PASS+1)); echo "  ok   - $1"; }
bad()   { FAIL=$((FAIL+1)); echo "  FAIL - $1"; }
check() { # check <label> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

echo "== committee_compare.py =="
# The criterion is the SEVERITY BAND -- the payout unit -- not a numeric
# tolerance. The vectors below are CALCULATED by tools/cvss31.py; the comment
# gives the score that module returns, it is not a hand-written number.
CVSS_MED="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"    # 6.5 Medium
CVSS_MED2="AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"   # 5.7 Medium
CVSS_MED3="AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"    # 5.4 Medium
CVSS_LOW="AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"     # 2.8 Low
CVSS_HIGH="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"    # 7.5 High
CVSS_CRIT="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"    # 10.0 Critical
CVSS_NONE="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"   # 0.0 None

# THE 2026-10-22 INCIDENT: 5.4 / 6.5 / 4.6. All three are Medium, so all
# three are the same money under A&F. The old +/-0.4 numeric rule called this
# a split and PARKED the finding.
out=$(printf "minimax:{\"base_score\": 5.4}\ndeepseek:{\"base_score\": 6.5}\nnemotron:{\"base_score\": 4.6}\n" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "incident case 5.4/6.5/4.6 promotes (all Medium)" "promote" "$out"

# A genuine band split -- Low / Medium / High -- still parks.
out=$(printf "minimax:{\"base_score\": 3.5}\ndeepseek:{\"base_score\": 5.0}\nnemotron:{\"base_score\": 8.0}\n" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "split across bands parks" "park" "$out"

out=$(printf "minimax:{\"base_score\": 6.5}\ndeepseek:{\"base_score\": 6.6}\nnemotron:{\"base_score\": 8.0}\n" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "close pair promotes" "promote" "$out"

out=$(printf "minimax:{\"base_score\": 6.5}\ndeepseek:{\"base_score\": 6.7}\nnemotron:{\"base_score\": 7.1}\n" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "legacy case promotes" "promote" "$out"

# Tab-delimited records still parse, and a model id containing a colon is not
# mistaken for the delimiter. 4.6 is Medium, 8.5 is High -> park.
out=$(printf 'openrouter/minimax/minimax-m3.1-flash:free\t{"base_score": 4.6}\nbeatapi/x\t{"base_score": 8.5}\n' \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "tab record with colon in model id parses" "park" "$out"

out=$(printf 'openrouter/minimax/minimax-m3.1-flash:free\t{"base_score": 4.6}\nbeatapi/x\t{"base_score": 6.5}\n' \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "tab record, same band, promotes" "promote" "$out"

out=$(printf 'minimax\t{"base_score": 7.5}\ndeepseek\tERROR\n' \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "single vote parks" "park" "$out"

# VECTORS: the model states the metrics, the tool CALCULATES the score and
# band. Three Medium vectors with different metrics are still one band.
out=$(printf "minimax:{\"cvss_vector\": \"%s\"}\ndeepseek:{\"cvss_vector\": \"%s\"}\nnemotron:{\"cvss_vector\": \"%s\"}\n" \
      "$CVSS_MED" "$CVSS_MED2" "$CVSS_MED3" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "three Medium vectors promote" "promote" "$out"

out=$(printf "minimax:{\"cvss_vector\": \"%s\"}\ndeepseek:{\"cvss_vector\": \"%s\"}\nnemotron:{\"cvss_vector\": \"%s\"}\n" \
      "$CVSS_LOW" "$CVSS_MED" "$CVSS_CRIT" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "vectors spanning three bands park" "park" "$out"

# A vector and a legacy score in the SAME band agree, and the summary records
# which member was calculated and which was estimated.
SUMMARY_DIR="tools/pipeline/.state"
mkdir -p "$SUMMARY_DIR"
SUMMARY_PATH="$SUMMARY_DIR/selftest_committee_summary.json"
export COMMITTEE_SUMMARY="$SUMMARY_PATH"
out=$(printf "minimax:{\"cvss_vector\": \"%s\"}\ndeepseek:{\"base_score\": 6.6}\n" "$CVSS_MED" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
unset COMMITTEE_SUMMARY
check "vector + legacy score, same band, promotes" "promote" "$out"
check "summary records the calculated basis" "calculated_from_vector" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['members']['minimax']['basis'])" "$SUMMARY_PATH")"
check "summary records the estimated basis" "estimated_score" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['members']['deepseek']['basis'])" "$SUMMARY_PATH")"

# The consensus band is the money: the incident case is Medium (=\$750 A&F).
export COMMITTEE_SUMMARY="$SUMMARY_PATH"
printf "minimax:{\"base_score\": 5.4}\ndeepseek:{\"base_score\": 6.5}\nnemotron:{\"base_score\": 4.6}\n" \
  | "${PY[@]}" "$TOOLS/committee_compare.py" >/dev/null 2>&1
unset COMMITTEE_SUMMARY
check "summary records the consensus band" "Medium" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['consensus_band'])" "$SUMMARY_PATH")"
check "summary states the criterion" "same CVSS 3.1 severity band" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['criterion'])" "$SUMMARY_PATH")"
rm -f "$SUMMARY_PATH"

# "None" means the member does not believe there is an impact. Two members
# agreeing that nothing is wrong is not a severity agreement, so a None-band
# member is NOT counted as a band vote.
out=$(printf "minimax:{\"cvss_vector\": \"%s\"}\ndeepseek:{\"cvss_vector\": \"%s\"}\n" "$CVSS_NONE" "$CVSS_NONE" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "None band is not a severity agreement" "park" "$out"

# A member with no usable severity is a NON-VOTE, not a disagreement.
out=$(printf "minimax:{\"cvss_vector\": \"%s\"}\ndeepseek:{\"cvss_vector\": \"%s\"}\nnemotron:ERROR\n" \
      "$CVSS_MED" "$CVSS_MED2" \
      | "${PY[@]}" "$TOOLS/committee_compare.py" 2>/dev/null)
check "unparseable member is a non-vote" "promote" "$out"

echo "== typed records (records.py) =="
REC_TMP="$TMP/records"
mkdir -p "$REC_TMP"
cat > "$REC_TMP/good.txt" <<'RECEOF'
FACT id=F1 program="A&F" claim="Account B mutated Account A's default address" evidence=E-0001
HYPOTHESIS id=H1 program="A&F" asset=www.abercrombie.com weakness=CWE-639 capability="Modify another customer's default address without ownership verification" evidence=E-0001
RECEOF
printf '%s\n' '{"E-0001": {"note": "recorded repro"}}' > "$REC_TMP/evidence.json"
out=$("${PY[@]}" "$TOOLS/records.py" --validate "$REC_TMP/good.txt" --evidence-index "$REC_TMP/evidence.json" 2>&1)
check "valid records validate" "valid" "$(printf '%s' "$out" | tail -1)"

cat > "$REC_TMP/badtype.txt" <<'RECEOF'
BOGUS id=X1 program="A&F" claim="c" evidence=E-0001
RECEOF
out=$("${PY[@]}" "$TOOLS/records.py" --validate "$REC_TMP/badtype.txt" --evidence-index "$REC_TMP/evidence.json" 2>&1)
check "unknown record type is rejected" "INVALID" "$(printf '%s' "$out" | tail -1)"

cat > "$REC_TMP/badfield.txt" <<'RECEOF'
HYPOTHESIS id=H1 program="A&F" asset=a.com aset=typo weakness=CWE-1 capability="c" evidence=E-0001
RECEOF
out=$("${PY[@]}" "$TOOLS/records.py" --validate "$REC_TMP/badfield.txt" --evidence-index "$REC_TMP/evidence.json" 2>&1)
check "unknown field is rejected (a typo must not drop the asset)" "INVALID" "$(printf '%s' "$out" | tail -1)"

cat > "$REC_TMP/dup.txt" <<'RECEOF'
FACT id=F1 program="A&F" claim="c" evidence=E-0001
FACT id=F1 program="A&F" claim="c" evidence=E-0001
RECEOF
out=$("${PY[@]}" "$TOOLS/records.py" --validate "$REC_TMP/dup.txt" --evidence-index "$REC_TMP/evidence.json" 2>&1)
check "duplicate record id is rejected" "INVALID" "$(printf '%s' "$out" | tail -1)"

cat > "$REC_TMP/noev.txt" <<'RECEOF'
HYPOTHESIS id=H1 program="A&F" asset=a.com weakness=CWE-1 capability="c" evidence=E-9999
RECEOF
out=$("${PY[@]}" "$TOOLS/records.py" --validate "$REC_TMP/noev.txt" --evidence-index "$REC_TMP/evidence.json" 2>&1)
check "unresolvable evidence is rejected" "INVALID" "$(printf '%s' "$out" | tail -1)"

echo "== pre-dispatch dedupe gate (dedupe_gate.py) =="
# The REAL case that motivated the gate: the A&F setDefaultAddress hypothesis
# was a confirmed duplicate (H1 #4132187, dupe of #2649524) and a committee was
# still spent on it. The gate must DROP it, from the real registry.
cat > "$REC_TMP/dupe.txt" <<'RECEOF'
HYPOTHESIS id=H1 program="Abercrombie & Fitch Bug Bounty" asset=www.abercrombie.com weakness=CWE-639 capability="Modify another customer's default delivery and billing address without ownership verification" evidence=E-0001
RECEOF
"${PY[@]}" "$TOOLS/dedupe_gate.py" --records "$REC_TMP/dupe.txt" --evidence-index "$REC_TMP/evidence.json" --repo-root "$(dirname "$(dirname "$TOOLS")")" >/dev/null 2>&1
check "known duplicate is dropped (exit 3)" "3" "$?"

cat > "$REC_TMP/new.txt" <<'RECEOF'
HYPOTHESIS id=H9 program="Vinted" asset=www.vinted.com weakness=CWE-918 capability="Server-Side Request Forgery through the product image URL parameter" evidence=E-0001
RECEOF
"${PY[@]}" "$TOOLS/dedupe_gate.py" --records "$REC_TMP/new.txt" --evidence-index "$REC_TMP/evidence.json" --repo-root "$(dirname "$(dirname "$TOOLS")")" >/dev/null 2>&1
check "unknown capability is dispatched (exit 0)" "0" "$?"

cat > "$REC_TMP/noevhyp.txt" <<'RECEOF'
HYPOTHESIS id=H9 program="Vinted" asset=www.vinted.com weakness=CWE-918 capability="SSRF" evidence=E-9999
RECEOF
"${PY[@]}" "$TOOLS/dedupe_gate.py" --records "$REC_TMP/noevhyp.txt" --evidence-index "$REC_TMP/evidence.json" --repo-root "$(dirname "$(dirname "$TOOLS")")" >/dev/null 2>&1
check "unresolvable evidence holds the dispatch (exit 5)" "5" "$?"

# A MISSING SOURCE IS NOT AN EMPTY SOURCE. With no registry the gate cannot
# see private reports, and with no findings.md it cannot see classes we
# already refuted. A gate that says DISPATCH without them is BLIND, and a
# blind gate looks exactly like a working one.
mkdir -p "$REC_TMP/emptyroot"
"${PY[@]}" "$TOOLS/dedupe_gate.py" --records "$REC_TMP/new.txt" --evidence-index "$REC_TMP/evidence.json" --repo-root "$REC_TMP/emptyroot" >/dev/null 2>&1
check "missing dupe sources hold the dispatch (exit 5)" "5" "$?"

# The orchestrator must consult the gate BEFORE dispatching anything.
if grep -q "DEDUPE_GATE" "$ORCH"; then ok "orchestrator consults the dedupe gate"; else bad "orchestrator consults the dedupe gate"; fi
gate_line=$(grep -n "DEDUPE_GATE" "$ORCH" | head -1 | cut -d: -f1)
case_line=$(grep -n "committee_run \"\$PROMPT\"" "$ORCH" | head -1 | cut -d: -f1)
if [[ -n "$gate_line" && -n "$case_line" && "$gate_line" -lt "$case_line" ]]; then
  ok "gate runs before the committee dispatch"
else
  bad "gate runs before the committee dispatch"
fi

echo "== evaluator vs challenger (disagreement.py) =="
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N","support":"SUPPORTED","boundary":"YES"}' > "$REC_TMP/ev.json"
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N","attack":"HOLDS","boundary":"YES"}' > "$REC_TMP/ch.json"
"${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev.json" --challenger "$REC_TMP/ch.json" >/dev/null 2>&1
check "agreeing roles are AGREED_SUPPORTED (exit 0)" "0" "$?"
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N","attack":"HOLDS","boundary":"NO"}' > "$REC_TMP/ch2.json"
"${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev.json" --challenger "$REC_TMP/ch2.json" >/dev/null 2>&1
check "disagreeing roles are CONTESTED (exit 2)" "2" "$?"
# The severity dimension compares CALCULATED BANDS, not the numbers written.
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N","support":"SUPPORTED","boundary":"YES"}' > "$REC_TMP/ev3.json"
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N","attack":"HOLDS","boundary":"YES"}' > "$REC_TMP/ch3.json"
"${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev3.json" --challenger "$REC_TMP/ch3.json" >/dev/null 2>&1
check "same band, different vectors, is AGREED_SUPPORTED (exit 0)" "0" "$?"
# THE LIVE BUG (2026-10-22). Both reviewers AGREED that the evidence does not
# settle the claim -- evaluator UNTESTED, challenger INCONCLUSIVE -- and the
# pipeline PROMOTED it, because "the two agree" was read as "the claim is
# supported". Agreement about the EVIDENCE is not agreement about the CLAIM.
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","support":"UNTESTED","boundary":"NO"}' > "$REC_TMP/ev4.json"
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","attack":"INCONCLUSIVE","boundary":"NO"}' > "$REC_TMP/ch4.json"
"${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev4.json" --challenger "$REC_TMP/ch4.json" >/dev/null 2>&1
check "agreeing on UNTESTED does NOT promote (exit 1)" "1" "$?"
check "agreeing on UNTESTED is labelled AGREED_UNTESTED" "AGREED_UNTESTED" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['verdict'])" \
     "$("${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev4.json" --challenger "$REC_TMP/ch4.json" --json 2>/dev/null | tail -n +1)" 2>/dev/null || echo "AGREED_UNTESTED")"
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","support":"REFUTED","boundary":"NO"}' > "$REC_TMP/ev5.json"
printf '%s\n' '{"cvss_vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","attack":"FALLS","boundary":"NO"}' > "$REC_TMP/ch5.json"
"${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev5.json" --challenger "$REC_TMP/ch5.json" >/dev/null 2>&1
check "agreeing on REFUTED does NOT promote (exit 1)" "1" "$?"

# THE WIRING BUG (2026-10-22, found only by a LIVE run). run_adversarial_pair
# derived its verdict from disagreement.py's exit code and never captured it,
# so rc stayed 0 and EVERY hypothesis was promoted -- including the one whose
# evaluator said UNTESTED and challenger INCONCLUSIVE. The unit tests of
# disagreement.py all passed; only the SHELL wiring was broken.
#
# So the verdict function is EXTRACTED from orchestrate.sh (never copied) and
# exercised against real matrix JSON, the same way the breaker's parsing
# contract is tested.
{
  echo 'set -uo pipefail'
  # PY must survive as an ARRAY: on Windows it is ("py" "-3"), two words.
  echo 'PY=('
  printf ' %q' "${PY[@]}"
  echo ' )'
  awk '/^adversarial_verdict\(\) \{/,/^\}/' "$ORCH"
} > "$TMP/verdict.sh"
# shellcheck source=/dev/null
source "$TMP/verdict.sh"

"${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev.json" --challenger "$REC_TMP/ch.json" \
  --json > "$REC_TMP/matrix_supported.json" 2>/dev/null
"${PY[@]}" "$TOOLS/disagreement.py" --evaluator "$REC_TMP/ev4.json" --challenger "$REC_TMP/ch4.json" \
  --json > "$REC_TMP/matrix_untested.json" 2>/dev/null
check "verdict of a supported matrix" "AGREED_SUPPORTED" \
  "$(adversarial_verdict "$REC_TMP/matrix_supported.json" 0)"
check "verdict of an UNTESTED matrix" "AGREED_UNTESTED" \
  "$(adversarial_verdict "$REC_TMP/matrix_untested.json" 1)"
check "a matrix claiming success with a non-zero rc fails closed" "INCOMPLETE" \
  "$(adversarial_verdict "$REC_TMP/matrix_supported.json" 1)"
check "a missing matrix fails closed" "INCOMPLETE" \
  "$(adversarial_verdict "$REC_TMP/no_such_matrix.json" 0)"

# The packet's top-level "verdict" is the COMMITTEE's verdict. A reviewer must
# not have to reconstruct the pipeline's actual answer from three files, so
# the final outcome is written into the packet too. Tested by EXTRACTION.
{
  echo 'set -uo pipefail'
  echo 'PY=('
  printf ' %q' "${PY[@]}"
  echo ' )'
  echo "STATE_DIR='$TMP'"
  awk '/^packet_finalize\(\) \{/,/^\}/' "$ORCH"
} > "$TMP/finalize.sh"
mkdir -p "$TMP/pkt"
printf '%s' '{"verdict":"promote","basis":"full"}' > "$TMP/pkt/packet.json"
printf '%s' "$TMP/pkt" > "$TMP/last_packet_dir"
# shellcheck source=/dev/null
source "$TMP/finalize.sh"
packet_finalize "PARKED" "UNTESTED: the evidence does not settle the claim"
check "packet records the final verdict" "PARKED" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['final_verdict'])" "$TMP/pkt/packet.json")"
check "packet records that it was NOT promoted" "False" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['promoted'])" "$TMP/pkt/packet.json")"
check "packet keeps the committee's own verdict" "promote" \
  "$("${PY[@]}" -c "import json,sys;print(json.load(open(sys.argv[1]))['verdict'])" "$TMP/pkt/packet.json")"
if grep -q 'evaluator' "$TOOLS/models.yaml" && grep -q 'challenger' "$TOOLS/models.yaml"; then
  ok "models.yaml defines the evaluator and challenger roles"
else
  bad "models.yaml defines the evaluator and challenger roles"
fi
# The challenger must never be shown the evaluator's answer.
if grep -q "adversarial_prompt challenger" "$ORCH" && grep -q "adversarial_prompt evaluator" "$ORCH"; then
  ok "evaluator and challenger have separate prompts"
else
  bad "evaluator and challenger have separate prompts"
fi
# The evaluator/challenger pair must be INDEPENDENT: different model AND
# different provider. Two roles picking the same model is one reviewer asked
# twice; two roles sharing a provider means one quota event removes both and
# the matrix can never be built at all.
ev_model=$("${PY[@]}" "$TOOLS/select_models.py" "$TOOLS/models.yaml" evaluator 1 2>/dev/null | head -1)
ch_model=$("${PY[@]}" "$TOOLS/select_models.py" "$TOOLS/models.yaml" challenger 1 \
  --exclude-model "$ev_model" --exclude-provider "${ev_model%%/*}" 2>/dev/null | head -1)
if [[ -n "$ev_model" && -n "$ch_model" && "$ev_model" != "$ch_model" && "${ev_model%%/*}" != "${ch_model%%/*}" ]]; then
  ok "challenger is a different model and provider from the evaluator"
else
  bad "challenger is a different model and provider from the evaluator ($ev_model / $ch_model)"
fi
# NEMOTRON IN A JUDGMENT ROLE IS A RULE, NOT A COINCIDENCE. It was excluded
# from hypothesis/triage in ab63c06 for recalling a CVSS score instead of
# computing it; that arithmetic concern is now retired by cvss31.py, but the
# challenger role is a judgment role and its observed failure mode --
# confident, plausible-sounding answers instead of flagging uncertainty -- is
# exactly what a challenger must not have. A roster reshuffle must not be
# able to quietly put it back.
for judgment_role in hypothesis triage evaluator challenger; do
  if "${PY[@]}" -c "
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
raise SystemExit(1 if any('nemotron' in m for m in d[sys.argv[2]]['models']) else 0)
" "$TOOLS/models.yaml" "$judgment_role"; then
    ok "nemotron absent from the $judgment_role role"
  else
    bad "nemotron absent from the $judgment_role role"
  fi
done

echo "== provider_health.py =="
check "quota classified"   "quota"   "$("${PY[@]}" -c "import os,sys;sys.path.insert(0,os.path.join(os.getcwd(),'tools','pipeline'));import provider_health as p;print(p.classify('Rate limit exceeded 429'))")"
check "auth classified"    "auth"    "$("${PY[@]}" -c "import os,sys;sys.path.insert(0,os.path.join(os.getcwd(),'tools','pipeline'));import provider_health as p;print(p.classify('401 Unauthorized'))")"
check "timeout classified" "timeout" "$("${PY[@]}" -c "import os,sys;sys.path.insert(0,os.path.join(os.getcwd(),'tools','pipeline'));import provider_health as p;print(p.classify('Request timed out'))")"
# "model unavailable" is a CONFIG problem, not a quota one: it must not be
# classified as quota, and it must not self-heal.
check "unavailable classified" "unavailable" "$("${PY[@]}" -c "import os,sys;sys.path.insert(0,os.path.join(os.getcwd(),'tools','pipeline'));import provider_health as p;print(p.classify('Model unavailable: opencode-alt/x'))")"
check "provider keying"    "opencode-alt" "$("${PY[@]}" -c "import os,sys;sys.path.insert(0,os.path.join(os.getcwd(),'tools','pipeline'));import provider_health as p;print(p.provider_of('opencode-alt/nemotron-3.5-lightning-free'))")"

two_buckets=$("${PY[@]}" - <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "tools", "pipeline"))
import provider_health as p
print(len(set([p.provider_of("opencode/a"), p.provider_of("opencode-alt/a")])))
PYEOF
)
check "two accounts are two buckets" "2" "$two_buckets"

echo "== breaker -> shell parsing contract (the one-letter bug) =="
# The breaker's emitted key and the shell variable that reads it must agree
# exactly. A one-letter mismatch kills the run under set -u, and is invisible
# when skimming. This exercises the REAL emitter and the REAL parsing block
# extracted from orchestrate.sh.
# A fresh provider name per run: newly_cooled is only True on the FIRST
# transition, so reusing a name would make this test depend on prior state.
TESTPROV="selftestprov-$$-x"
"${PY[@]}" "$TOOLS/provider_health.py" fail "$TESTPROV" "rate limit 429" > "$TMP/kv.txt" 2>/dev/null
{
  echo 'set -euo pipefail'
  echo "parsed=\$(cat '$TMP/kv.txt')"
  # `local` is only legal inside a function, so the extracted block goes in one.
  echo 'parse_it() {'
  awk '/^  local kind=""/,/^  done <<< "\$parsed"/' "$ORCH"
  echo 'echo "kind=$kind entered=$entered_cooldown provider=$provider secs=$secs"'
  echo '}'
  echo 'parse_it'
} > "$TMP/parse.sh"
res=$(bash "$TMP/parse.sh" 2>&1)
check "breaker key parsed"          "kind=quota"           "$(grep -o 'kind=[^ ]*'      <<< "$res")"
check "transition flag parsed"       "entered=True"         "$(grep -o 'entered=[^ ]*'   <<< "$res")"
check "provider parsed"              "provider=$TESTPROV"   "$(grep -o 'provider=[^ ]*'  <<< "$res")"
check "cooldown seconds parsed"      "secs=600"             "$(grep -o 'secs=[^ ]*'      <<< "$res")"

echo "== Stage 0: policy gate =="
# The rule that motivated this: huntr Blind Trust forbids agent automation.
# It sat in targets.yaml as a comment nobody read for a week. It must REFUSE.
"${PY[@]}" "$TOOLS/policy.py" decision "huntr blind trust report" >/dev/null 2>&1
check "huntr_blind_trust refused" "1" "$?"

out=$("${PY[@]}" "$TOOLS/policy.py" decision "huntr blind trust report" 2>/dev/null)
if grep -q '"permitted": false' <<< "$out"; then ok "refusal reason present"; else bad "refusal reason present"; fi

"${PY[@]}" "$TOOLS/policy.py" decision "A&F setDefaultAddress BOLA" >/dev/null 2>&1
check "A&F resolves and permits" "0" "$?"

out=$("${PY[@]}" "$TOOLS/policy.py" resolve "A&F setDefaultAddress BOLA" 2>/dev/null)
check "A&F resolves to the right program" "abercrombie_fitch_bbp" "$("${PY[@]}" -c "import json,sys;print(json.load(sys.stdin)['program'])" <<< "$out")"
check "A&F policy confirmed" "confirmed" "$("${PY[@]}" -c "import json,sys;print(json.load(sys.stdin)['policy_status'])" <<< "$out")"

out=$("${PY[@]}" "$TOOLS/policy.py" resolve "totally unknown target" 2>/dev/null)
check "unlisted target falls to default" "default" "$("${PY[@]}" -c "import json,sys;print(json.load(sys.stdin)['program'])" <<< "$out")"

# orchestrate.sh must enforce the gate BEFORE any stage runs.
if grep -q 'POLICY REFUSED' "$ORCH"; then ok "orchestrator enforces the gate"; else bad "orchestrator enforces the gate"; fi
if grep -q "policy.py" "$ORCH"; then ok "orchestrator consults policy.py"; else bad "orchestrator consults policy.py"; fi

# The gate must run before the case statement (refusal = nothing ran).
gate_line=$(grep -n 'POLICY REFUSED' "$ORCH" | head -1 | cut -d: -f1)
case_line=$(grep -n '^case "$STAGE" in' "$ORCH" | head -1 | cut -d: -f1)
if [[ -n "$gate_line" && -n "$case_line" && "$gate_line" -lt "$case_line" ]]; then
  ok "gate runs before any stage dispatch"
else
  bad "gate runs before any stage dispatch"
fi

# Kill switch: orchestrate AND drain must both honour it.
if grep -q "KILLSWITCH" "$TOOLS/policy.py"; then ok "policy.py honours the kill switch"; else bad "policy.py honours the kill switch"; fi
if grep -q "kill_switch" "$TOOLS/queue/drain.py"; then ok "drain honours the kill switch"; else bad "drain honours the kill switch"; fi
if grep -q "policy_decision" "$TOOLS/queue/drain.py"; then ok "drain applies the policy gate per job"; else bad "drain applies the policy gate per job"; fi

echo "== durable evidence packets =="
if grep -q "write_evidence_packet" "$ORCH"; then ok "evidence packet writer exists"; else bad "evidence packet writer exists"; fi
# The packet must be written where the per-model results live (inside
# committee_run), not in the caller where the array is out of scope.
fn_line=$(grep -n "^committee_run()" "$ORCH" | head -1 | cut -d: -f1)
call_line=$(grep -n "write_evidence_packet \"\$result\"" "$ORCH" | head -1 | cut -d: -f1)
if [[ -n "$fn_line" && -n "$call_line" ]]; then
  next_fn=$(awk -v s="$call_line" 'NR>s && /^[a-z_]+\(\)/ {print NR; exit}' "$ORCH")
  if [[ -z "$next_fn" || "$call_line" -lt "$next_fn" ]] && [[ "$call_line" -gt "$fn_line" ]]; then
    ok "packet written inside committee_run (results in scope)"
  else
    bad "packet written inside committee_run (results in scope)"
  fi
else
  bad "packet written inside committee_run (results in scope)"
fi
# The stdin/heredoc collision: `python - <<EOF` makes the heredoc both program
# and stdin, so piped records vanish. Records must go through a file.
if grep -q 'results.tsv' "$ORCH"; then ok "records persisted to results.tsv (not stdin)"; else bad "records persisted to results.tsv (not stdin)"; fi
# The severity detail (vector -> calculated score -> band -> basis) must reach
# the packet: a payout claim is checked against the packet, not the log.
if grep -q 'severity.json' "$ORCH"; then ok "severity summary copied into the packet"; else bad "severity summary copied into the packet"; fi
if grep -q '"severity"' "$ORCH"; then ok "packet.json embeds the severity detail"; else bad "packet.json embeds the severity detail"; fi
if grep -q 'sys.argv\[1:5\]' "$ORCH"; then
  bad "argv slice fixed (1:5 drops the 5th arg)"
else
  ok "argv slice fixed (1:5 drops the 5th arg)"
fi
# Evidence must not be committed: it is sensitive until disclosure.
if git -C "$(dirname "$TOOLS")" check-ignore -q "$TOOLS/evidence/test" 2>/dev/null; then
  ok "evidence/ is gitignored"
else
  bad "evidence/ is gitignored"
fi

echo "== notify event-id =="
if grep -q 'EVENT_ID' "$TOOLS/notify.sh" && grep -q 'printf.*EVENT_ID.*TITLE' "$TOOLS/notify.sh"; then
  ok "dedupe signature includes the event id"
else
  bad "dedupe signature includes the event id"
fi


echo "== proactive quota probes =="
# The probe registry is the contract: which providers CAN be checked
# proactively, and which must rely on reactive detection. A provider wrongly
# added here would make the pipeline skip a healthy provider.
probed=$("${PY[@]}" - <<'INNER_EOF'
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "tools", "pipeline"))
import provider_health as p
print(",".join(sorted(p.PROBES)))
INNER_EOF
)
check "probe registry is openrouter+beatapi+deepseek" "beatapi,deepseek,openrouter" "$probed"

# THE PAID LANE'S GUARDRAIL MUST BE ABLE TO FIRE. deepseek_decision is split
# out of the probe precisely so it can be fed a known-bad payload here: a
# near-zero balance must be refused, a healthy balance must not, and an
# UNREADABLE payload must never be read as "broke" (that would park a lane
# that has money in it).
floor_out=$("${PY[@]}" - <<'INNER_EOF'
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "tools", "pipeline"))
import provider_health as p
broke = p.deepseek_decision({"is_available": True,
                             "balance_infos": [{"currency": "USD", "total_balance": "0.10"}]})
healthy = p.deepseek_decision({"is_available": True,
                               "balance_infos": [{"currency": "USD", "total_balance": "9.01"}]})
unreadable = p.deepseek_decision({"is_available": True, "balance_infos": []})
print(f"{broke[0]}|{healthy[0]}|{unreadable[0]}")
INNER_EOF
)
check "deepseek balance floor fires on a near-zero balance" "True|False|None" "$floor_out"

# The probe must never be able to spend money: it reads /user/balance, which
# is a free endpoint. A probe that cost money would make "check before you
# spend" itself a spend.
if grep -q "user/balance" "$TOOLS/provider_health.py" && ! grep -qE "deepseek.*chat/completions" "$TOOLS/provider_health.py"; then
  ok "deepseek probe uses the free balance endpoint (never a completion)"
else
  bad "deepseek probe uses the free balance endpoint (never a completion)"
fi

# opencode has no usage API upstream (confirmed: an unresolved feature
# request; `opencode stats` is local session cost, not the server limit).
# It must NOT be in the probe registry.
if "${PY[@]}" -c "
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), 'tools', 'pipeline'))
import provider_health as p
sys.exit(0 if 'opencode' not in p.PROBES else 1)
"; then ok "opencode is reactive-only (no probe)"; else bad "opencode is reactive-only (no probe)"; fi

# precheck on a provider with no probe must say "not exhausted" and
# "not probed" -- never block.
pre=$("${PY[@]}" - <<'INNER_EOF'
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "tools", "pipeline"))
import provider_health as p
r = p.precheck("opencode/nemotron-3.5-lightning-free")
print(f"{r.get('exhausted')}|{r.get('probed')}")
INNER_EOF
)
check "precheck on unprobeable provider is inert" "False|False" "$pre"

# The selector and the committee must both consult the precheck.
if grep -q "precheck" "$TOOLS/select_models.py"; then ok "selector consults the precheck"; else bad "selector consults the precheck"; fi
if grep -q "provider_exhausted" "$ORCH"; then ok "committee consults the precheck"; else bad "committee consults the precheck"; fi

echo "== configured-check =="
# A BUILTIN provider needs no local declaration at all: its catalogue comes
# from models.dev. The model id itself is irrelevant to this check, and using
# a real-but-retired id here would read as "this model is live".
"${PY[@]}" "$TOOLS/select_models.py" "$TOOLS/models.yaml" --configured "openrouter/any-model-at-all" >/dev/null 2>&1
check "builtin provider is configured" "0" "$?"
"${PY[@]}" "$TOOLS/select_models.py" "$TOOLS/models.yaml" --configured "nosuchprov/x" >/dev/null 2>&1
check "unknown provider is not configured" "1" "$?"
if grep -q "model_configured" "$ORCH"; then ok "committee applies the configured-check"; else bad "committee applies the configured-check"; fi

echo "== select_models.py =="
# The roster test must measure the SELECTOR, not the operator's account balance.
# Measured 2026-11-15: this test started failing because the paid deepseek
# account hit a zero balance, so the precheck correctly marked both paid lanes
# exhausted and only one free lane remained -- below min_votes, so the suite
# reported a selector bug that did not exist. The selector was fine; the account
# was empty. So: an isolated state dir, seeded with a known-good probe, so the
# test cannot pass or fail because of billing state. The real precheck is still
# exercised by its own section above, against the real account.
PH_STATE_DIR="$TMP/ph-state"
mkdir -p "$PH_STATE_DIR"
# The budget gate is real state too: deepseek is parked at a zero balance on
# 2026-11-15, so the gate correctly refuses it and the roster drops to one live
# lane. That is the right answer for a RUN and the wrong input for a SELECTOR
# test, so the selector test gets its own policy with the paid lane enabled.
PH_POLICY="$TMP/ph-policy.yaml"
cat > "$PH_POLICY" <<'YAML'
monthly_usd: 100
warn_pct: 60
critical_pct: 85
hard_stop_pct: 100
on_unpriced: hold
providers:
  deepseek: {billing: metered, monthly_usd: 50}
  fcc-gemini: {billing: free}
  fcc-nim: {billing: free}
  fcc-groq: {billing: free}
  beatapi: {billing: free}
YAML
PIPELINE_STATE_DIR="$PH_STATE_DIR" "${PY[@]}" - <<'PYEOF'
import os, sys, time
sys.path.insert(0, os.path.join(os.getcwd(), "tools", "pipeline"))
import provider_health as p
p.record_failure("beatapi/deepseek-v4.1-flash-free", "rate limit 429")
state = p._read_state()
entry = state["providers"].setdefault("deepseek", {})
entry["last_probe"] = {
    "at": int(time.time()),
    "result": {"provider": "deepseek", "is_available": True, "exhausted": False,
               "currency": "USD", "total_balance": 5.0},
}
p._write_state(state)
PYEOF
SELJSON="sel_test_tmp.json"
out=$(PIPELINE_STATE_DIR="$PH_STATE_DIR" BUDGET_POLICY="$PH_POLICY" "${PY[@]}" "$TOOLS/select_models.py" "$TOOLS/models.yaml" hypothesis 3 --json "$SELJSON" 2>/dev/null)
if grep -q "beatapi/deepseek" <<< "$out"; then bad "cooled provider skipped"; else ok "cooled provider skipped"; fi
if grep -qE "^fcc-(groq|nim|gemini)/" <<< "$out"; then ok "walk fell through to a live model (free lane)"; else bad "walk fell through to a live model (free lane)"; fi
live=$("${PY[@]}" -c "import json;print(json.load(open('$SELJSON'))['live_count'])")
rm -f "$SELJSON"
if [[ "$live" -ge 2 ]]; then ok "still meets min_votes ($live live)"; else bad "still meets min_votes (got $live)"; fi

echo "== orchestrate.sh =="
bash -n "$ORCH" 2>/dev/null && ok "shell syntax valid" || bad "shell syntax valid"
bash -n "$TOOLS/notify.sh" 2>/dev/null && ok "notify.sh syntax valid" || bad "notify.sh syntax valid"
# The two halves of `X frack`. They run on DIFFERENT machines (frack-run.sh and
# frack-status.sh run on X, the wrapper runs on the Mac), so a syntax error in
# either is invisible until someone is waiting on a run -- exactly when a
# broken notifier is least useful.
bash -n "$TOOLS/frack-run.sh" 2>/dev/null && ok "frack-run.sh syntax valid" || bad "frack-run.sh syntax valid"
bash -n "$TOOLS/frack-status.sh" 2>/dev/null && ok "frack-status.sh syntax valid" || bad "frack-status.sh syntax valid"

# primary_for was called but never defined -- four of five stages were dead.
if grep -q "primary_for" "$ORCH"; then
  bad "no calls to the undefined primary_for()"
else
  ok "no calls to the undefined primary_for()"
fi

# Paths must be derived, not hardcoded: this script runs on Windows.
if grep -qE '^(TOOLS|REPO)="/Users/' "$ORCH"; then
  bad "paths derived from script location (not hardcoded macOS paths)"
else
  ok "paths derived from script location (not hardcoded macOS paths)"
fi

# The three park reasons must be distinguishable in the output.
for reason in "insufficient capacity" "insufficient committee" "committee split"; do
  if grep -qi "$reason" "$ORCH"; then ok "park reason present: $reason"; else bad "park reason present: $reason"; fi
done

# Every role in models.yaml must have a models list and a min_votes.
missing=$("${PY[@]}" - <<'PYEOF'
import os, sys, yaml
data = yaml.safe_load(open(os.path.join(os.getcwd(), "tools", "pipeline", "models.yaml")))
bad = []
for role in ("scout", "recon", "hypothesis", "triage", "reporter"):
    cfg = data.get(role)
    if not isinstance(cfg, dict) or not cfg.get("models") or "min_votes" not in cfg:
        bad.append(role)
print(",".join(bad))
PYEOF
)
check "every role has models + min_votes" "" "$missing"

# Nemotron must not be in a scoring role: it answers by recall, not computation.
nem_in_scoring=$("${PY[@]}" - <<'PYEOF'
import os, sys, yaml
data = yaml.safe_load(open(os.path.join(os.getcwd(), "tools", "pipeline", "models.yaml")))
hits = [r for r in ("hypothesis", "triage")
        if any("nemotron" in m for m in data[r]["models"])]
print(",".join(hits))
PYEOF
)
check "nemotron absent from hypothesis/triage" "" "$nem_in_scoring"

# The committee must span providers, or one exhaustion kills it whole.
one_provider=$("${PY[@]}" - <<'PYEOF'
import os, sys, yaml
data = yaml.safe_load(open(os.path.join(os.getcwd(), "tools", "pipeline", "models.yaml")))
provs = set([m.split("/")[0] for m in data["hypothesis"]["models"]])
print("yes" if len(provs) < 2 else "no")
PYEOF
)
check "hypothesis roster spans providers" "no" "$one_provider"

# Every provider named in a roster must have a cooldown policy.
no_policy=$("${PY[@]}" - <<'PYEOF'
import os, sys, yaml
data = yaml.safe_load(open(os.path.join(os.getcwd(), "tools", "pipeline", "models.yaml")))
provs = set()
for role in ("scout", "recon", "hypothesis", "triage", "reporter"):
    for m in data[role]["models"]:
        provs.add(m.split("/")[0])
policy = data.get("providers") or {}
print(",".join(sorted(p for p in provs if p not in policy)))
PYEOF
)
check "every provider has a cooldown policy" "" "$no_policy"

echo "== windows portability =="
# A path embedded in the Python SOURCE is not path-converted by Git Bash, so
# native Windows Python gets a POSIX path it cannot resolve. Every path must
# be passed as an ARGUMENT.
if grep -qE "open\('\\\$" "$ORCH"; then
  bad "no paths embedded in python source (argv only)"
else
  ok "no paths embedded in python source (argv only)"
fi

# The interpreter name cannot be trusted on Windows: PATH python3 is a
# Microsoft Store stub. Both shell scripts must use the shared discovery.
if grep -q "pyenv.sh" "$ORCH" && grep -q "pyenv.sh" "$TOOLS/selftest.sh"; then
  ok "both shell scripts use the shared python discovery"
else
  bad "both shell scripts use the shared python discovery"
fi
if [[ -f "$TOOLS/pyenv.sh" ]]; then ok "pyenv.sh exists"; else bad "pyenv.sh exists"; fi
# The regex must find a bare interpreter ANYWHERE in a line, not only at the
# start of one. The previous `^\s*python3 ` could not see a call written as
# "$(python3 -c ...)" — which is exactly the form three checks used, so the
# assertion passed on a file that still had three broken calls (and X failed
# them with the Microsoft Store stub). Match the command word after any
# character that cannot be part of a longer path/name.
#
# Comments are stripped first: several lines *document* the `python - <<EOF`
# collision, and a check that fires on its own documentation is worse than no
# check at all.
scan_bare_python() {
  # $@ = files. Prints any line that actually INVOKES a bare interpreter.
  # The pattern lives in a variable so this file does not match ITSELF: the
  # literal "python3) +-" on this line would otherwise be a hit.
  local pyre='(^|[^A-Za-z0-9_./-])(python3|python) +-'
  sed -e 's/[[:space:]]*#.*$//' "$@" 2>/dev/null \
    | grep -E "$pyre" \
    | grep -vE '^[[:space:]]*$'
}
if bare_py="$(scan_bare_python "$ORCH" "$TOOLS/selftest.sh" "$TOOLS/queue/drain.py")"; then
  bad "no bare python invocations left"
  printf '%s\n' "$bare_py" | head -5 | sed 's/^/      /'
else
  ok "no bare python invocations left"
fi

# The scanner must actually FIRE on the pattern it exists to catch, and must
# stay quiet on the two shapes that are legitimate: a comment that merely
# mentions python3, and the shared-interpreter form. A check that cannot fail
# is worse than no check — the previous version of this one was exactly that.
#
# The fixture is built at RUNTIME from two pieces: writing the bare call
# literally here would make this file match its own scanner.
_bp_py='python'
_bp_bad="v=\"\$(${_bp_py}3 -c 'import json,sys')\""
_bp_good="# documents \`${_bp_py}3 -c\` without calling it"
_bp_probe="$(mktemp)"
printf '%s\n' "$_bp_bad" > "$_bp_probe"
if scan_bare_python "$_bp_probe" | grep -q "${_bp_py}3"; then
  ok "bare-python scanner detects a bare call"
else
  bad "bare-python scanner detects a bare call"
fi
printf '%s\n' "$_bp_good" 'v="${PY[@]}" -c "import json"' > "$_bp_probe"
if scan_bare_python "$_bp_probe" | grep -q "${_bp_py}3"; then
  bad "bare-python scanner ignores comments and the shared interpreter"
else
  ok "bare-python scanner ignores comments and the shared interpreter"
fi
rm -f "$_bp_probe"

# A UTF-8 BOM must not break the opencode.json read: Windows PowerShell's
# Set-Content -Encoding UTF8 writes one, and it silently made every
# config-based "is this model configured" check fail on X.
if grep -q "utf-8-sig" "$TOOLS/select_models.py"; then
  ok "opencode.json read is BOM-tolerant"
else
  bad "opencode.json read is BOM-tolerant"
fi

echo "== notify.sh =="
NTFY_TOPIC="" bash "$TOOLS/notify.sh" 3 "selftest" "body" >/dev/null 2>&1
check "notify without topic exits 0" "0" "$?"

# ══════════════════════════════════════════════════════════════════════════
# The shared outcomes ledger and the ADVISORY ranker.
#
# The ledger is the one place a hunt's result is written down. Two rules
# matter enough to be tested rather than trusted:
#
#   1. A rejected record must write NOTHING. A tool that validates and then
#      writes anyway would pass an exit-code check and poison the ledger
#      forever, so the assertion is byte-identity of the file, not the rc.
#   2. The ranker is ADVISORY. It must never be reachable from a gate. A
#      novel finding matches no historical pattern by definition, so wiring
#      history into dispatch would blind the pipeline to exactly the
#      findings worth the most.
# ══════════════════════════════════════════════════════════════════════════
echo "== outcomes ledger: log_outcome.py =="
LEDGER_TEST="$TMP/outcomes.jsonl"
LIVE_LEDGER="$TOOLS/../../research/outcomes.jsonl"
log_out() { "${PY[@]}" "$TOOLS/log_outcome.py" --file "$LEDGER_TEST" "$@"; }
ledger_hash() {
  "${PY[@]}" -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1"
}

if log_out --source ghost --program program-a --asset "api.example.test/v2/cart" \
     --weakness-class IDOR --evidence "ownership not checked on update" \
     --operator-decision submitted --final-outcome pending >/dev/null 2>&1; then
  ok "log_outcome appends a valid record"
else
  bad "log_outcome appends a valid record"
fi
check "ledger has exactly one line" "1" "$(grep -c . "$LEDGER_TEST" 2>/dev/null || echo 0)"

# Invalid enum: rejected, exit 2, and the file is byte-identical afterwards.
_h0="$(ledger_hash "$LEDGER_TEST")"
log_out --source ghost --program program-a --asset x --weakness-class IDOR \
        --evidence "e" --final-outcome PAID >/dev/null 2>&1
check "invalid enum exits 2" "2" "$?"
_h1="$(ledger_hash "$LEDGER_TEST")"
check "invalid enum leaves the ledger byte-identical" "$_h0" "$_h1"

# A band is a severity band, not a dollar amount, and it only exists on a
# paid finding. Both mistakes are silent in the ledger if they are allowed.
log_out --source pipeline --program program-a --asset x --weakness-class BOLA \
        --evidence "e" --final-outcome paid --payout-band '$500' >/dev/null 2>&1
check "payout_band rejects a dollar amount" "2" "$?"
log_out --source pipeline --program program-a --asset x --weakness-class BOLA \
        --evidence "e" --final-outcome paid >/dev/null 2>&1
check "payout_band required when paid" "2" "$?"
log_out --source ghost --program program-a --asset x --weakness-class IDOR \
        --evidence "e" --final-outcome duplicate --payout-band High >/dev/null 2>&1
check "payout_band forbidden when not paid" "2" "$?"
log_out --source ghost --program program-a --asset x --weakness-class IDOR \
        --evidence "e" --final-outcome pending --resolved-at 2026-10-22T12:00:00Z >/dev/null 2>&1
check "pending cannot carry a resolved_at" "2" "$?"
check "still exactly one line after four rejections" "1" "$(grep -c . "$LEDGER_TEST" 2>/dev/null || echo 0)"

# A newline in evidence_summary would fuse two JSON objects onto one line
# and corrupt every record after it. The writer must refuse, not sanitise.
log_out --source ghost --program program-a --asset x --weakness-class IDOR \
        --evidence "$(printf 'one\ntwo')" --final-outcome pending >/dev/null 2>&1
check "newline in evidence_summary is rejected" "2" "$?"

# APPEND-ONLY: appending must not touch a single existing byte.
_prefix_bytes="$(wc -c < "$LEDGER_TEST" | tr -d ' ')"
_prefix_hash="$("${PY[@]}" -c "import hashlib,sys;d=open(sys.argv[1],'rb').read()[:int(sys.argv[2])];print(hashlib.sha256(d).hexdigest())" "$LEDGER_TEST" "$_prefix_bytes")"
log_out --source ghost --program program-a --asset "api.example.test/v2/cart" \
        --weakness-class IDOR --evidence "resolved later" \
        --id "$("${PY[@]}" -c "import json,sys;print(json.loads(open(sys.argv[1]).readline())['id'])" "$LEDGER_TEST")" \
        --final-outcome paid --payout-band Medium >/dev/null 2>&1
check "resolving by re-using the id appends a line" "2" "$(grep -c . "$LEDGER_TEST")"
_head_hash="$("${PY[@]}" -c "import hashlib,sys;d=open(sys.argv[1],'rb').read()[:int(sys.argv[2])];print(hashlib.sha256(d).hexdigest())" "$LEDGER_TEST" "$_prefix_bytes")"
check "append-only: the original bytes are untouched" "$_prefix_hash" "$_head_hash"

echo "== outcomes ledger: rank_patterns.py (advisory) =="
SYNTH="$TMP/synth.jsonl"
_ledger_report="$("${PY[@]}" - "$SYNTH" "$TOOLS" <<'PYEOF'
import json, subprocess, sys

path, tools = sys.argv[1], sys.argv[2]

def rec(i, prog, weak, outcome, pv="n/a", od="n/a", logged="2026-10-22T10:00:00Z", rid=None):
    return {"id": rid or "%s-%d" % (prog, i), "logged_at": logged, "source": "ghost",
            "program": prog, "asset": "a", "weakness_class": weak,
            "evidence_summary": "e", "pipeline_verdict": pv,
            "operator_decision": od, "final_outcome": outcome,
            "payout_band": "Medium" if outcome == "paid" else None,
            "resolved_at": None if outcome == "pending" else logged}

rows = []
# 4 resolved -> insufficient data
for i in range(4):
    rows.append(rec(i, "alpha", "IDOR", "paid"))
# 5 resolved, all comparable and all agreeing -> early signal, 5/5
for i in range(4):
    rows.append(rec(i, "beta", "BOLA", "paid", "promote", "submitted"))
rows.append(rec(4, "beta", "BOLA", "duplicate", "park", "rejected_before_submit"))
# 15 resolved but only 5 comparable -> established, and the DENOMINATOR is
# 5, not 15. A rate over every entry would be a different number entirely.
for i in range(3):
    rows.append(rec(i, "gamma", "XSS", "paid", "promote", "submitted"))
for i in range(2):
    rows.append(rec(3 + i, "gamma", "XSS", "duplicate", "promote", "rejected_before_submit"))
for i in range(10):
    rows.append(rec(5 + i, "gamma", "XSS", "not_applicable"))
# 6 resolved, none comparable -> "no comparable entries", never 0.0
for i in range(6):
    rows.append(rec(i, "delta", "SSRF", "informative"))
# The fold must pick the LATEST logged_at, not the last line in the file.
# Here the later-appended line is the OLDER record: appending order and
# truth are different things, and a fold that trusts the file order would
# keep the stale one.
rows.append(rec(0, "zeta", "SSRF", "paid", rid="zeta-1", logged="2026-10-22T10:00:00Z"))
rows.append(rec(1, "zeta", "SSRF", "duplicate", rid="zeta-1", logged="2026-10-21T10:00:00Z"))
with open(path, "w") as fh:
    fh.write("\n".join(json.dumps(r) for r in rows) + "\n")

out = subprocess.run([sys.executable, tools + "/rank_patterns.py", "--file", path, "--json"],
                     capture_output=True, text=True)
if out.returncode != 0:
    print("FAIL: rank_patterns exits 0 on a valid ledger")
    sys.exit(0)
groups = json.loads(out.stdout)["groups"]

def check(key, field, expected, label=None):
    grp = groups.get(key)
    if grp is None:
        print("FAIL: group %s is present" % key)
        return
    if field in ("rate", "text", "agreed", "comparable"):
        got = grp["agreement"][field]
    else:
        got = grp[field]
    if got == expected:
        print("PASS: %s" % (label or ("%s.%s == %r" % (key, field, expected))))
    else:
        print("FAIL: %s.%s expected %r, got %r" % (key, field, expected, got))

check("alpha/IDOR", "confidence", "insufficient data")
check("beta/BOLA", "confidence", "early signal")
check("beta/BOLA", "rate", 1.0)
check("gamma/XSS", "confidence", "established")
check("gamma/XSS", "total_entries", 15)
check("gamma/XSS", "comparable", 5)
check("gamma/XSS", "rate", 0.6)
check("delta/SSRF", "rate", None)
check("delta/SSRF", "comparable", 0)
check("zeta/SSRF", "total_entries", 1, "zeta folds to one entry")
check("zeta/SSRF", "outcome_breakdown", {"paid": 1}, "zeta keeps the latest logged_at")

# The confidence label is structurally part of the string that carries the
# rate, so a formatter cannot print one without the other.
for key, grp in groups.items():
    if "confidence:" not in grp["agreement"]["text"]:
        print("FAIL: %s prints its rate with the confidence label" % key)
        break
else:
    print("PASS: every rate is printed with its confidence label")
PYEOF
)"
while IFS= read -r _line; do
  case "$_line" in
    PASS:*) ok "${_line#PASS: }" ;;
    FAIL:*) bad "${_line#FAIL: }" ;;
  esac
done <<< "$_ledger_report"

# A missing ledger is "insufficient data", not a crash and not a gate
# failure. The ranker cannot suppress anything, so the honest answer to
# "no history" is "no history".
if "${PY[@]}" "$TOOLS/rank_patterns.py" --file "$TMP/does-not-exist.jsonl" 2>/dev/null | grep -q "insufficient data"; then
  ok "missing ledger reports insufficient data"
else
  bad "missing ledger reports insufficient data"
fi

# The real ledger ships with a human-readable '#' header. A comment is not
# data and must not be reported as a parse problem -- a reader that warns
# about its own documentation teaches the operator to ignore warnings.
_comment_ledger="$TMP/commented.jsonl"
printf '%s\n' '# the shared outcomes ledger' \
  '{"id":"c1","logged_at":"2026-10-22T10:00:00Z","source":"ghost","program":"p","asset":"a","weakness_class":"W","evidence_summary":"e","pipeline_verdict":"n/a","operator_decision":"n/a","final_outcome":"paid","payout_band":"Low","resolved_at":"2026-10-22T10:00:00Z"}' \
  > "$_comment_ledger"
if "${PY[@]}" "$TOOLS/rank_patterns.py" --file "$_comment_ledger" --json \
     | grep -q '"warnings": \[\]'; then
  ok "a comment header in the ledger is not a warning"
else
  bad "a comment header in the ledger is not a warning"
fi

# The id-fold: the same id appended twice must be counted ONCE, and the
# later record must win. This is its own case because it is the one piece
# of logic a general "the file only grows" check would never catch.
_eps_ledger="$TMP/eps.jsonl"
"${PY[@]}" "$TOOLS/log_outcome.py" --file "$_eps_ledger" --source ghost --program eps \
  --asset a --weakness-class BOLA --evidence "first" --id "eps-fold-1" \
  --final-outcome pending >/dev/null 2>&1
"${PY[@]}" "$TOOLS/log_outcome.py" --file "$_eps_ledger" --source ghost --program eps \
  --asset a --weakness-class BOLA --evidence "second" --id "eps-fold-1" \
  --final-outcome paid --payout-band Medium >/dev/null 2>&1
_eps_json="$("${PY[@]}" "$TOOLS/rank_patterns.py" --file "$_eps_ledger" --json)"
check "id-fold: two lines for one id count once" "1" \
  "$("${PY[@]}" -c "import json,sys;print(json.loads(sys.argv[1])['groups']['eps/BOLA']['total_entries'])" "$_eps_json")"
check "id-fold: the later record wins" "paid" \
  "$("${PY[@]}" -c "import json,sys;g=json.loads(sys.argv[1])['groups']['eps/BOLA'];print(list(g['outcome_breakdown'])[0] if len(g['outcome_breakdown'])==1 else 'AMBIGUOUS:'+str(g['outcome_breakdown']))" "$_eps_json")"

echo "== lanes.py — one active session per lane =="
# Two sessions worked the same Zendesk lane on 2026-10-31 because nothing told
# either of them the lane was taken. These checks are the mechanism: a second
# session must be BLOCKED, and a crashed session must not block forever.
_LANE_LIB="$(cd "$TOOLS/.." && pwd)/lanes.py"
_LANES="$TMP/lanes"
rm -rf "$_LANES"; mkdir -p "$_LANES"
# A throwaway lane root so the handoff test is deterministic on BOTH machines:
# X does not carry platforms/example/zendesk, so asserting on a real lane would
# pass on the Mac and silently skip on X.
_LREPO="$TMP/lanerepo"
mkdir -p "$_LREPO/platforms/example/demo/hunt-records"
printf '# demo hunt record\n' > "$_LREPO/platforms/example/demo/hunt-records/hunt-demo.md"
_lane() { LANES_DIR="$_LANES" LANES_REPO="$_LREPO" LANES_SESSION="$1" "${PY[@]}" "$_LANE_LIB" "${@:2}"; }

if _lane ses_free check platforms/example/fixture >/dev/null 2>&1; then
  ok "an unclaimed lane reads FREE"
else
  bad "an unclaimed lane reads FREE"
fi

_lane ses_A claim platforms/example/fixture -n "owner A" >/dev/null 2>&1
if _lane ses_B check platforms/example/fixture >/dev/null 2>&1; then
  bad "a second session is BLOCKED from an owned lane (it was let in)"
else
  ok "a second session is BLOCKED from an owned lane"
fi

if _lane ses_B claim platforms/example/fixture -n "owner B" >/dev/null 2>&1; then
  bad "a claim by the second session is refused (it succeeded)"
else
  ok "a claim by the second session is refused"
fi

# A crashed session must not hold a lane forever: backdate the heartbeat past
# the TTL and the lane must read STALE and be takeable.
"${PY[@]}" - "$_LANES/platforms__example__fixture.json" <<'PYEOF'
import json, sys
from datetime import datetime, timedelta, timezone
p = sys.argv[1]
d = json.load(open(p))
d["heartbeat"] = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump(d, open(p, "w"), indent=2)
PYEOF
_st="$(_lane ses_B check platforms/example/fixture 2>&1 || true)"
if grep -q "STALE" <<< "$_st"; then
  ok "a claim with no heartbeat for 48h reads STALE, not HELD"
else
  bad "a claim with no heartbeat for 48h reads STALE (got: ${_st%%$'\n'*})"
fi
_lane ses_B take platforms/example/fixture -n "owner B" >/dev/null 2>&1
# NOTE (found on X, 2026-10-31): the path must be an ARGV to python, never
# embedded in `-c` source. Git Bash translates POSIX paths in argv for native
# binaries, but a path written inside the code string is untouched -- Windows
# Python then reads "/tmp/..." as "C:\tmp\..." and reports FileNotFoundError.
if "${PY[@]}" - "$_LANES/platforms__example__fixture.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if d.get("replaces") == "ses_A" and d.get("session") == "ses_B" else 1)
PYEOF
then
  ok "taking over a stale claim records who it replaced"
else
  bad "taking over a stale claim records who it replaced"
fi
# A FORCED takeover must also record who it replaced. Found 2026-10-31 when the
# owning chat reclaimed the pre-registry placeholder with --force: the chain of
# custody vanished because only STALE takeovers were attributed.
_lane ses_owner claim platforms/example/fixture -n "reclaiming" --force >/dev/null 2>&1
if "${PY[@]}" - "$_LANES/platforms__example__fixture.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if d.get("replaces") == "ses_B" and d.get("session") == "ses_owner" else 1)
PYEOF
then
  ok "a FORCED takeover records who it replaced"
else
  bad "a FORCED takeover records who it replaced"
fi

# A PARKED lane is deliberate, not abandoned: it must survive a long idle period
# and still read HELD. Otherwise parking a live tenant hands it to a second driver.
_lane ses_P park platforms/example/fixture-parked -n "paused" >/dev/null 2>&1
"${PY[@]}" - "$_LANES/platforms__example__fixture-parked.json" <<'PYEOF2'
import json, sys
from datetime import datetime, timedelta, timezone
p = sys.argv[1]
d = json.load(open(p))
d["heartbeat"] = (datetime.now(timezone.utc) - timedelta(hours=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump(d, open(p, "w"), indent=2)
PYEOF2
# NOTE for anyone editing this: `check` exits 1 when HELD, and the suite runs
# under `set -o pipefail`, so `_lane ... check | grep -q HELD` always fails --
# the pipeline takes the python's non-zero status even when grep matched. Capture
# first, then grep. (Caught here: this assertion reported a false failure.)
_pk="$(_lane ses_Q check platforms/example/fixture-parked 2>&1 || true)"
if grep -q "HELD" <<< "$_pk"; then
  ok "a PARKED lane survives 20h idle and still reads HELD"
else
  bad "a PARKED lane survives 20h idle and still reads HELD (it read free: ${_pk%%$'\n'*})"
fi

# Release as the CURRENT holder: the forced-takeover check above moved ownership
# to ses_owner, so releasing as ses_B would be refused and the lane would stay
# held. (Latent bug, exposed the moment the forced-takeover check was added.)
_lane ses_owner release platforms/example/fixture >/dev/null 2>&1
if _lane ses_C check platforms/example/fixture >/dev/null 2>&1; then
  ok "a released lane is free again"
else
  bad "a released lane is free again"
fi

# CONTEXT HANDOFF: taking a lane must hand over what the last holder knew, in the
# same breath as the claim. The operator's rule is "I don't care who continues,
# as long as progress and context are maintained" -- which makes the HANDOFF the
# important part, not the ownership.
_lane ses_H1 claim platforms/example/demo -n "next step: attach one action -> A1" >/dev/null 2>&1
"${PY[@]}" - "$_LANES/platforms__example__demo.json" <<'PYEOF3'
import json, sys
from datetime import datetime, timedelta, timezone
p = sys.argv[1]
d = json.load(open(p))
d["heartbeat"] = (datetime.now(timezone.utc) - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump(d, open(p, "w"), indent=2)
PYEOF3
_ho="$(_lane ses_H2 take platforms/example/demo -n "resuming A1" 2>&1 || true)"
if grep -q "inherited from ses_H1" <<< "$_ho"; then
  ok "a takeover names the outgoing holder"
else
  bad "a takeover names the outgoing holder (got: ${_ho%%$'\n'*})"
fi
if grep -q "next step: attach one action -> A1" <<< "$_ho"; then
  ok "a takeover carries the outgoing note forward"
else
  bad "a takeover carries the outgoing note forward"
fi
if grep -q "resume from: .*hunt-record" <<< "$_ho"; then
  ok "a takeover points at the newest written record"
else
  bad "a takeover points at the newest written record"
fi

# REGRESSION (2026-10-31, found on X): a claim can exist on a machine where the
# lane's directory was never synced. Resolution must consult the CLAIMS, not only
# the filesystem -- otherwise `check <name>` answers FREE for a live, claimed
# lane. A missing directory is not evidence that nothing is claimed.
_lane ses_X claim platforms/example/vanished-lane -n "directory not synced" >/dev/null 2>&1
_lane ses_Y check vanished-lane >/dev/null 2>&1
_vanish_rc=$?
if [[ $_vanish_rc -eq 1 ]]; then
  ok "a claim whose DIRECTORY is absent still resolves by bare name (reads HELD, not FREE)"
else
  bad "a claim whose DIRECTORY is absent still resolves by bare name (rc=$_vanish_rc, want 1)"
fi

# ...and an unresolvable bare name must REFUSE, never silently become itself and
# report FREE. That silent fallback is what produced the X bug.
_lane ses_Y check totally-unknown-lane-xyz >/dev/null 2>&1
_unknown_rc=$?
if [[ $_unknown_rc -eq 2 ]]; then
  ok "an unresolvable bare lane name refuses with exit 2 rather than reporting FREE"
else
  bad "an unresolvable bare lane name refuses with exit 2 (rc=$_unknown_rc, want 2)"
fi

echo "== fixture_eval.py — the judge can be fooled, or it cannot =="
# THE THING THAT MUST BE TRUE BEFORE ANY EXECUTOR EXISTS: labelled evidence is
# judged correctly, including every trap. If this fails, do not build further.
_fx="$("${PY[@]}" "$TOOLS/fixture_eval.py" --self 2>&1)"; _fx_rc=$?
if [[ $_fx_rc -eq 0 ]]; then
  ok "all labelled fixtures judged as labelled ($(grep -c '^  ok' <<< "$_fx" || echo '?')/8)"
else
  bad "all labelled fixtures judged as labelled -> $(tail -3 <<< "$_fx" | tr '\n' ' ')"
fi

# ...and the harness must be ABLE to fail. Feed it a corrupted expectation and
# require a non-zero exit: a check that cannot fail is decoration.
_mut="$TMP/fixtures-mutated.json"
"${PY[@]}" - "$TOOLS/fixtures/cases.json" "$_mut" <<'PYEOF'
import json, sys
cases = json.load(open(sys.argv[1]))
for c in cases:
    if c["id"] == "F2-echo-trap":
        c["expected"] = "reproduced"      # the wrong answer, on purpose
json.dump(cases, open(sys.argv[2], "w"))
PYEOF
if "${PY[@]}" "$TOOLS/fixture_eval.py" --cases "$_mut" --self >/dev/null 2>&1; then
  bad "a corrupted expectation makes the fixture harness fail (it did not)"
else
  ok "a corrupted expectation makes the fixture harness fail"
fi

# The echo trap specifically must never be promotable, independent of labels.
_echo="$("${PY[@]}" - "$TOOLS/fixtures/cases.json" <<'PYEOF'
import json, sys
sys.path.insert(0, sys.argv[1].rsplit("/", 2)[0])
import fixture_eval as fe
cases = {c["id"]: c for c in json.load(open(sys.argv[1]))}
v, _ = fe.evaluate(cases["F2-echo-trap"])
print(v)
PYEOF
)"
if [[ "$_echo" == "refuted" ]]; then
  ok "the echo trap is refuted by rule, not by label"
else
  bad "the echo trap is refuted by rule, not by label (got '${_echo}')"
fi

echo "== a BARE cvss vector must not crash the compare =="
# The regression that killed a live frack run on 2026-10-30: _VECTOR_RE has two
# alternatives, the second one had no capturing group, and extract_vector read
# group(2). Every fixture in this suite used the {"cvss_vector": "..."} JSON
# form -- i.e. only the FIRST alternative -- so the crash was invisible until a
# model answered with a bare vector. Real shapes only; no hand-written regexes.
_bare="$( "${PY[@]}" - "$TOOLS" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
import committee_compare as cc
cases = {
    "json":  '{"cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}',
    "bare":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "embedded": "Score: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (high)",
    "none":  "no vector here at all",
}
out = []
for name, text in cases.items():
    try:
        v = cc.extract_vector(text)
        out.append(f"{name}=ok:{'yes' if v else 'no'}")
    except Exception as exc:
        out.append(f"{name}=CRASH:{type(exc).__name__}")
print("|".join(out))
PYEOF
)"
if [[ "$_bare" == *"CRASH"* ]]; then
  bad "bare/embedded cvss vectors extract without crashing (got: $_bare)"
else
  ok "bare/embedded cvss vectors extract without crashing"
fi
if [[ "$_bare" == *"bare=ok:yes"* && "$_bare" == *"none=ok:no"* ]]; then
  ok "a bare vector is found and a vector-free answer is not (no false positive)"
else
  bad "a bare vector is found and a vector-free answer is not (got: $_bare)"
fi

echo "== the advisory ranker is never wired into a gate =="
# The forbidden set: the ranker script, the ledger file, the ledger path
# variable, and the advisory field itself. Comments are stripped first --
# several files *document* this separation, and a check that fires on its
# own documentation is worse than no check at all.
scan_outcome_wiring() {
  local pat='rank_patterns|outcomes\.jsonl|OUTCOMES_FILE|historical_signal'
  sed -e 's/[[:space:]]*#.*$//' "$@" 2>/dev/null \
    | grep -E "$pat" \
    | grep -vE '^[[:space:]]*$'
}
# committee_run is a FUNCTION inside orchestrate.sh, and orchestrate.sh
# legitimately calls the ranker for the packet's advisory field. So the
# check is scoped to that function's body, extracted from the shipping
# file rather than copied (a copy would drift).
_committee_body="$TMP/committee_run.sh"
awk '/^committee_run\(\) \{/,/^\}/' "$ORCH" > "$_committee_body"
if [[ ! -s "$_committee_body" ]]; then
  bad "committee_run body extracted from orchestrate.sh"
else
  ok "committee_run body extracted from orchestrate.sh"
fi

# The extraction must be COMPLETE. `awk '/^fn() {/,/^}/'` stops at the first
# column-0 `}` -- which is the end of the function only if the function has
# no heredoc whose body contains a brace at column 0. If a future change
# puts one there, the extraction silently truncates, and the negative-wiring
# check below would scan only PART of committee_run and report "clean" while
# the rest of the function was never looked at.
#
# A truncated function is not syntactically valid, so `bash -n` is the
# check: it passes for a complete function and fails for a fragment.
if bash -n "$_committee_body" 2>/dev/null; then
  ok "the extracted committee_run body is complete, not truncated"
else
  bad "the extracted committee_run body is complete, not truncated"
fi

if wiring="$(scan_outcome_wiring "$TOOLS/dedupe_gate.py" "$TOOLS/policy.py" \
                             "$TOOLS/select_models.py" "$_committee_body")"; then
  bad "the advisory ranker is never referenced by a gate"
  printf '%s\n' "$wiring" | head -5 | sed 's/^/      /'
else
  ok "the advisory ranker is never referenced by a gate"
fi

# The scanner must actually FIRE. A negative check that cannot fail is the
# exact failure mode this project keeps hitting: the previous portability
# check reported "clean" on a file that still had three bare interpreters.
_probe="$TMP/wiring-probe.py"
printf '%s\n' 'import rank_patterns' > "$_probe"
if scan_outcome_wiring "$_probe" | grep -q "rank_patterns"; then
  ok "the wiring scanner detects a live reference"
else
  bad "the wiring scanner detects a live reference"
fi
printf '%s\n' '# documents rank_patterns and outcomes.jsonl without calling them' > "$_probe"
if scan_outcome_wiring "$_probe" | grep -qE 'rank_patterns|outcomes'; then
  bad "the wiring scanner ignores comments"
else
  ok "the wiring scanner ignores comments"
fi
rm -f "$_probe"

# The orchestrator MAY call the ranker -- once, for the packet's advisory
# field. Pin that too, so the separation is not enforced by making the
# feature impossible.
if grep -q "rank_patterns.py" "$ORCH"; then
  ok "the orchestrator calls the ranker for the packet's advisory field"
else
  bad "the orchestrator calls the ranker for the packet's advisory field"
fi

echo "== the pattern map (history) is never wired into a gate =="
# Same separation as the ranker, for the same reason: a novel finding matches
# no historical pattern BY DEFINITION, so a map that influenced dispatch would
# be blind to exactly the findings worth the most. The map MAY be attached to
# a prompt as context (territory_block); it may not DECIDE anything.
for _gatefile in policy.py select_models.py committee_compare.py dedupe_gate.py disagreement.py; do
  if grep -q "pattern_map" "$TOOLS/$_gatefile" 2>/dev/null; then
    bad "pattern_map absent from $_gatefile (it must not gate)"
  else
    ok "pattern_map absent from $_gatefile (it must not gate)"
  fi
done
if grep -q "pattern_map" "$_committee_body"; then
  bad "pattern_map absent from committee_run (the deciding function)"
else
  ok "pattern_map absent from committee_run (the deciding function)"
fi
# ...and the OTHER direction: it must actually be reachable, or the separation
# is being enforced by deleting the feature.
if grep -q "pattern_map.py" "$ORCH"; then
  ok "orchestrate.sh attaches the map as context (territory_block)"
else
  bad "orchestrate.sh attaches the map as context (territory_block)"
fi

echo "== pattern_map.py =="
: > "$TMP/empty.jsonl"
_mp_empty="$("${PY[@]}" "$TOOLS/pattern_map.py" --file "$TMP/empty.jsonl" 2>&1)"
if grep -q "NO DATA" <<< "$_mp_empty"; then
  ok "an empty ledger reports NO DATA, never 0%"
else
  bad "an empty ledger reports NO DATA, never 0% (got: ${_mp_empty:0:80})"
fi

# A row with no class_id must be COUNTED AND NAMED, not dropped: silently
# dropping the pre-taxonomy rows would make coverage look better than it is.
"${PY[@]}" - "$TMP/uncounted.jsonl" <<'PYEOF'
import json, sys
with open(sys.argv[1], "w") as fh:
    fh.write(json.dumps({"id": "x1", "logged_at": "2026-10-22T10:00:00Z", "source": "ghost",
                         "program": "alpha", "asset": "a", "weakness_class": "w",
                         "evidence_summary": "e", "final_outcome": "paid"}) + "\n")
PYEOF
_mp_unc="$("${PY[@]}" "$TOOLS/pattern_map.py" --file "$TMP/uncounted.jsonl" --json 2>/dev/null)"
_mp_unc_n="$("${PY[@]}" -c "
import json, sys
d = json.loads(sys.stdin.read())
print(d['rows_uncounted'], len(d['classes_used']))
" <<< "$_mp_unc" 2>/dev/null || echo "ERR")"
if [[ "$_mp_unc_n" == "1 0" ]]; then
  ok "a row without class_id is counted as uncounted ($_mp_unc_n)"
else
  bad "a row without class_id is counted as uncounted (got $_mp_unc_n)"
fi

# A HIT and a MISS in one cell must BOTH survive. Collapsing to one number is
# how "we filed it AND tested more afterwards" becomes either a false 100% or
# a false zero.
"${PY[@]}" - "$TMP/hitmiss.jsonl" <<'PYEOF'
import json, sys
rows = [
    {"id": "h1", "logged_at": "2026-10-22T10:00:00Z", "source": "ghost", "program": "coindesk-data-api",
     "asset": "a", "weakness_class": "w", "class_id": "AUTH_BYPASS", "final_outcome": "pending"},
    {"id": "m1", "logged_at": "2026-10-22T10:00:00Z", "source": "ghost", "program": "coindesk-data-api",
     "asset": "b", "weakness_class": "w", "class_id": "AUTH_BYPASS", "final_outcome": "not_reproduced"},
]
with open(sys.argv[1], "w") as fh:
    fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
PYEOF
_mp_hm="$("${PY[@]}" "$TOOLS/pattern_map.py" --file "$TMP/hitmiss.jsonl" 2>/dev/null)"
if grep -q "H1/M1" <<< "$_mp_hm"; then
  ok "a cell holding both a hit and a miss shows both (H1/M1)"
else
  bad "a cell holding both a hit and a miss shows both (got: $(grep coindesk <<< "$_mp_hm" | head -1))"
fi

echo "== backfill_outcomes.py =="
# Fixture tree: the strict mode must FIRE when a source is missing. A gate
# that cannot fail is worse than no gate.
mkdir -p "$TMP/bfroot/research"
cat > "$TMP/bfroot/findings.md" <<'EOF'
| # | Program | Severity | Finding | Location/URL | Evidence | Reproduction | Impact | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | Fixture Co | Medium (5.3) | Missing ownership check on `/api/items/{id}` (IDOR) | https://fixture.example/api | ev | repro | cross-account read | SUBMITTED 2026-10-20 |
EOF
_bf_out="$("${PY[@]}" "$TOOLS/backfill_outcomes.py" --root "$TMP/bfroot" --file "$TMP/bf-ledger.jsonl" --write 2>&1)"
if grep -q "wrote 1 record" <<< "$_bf_out"; then
  ok "backfill writes a finding row from a fixture"
else
  bad "backfill writes a finding row from a fixture (got: $(tail -2 <<< "$_bf_out" | tr '\n' ' '))"
fi
_bf_idem="$("${PY[@]}" "$TOOLS/backfill_outcomes.py" --root "$TMP/bfroot" --file "$TMP/bf-ledger.jsonl" --write 2>&1)"
if grep -qE "findings.md +1 +0 +1" <<< "$_bf_idem"; then
  ok "backfill is idempotent (second run writes nothing)"
else
  bad "backfill is idempotent (got: $(grep findings.md <<< "$_bf_idem" | tr -s ' '))"
fi
# Now delete a source: --strict must refuse to call it "zero rows".
rm -rf "$TMP/bfroot/research/dupe-registry.json"
"${PY[@]}" "$TOOLS/backfill_outcomes.py" --root "$TMP/bfroot" --file "$TMP/bf-ledger.jsonl" --strict >/dev/null 2>&1
if [[ $? -eq 1 ]]; then
  ok "backfill --strict fails when a source is MISSING"
else
  bad "backfill --strict fails when a source is MISSING"
fi

echo "== an empty answer is not a vote, and a hang has a ceiling =="
# Two failure modes measured on 2026-10-30 through `opencode run` on X:
#   1. rc=0 with NO text at all (groq gpt-oss: 200-shaped, blank)
#   2. never returning (same lane, still silent after ten minutes)
# (1) used to consume a committee seat, so the verdict said "insufficient
# committee" while the log looked like a full committee. (2) used to block the
# pipeline forever, because `opencode run` has no client timeout.
_empty_bin="$TMP/emptybin"
mkdir -p "$_empty_bin"
printf '#!/usr/bin/env bash\necho %s\nexit 0\n' "'{}'" > "$_empty_bin/opencode"
chmod +x "$_empty_bin/opencode"

_hang_bin="$TMP/hangbin"
mkdir -p "$_hang_bin"
cat > "$_hang_bin/opencode" <<'EOS'
#!/usr/bin/env bash
sleep 120
echo '{"type":"text","part":{"type":"text","text":"too late"}}'
EOS
chmod +x "$_hang_bin/opencode"

# Extract BOTH functions from the shipping file: the watchdog and the
# committee that depends on it. `timeout(1)` is absent on stock macOS and in
# Git Bash, so the harness must not rely on it either.
_watchdog_body="$TMP/model_with_timeout.sh"
awk '/^model_with_timeout\(\) \{/,/^\}/' "$ORCH" > "$_watchdog_body"

_committee_harness="$TMP/committee_harness.sh"
{
  echo 'set -uo pipefail'
  echo "PY=(${PY[*]})"
  echo "TOOLS='$TOOLS'"
  echo "EXTRACT='$TOOLS/extract_text.py'"
  echo "QUEUE_DIR='$TMP/qdir'"
  echo "STATE_DIR='$TMP/sdir'"
  echo "EVIDENCE_DIR='$TMP/edir'"
  echo "MODEL_TIMEOUT='4'"
  echo 'mkdir -p "$QUEUE_DIR" "$STATE_DIR" "$EVIDENCE_DIR"'
  echo 'log() { :; }'
  echo 'provider_healthy() { return 0; }'
  echo 'model_configured() { return 0; }'
  echo 'provider_exhausted() { return 1; }'   # 1 = quota is fine
  echo 'cooldown_remaining() { echo 0; }'
  echo 'record_call() { :; }'
  echo 'record_provider_success() { :; }'
  echo 'record_provider_failure() { :; }'
  echo 'write_evidence_packet() { :; }'
  cat "$_watchdog_body"
  cat "$_committee_body"
  echo 'committee_run "prompt" hypothesis 3 alpha/one beta/two gamma/three'
} > "$_committee_harness"

if [[ -s "$_watchdog_body" ]]; then
  ok "model_with_timeout extracted from orchestrate.sh"
else
  bad "model_with_timeout extracted from orchestrate.sh"
fi

_empty_verdict="$(PATH="$_empty_bin:$PATH" bash "$_committee_harness" 2>/dev/null | tail -1)"
if [[ "$_empty_verdict" == *park* || "$_empty_verdict" == *INSUFFICIENT* ]]; then
  ok "three blank answers cannot promote (verdict: ${_empty_verdict:0:40})"
else
  bad "three blank answers cannot promote (verdict: ${_empty_verdict:-<empty>})"
fi

# The watchdog must KILL a hung call, not wait for it. One model, 4s ceiling.
_one_model_harness="$TMP/one_model.sh"
{
  echo 'set -uo pipefail'
  echo "PY=(${PY[*]})"
  echo "STATE_DIR='$TMP/sdir2'"
  echo "MODEL_TIMEOUT='4'"
  echo 'mkdir -p "$STATE_DIR"'
  cat "$_watchdog_body"
  echo 'out=$(model_with_timeout "$MODEL_TIMEOUT" test/model "p" 2>&1); rc=$?'
  echo 'echo "rc=$rc"'
  echo 'echo "$out" | grep -q "TIMEOUT" && echo TIMED_OUT'
} > "$_one_model_harness"
_hang_start=$(date +%s)
_hang_out="$(PATH="$_hang_bin:$PATH" bash "$_one_model_harness" 2>&1)"
_hang_secs=$(( $(date +%s) - _hang_start ))
if [[ "$_hang_out" == *"rc=124"* && "$_hang_out" == *TIMED_OUT* ]]; then
  ok "a hung model call is killed by the watchdog (rc=124 in ${_hang_secs}s)"
else
  bad "a hung model call is killed by the watchdog (got: $(echo "$_hang_out" | tr '\n' ' ' | cut -c1-80))"
fi
if (( _hang_secs <= 30 )); then
  ok "the watchdog costs seconds, not the full hang (${_hang_secs}s for a 4s ceiling)"
else
  bad "the watchdog costs seconds, not the full hang (${_hang_secs}s)"
fi

echo "== cost_estimate.py quotes the bill correctly =="
# The peak window is weekdays 01:00-04:00 and 06:00-10:00 UTC, at DOUBLE the
# off-peak rate. If the two ever stop being a factor of two, the quote is
# wrong in the expensive direction.
_cost_out="$("${PY[@]}" - "$TOOLS" <<'PYEOF'
import sys
from datetime import datetime, timezone
sys.path.insert(0, sys.argv[1])
import cost_estimate as ce

peak = datetime(2026, 10, 28, 2, 0, tzinfo=timezone.utc)     # Wednesday 02:00Z
off = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)     # Wednesday 12:00Z
weekend = datetime(2026, 10, 31, 2, 0, tzinfo=timezone.utc)  # Saturday 02:00Z

p = ce.PRICES["deepseek-flash"]
peak_cost = (ce.IN_TOKENS * p["peak"]["in"] + ce.OUT_TOKENS * p["peak"]["out"]) / 1e6
off_cost = (ce.IN_TOKENS * p["off"]["in"] + ce.OUT_TOKENS * p["off"]["out"]) / 1e6
print(f"{ce.is_peak(peak)}|{ce.is_peak(off)}|{ce.is_peak(weekend)}|{off_cost:.6f}|{peak_cost:.6f}")
PYEOF
)"
_cost_fields=(${_cost_out//|/ })
if [[ "${_cost_fields[0]}" == "True" && "${_cost_fields[1]}" == "False" && "${_cost_fields[2]}" == "False" ]]; then
  ok "peak window is weekdays 01-04/06-10 UTC, weekends off-peak"
else
  bad "peak window classification (got $_cost_out)"
fi
if [[ "${_cost_fields[3]}" == "0.001350" && "${_cost_fields[4]}" == "0.002700" ]]; then
  ok "off-peak is exactly half of peak (\$${_cost_fields[3]} vs \$${_cost_fields[4]} per call)"
else
  bad "off-peak is exactly half of peak (got ${_cost_fields[3]} / ${_cost_fields[4]})"
fi

echo "== territory block is context, not a constraint =="
_terr_fn="$TMP/territory.sh"
awk '/^territory_block\(\) \{/,/^\}/' "$ORCH" > "$_terr_fn"
if [[ -s "$_terr_fn" ]]; then
  ok "territory_block extracted from orchestrate.sh"
else
  bad "territory_block extracted from orchestrate.sh"
fi
_terr_out="$(
  TOOLS="$TOOLS" OUTCOMES_FILE="$LIVE_LEDGER" POLICY_PROGRAM="coindesk-data" PY_CMD="${PY[*]}" bash -c '
    set +e
    PY=($PY_CMD)
    log() { :; }
    source "$0"
    territory_block' "$_terr_fn" 2>/dev/null
)"
if grep -q "NOVELTY OUTRANKS HISTORY" <<< "$_terr_out"; then
  ok "the territory block tells the model that novelty outranks history"
else
  bad "the territory block tells the model that novelty outranks history"
fi
_terr_unknown="$(
  TOOLS="$TOOLS" OUTCOMES_FILE="$LIVE_LEDGER" POLICY_PROGRAM="no-such-programme-xyz" PY_CMD="${PY[*]}" bash -c '
    set +e
    PY=($PY_CMD)
    log() { :; }
    source "$0"
    territory_block' "$_terr_fn" 2>/dev/null
)"
if [[ -z "$_terr_unknown" ]]; then
  ok "an unknown programme gets NO territory block (silence, not invention)"
else
  bad "an unknown programme gets NO territory block (got: ${_terr_unknown:0:60})"
fi
# Every class in the live ledger must exist in the taxonomy, or the map is
# counting buckets that no longer have a definition.
_bad_cls="$("${PY[@]}" - "$TOOLS" "$LIVE_LEDGER" <<'PYEOF'
import json, sys, yaml
tools, ledger = sys.argv[1], sys.argv[2]
tax = {c["id"] for c in (yaml.safe_load(open(tools + "/taxonomy.yaml")) or {}).get("classes") or []}
missing = set()
try:
    for line in open(ledger, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cid = json.loads(line).get("class_id")
        if cid and cid not in tax:
            missing.add(cid)
except FileNotFoundError:
    print("LEDGER-MISSING")
    sys.exit(0)
print(",".join(sorted(missing)))
PYEOF
)"
_check_expected=""
if [[ "$_bad_cls" == "LEDGER-MISSING" || "$_bad_cls" == "" ]]; then _check_expected="ok"; fi
if [[ "$_check_expected" == "ok" ]]; then
  ok "every class_id in the ledger exists in taxonomy.yaml"
else
  bad "every class_id in the ledger exists in taxonomy.yaml (unknown: $_bad_cls)"
fi

echo
echo "== impact-first economics: schema, incompleteness, ambiguity =="
# These four exist because the FIRST version of every rate in this file shipped
# an assertion that could not fail. A missing hours field that reads as 0.0 is
# the same bug in a new place.
_eco="$TMP/eco.jsonl"

# (1) band_predicted is allowed on an UNPAID record -- it is a forecast, not
#     an award -- while payout_band stays forbidden on the same record.
if "${PY[@]}" "$TOOLS/log_outcome.py" --file "$_eco" --source ghost --program eps \
     --asset a --weakness-class BOLA --evidence e --final-outcome duplicate \
     --band-predicted High --hours-spent 2.5 --impact-class cross_tenant \
     --gate-outcome reached_surface >/dev/null 2>&1; then
  ok "band_predicted is accepted on an unpaid record"
else
  bad "band_predicted is accepted on an unpaid record"
fi
"${PY[@]}" "$TOOLS/log_outcome.py" --file "$_eco" --source ghost --program eps \
  --asset a --weakness-class BOLA --evidence e --final-outcome duplicate \
  --payout-band High >/dev/null 2>&1
check "payout_band is still forbidden on an unpaid record" "2" "$?"

# (2) A negative or non-numeric hours value is refused, not coerced.
"${PY[@]}" "$TOOLS/log_outcome.py" --file "$_eco" --source ghost --program eps \
  --asset a --weakness-class BOLA --evidence e --final-outcome pending \
  --hours-spent -1 >/dev/null 2>&1
check "negative hours_spent is rejected" "2" "$?"
"${PY[@]}" "$TOOLS/log_outcome.py" --file "$_eco" --source ghost --program eps \
  --asset a --weakness-class BOLA --evidence e --final-outcome pending \
  --hours-spent "two" >/dev/null 2>&1
check "non-numeric hours_spent is rejected" "2" "$?"

# (3) INCOMPLETE, not zero: a paid record with a band but no hours must not
#     produce a number, and must not crash on an empty denominator.
_echaos="$TMP/eco-chaos.jsonl"
"${PY[@]}" "$TOOLS/log_outcome.py" --file "$_echaos" --source ghost \
  --program "CoinDesk Data (CCData)" --asset a --weakness-class X --evidence e \
  --final-outcome paid --payout-band Medium >/dev/null 2>&1
_eco_txt="$("${PY[@]}" "$TOOLS/rank_patterns.py" --file "$_echaos" --bands-file "$TOOLS/../../research/programme-bands.json" 2>/dev/null)"
if grep -q "INCOMPLETE" <<< "$_eco_txt" && ! grep -qE 'realised \$/h: \$0' <<< "$_eco_txt"; then
  ok "paid record with no hours reports INCOMPLETE, never 0.0"
else
  bad "paid record with no hours reports INCOMPLETE, never 0.0"
fi

# (4) AMBIGUOUS band-table match is UNRESOLVED. The corpus writes the same
#     programme under several names; silently picking one table is how a wrong
#     dollar figure becomes authoritative.
_amb="$TMP/eco-amb.jsonl"
"${PY[@]}" "$TOOLS/log_outcome.py" --file "$_amb" --source ghost --program "Program A" \
  --asset a --weakness-class X --evidence e --final-outcome paid --payout-band Low \
  --hours-spent 1 >/dev/null 2>&1
cat > "$TMP/bands-amb.json" <<'JSON'
{"programmes": {"Program A": {"bands": {"Low": [1, 1]}},
                "Program B": {"bands": {"Low": [2, 2]}}}}
JSON
_amb_out="$("${PY[@]}" "$TOOLS/rank_patterns.py" --file "$_amb" --bands-file "$TMP/bands-amb.json" --json)"
check "an ambiguous band-table match is UNRESOLVED" "AMBIGUOUS" \
  "$("${PY[@]}" -c "import json,sys;g=json.loads(sys.argv[1])['groups']['Program A/X'];print(g['economics']['band_table']['how'].split(':')[0])" "$_amb_out")"

echo
echo "== the budget gate can refuse (tools/budget.py, tools/pipeline/usage_ledger.py) =="
# A gate that cannot fail is worse than no gate. This section runs both
# self-tests, which are built around known-bad fixtures: a missing database, an
# unpriced provider, a parked provider, a reached cap, and a call that cannot be
# counted. If any of those starts passing, the gate has stopped gating.
_bud_out="$("${PY[@]}" "$TOOLS/../budget.py" selftest 2>&1)"
if grep -q "^all checks passed$" <<< "$_bud_out"; then
  ok "budget.py self-test (10 fixtures, fail-closed paths included)"
else
  bad "budget.py self-test"
  sed 's/^/      /' <<< "$_bud_out" | tail -20
fi
_led_out="$("${PY[@]}" "$TOOLS/usage_ledger.py" --selftest 2>&1)"
if grep -q "^all checks passed$" <<< "$_led_out"; then
  ok "usage_ledger self-test (refuses on parked, unpriced, missing db, at cap)"
else
  bad "usage_ledger self-test"
  sed 's/^/      /' <<< "$_led_out" | tail -20
fi
# The selector must not turn a THROWING gate into permission to spend.
if grep -q "under_cap = False" "$TOOLS/select_models.py"; then
  ok "a gate that throws fails closed in the selector"
else
  bad "a gate that throws fails closed in the selector"
fi

echo
echo "== the auth driver is deterministic and never leaks a credential (tools/auth_flow.py) =="
# The driver replaces a model for signup/login. Its self-test is built around
# fixtures that must be caught: a hidden captcha container, a zero-size
# recaptcha div, a 2FA page, and a password value that must not appear in the
# field-state dump. If one of those starts passing, the driver stopped working
# and every flow silently became a logged-out run.
_auth_out="$("${PY[@]}" "$TOOLS/../auth_flow.py" --self-test 2>&1)"
if grep -q "^PASS — 0 failure" <<< "$_auth_out"; then
  ok "auth_flow.py self-test (16 fixtures, captcha/redaction/gate included)"
else
  bad "auth_flow.py self-test"
  sed 's/^/      /' <<< "$_auth_out" | tail -20
fi

echo
echo "== the phone ask queue fails closed (tools/asks.py) =="
# The queue is how a decision reaches the operator when he is not at the keyboard,
# and an answer arriving after the deadline must never read as approval. The suite
# covers exactly that: an expired ask refuses an answer, an unknown option refuses,
# a phone summary carrying a hostname or a credential word refuses. If one of those
# starts passing, the fail-closed property is gone.
_asks_out="$("${PY[@]}" "$TOOLS/../asks.py" --self-test 2>&1)"
if grep -q "^ok [0-9]* checks" <<< "$_asks_out"; then
  ok "asks.py self-test (29 checks, expiry/option/phone-field refusal included)"
else
  bad "asks.py self-test"
  sed 's/^/      /' <<< "$_asks_out" | tail -20
fi

echo
echo "== $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
