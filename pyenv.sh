#!/usr/bin/env bash
# pyenv.sh — locate a WORKING python and expose it as the PY array.
#
# Sourced by orchestrate.sh and selftest.sh. Deliberately a separate file
# rather than a copy of the logic in each: the same block pasted twice is the
# same drift risk as the breaker's emitted key vs the shell that read it.
#
# The interpreter NAME cannot be trusted:
#   - On Windows the PATH `python` and `python3` are Microsoft Store stubs
#     that print "Python was not found; run without arguments to install
#     from the Microsoft Store" and exit 9009 without running anything.
#   - There is no python3.exe at all on Windows -- only `python.exe` and the
#     `py` launcher.
#   - Git Bash resolves `python3` to the same WindowsApps stub, so a bash
#     script on X breaks at every python call unless it probes.
#
# So: probe each candidate by ACTUALLY RUNNING it, then fall back to the
# standard Windows install location. PY is an array so `py -3` survives as
# two words.

PY=()

_pyenv_find() {
  local _cand
  for _cand in python3 python; do
    if command -v "$_cand" >/dev/null 2>&1 && "$_cand" -c "import sys" >/dev/null 2>&1; then
      PY=("$_cand")
      return 0
    fi
  done
  if command -v py >/dev/null 2>&1 && py -3 -c "import sys" >/dev/null 2>&1; then
    PY=(py -3)
    return 0
  fi
  for _cand in \
    "$LOCALAPPDATA/Programs/Python/Python313/python.exe" \
    "$LOCALAPPDATA/Programs/Python/Python312/python.exe" \
    "/c/Users/$USERNAME/AppData/Local/Programs/Python/Python313/python.exe" \
    "/c/Users/$USERNAME/AppData/Local/Programs/Python/Python312/python.exe"
  do
    if [[ -x "$_cand" ]] && "$_cand" -c "import sys" >/dev/null 2>&1; then
      PY=("$_cand")
      return 0
    fi
  done
  return 1
}

if ! _pyenv_find; then
  echo "ERROR: no working python found (tried python3, python, py -3, and the standard Windows install path)." >&2
  echo "       Install Python 3 and ensure PyYAML is available: py -3 -m pip install pyyaml" >&2
  exit 4
fi
