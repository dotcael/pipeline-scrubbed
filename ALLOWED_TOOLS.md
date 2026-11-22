# ALLOWED_TOOLS.md — Passive / local-tool whitelist for the bug-bounty pipeline

## Philosophy
The pipeline never invites active scanners (httpx, nuclei, ffuf, sqlmap, dalfox, katana)
against authenticated targets. All tools below are **passive**, **offline**, or **read-only**.
Any active scanning must be performed by the operator hand-running tools, never via agent invocation.

## Passive data sources (always allowed)
- `waybackurls` — archive.org URL extraction; output feeds Scout/Recon only
- `gau` (GetAllUrls) — Common Crawl + Wayback; passive only
- `unfurl`, `uro` — URL parsing/triage/dedup; offline pattern matching
- `anew` — append-new-urls; idempotent file writing
- `gf` — pattern matching (cli, xss, ssti, etc.) on already-collected URLs
- `qsreplace` — URL parameter replacement; hypothesis generation on archived data
- `jq`, `gron` — JSON manipulation; offline analysis
- `sqlite3` — local DB queries; evidence registry, dupe-registry
- `pandoc` — markdown-to-report formatting; operator-side only

## Local file analysis (always allowed, no network)
- `dupecheck.py` — Hacktivity census + policy miner (reads local cache + public API only)
- `redact_evidence.py` — token/secret redaction; read-only original, write next to it
- `safari_cookies.py` — read own Safari cookies; read-only, own-account only
- `sd_ids.py` — own-account identifiers; read-only
- `gitleaks` / `trufflehog` — **public repos only** (e.g. Omarchy GitHub repo); no target scanning
- `jq`, `gron` — local JSON/DOM analysis

## Added 2026-11-18 (tool addendum tier — scope-gated like everything else)
- `clairvoyance` (pip) — GraphQL schema recovery with introspection disabled; probe-side
  complement to `gql_persisted_hash.py`. Target-facing: needs the lane gate and operator GO.
- `inql` (pip) — GraphQL schema exploration/mutation generation; inside Burp or standalone.
  Target-facing: lane gate + GO.
- `lief` (pip) — APK native-lib repack for Frida Gadget injection (Quest/mobile stack).
  Local artifact analysis; no target traffic by itself.
- `frida`, `frida-tools`, `objection` (pip) — runtime instrumentation, unpinning.
  Device/target-facing: sitting-card-driven, operator GO for every attach.
- `~/bin/subfinder` (v2.17.0, checksum-verified) — passive-only subdomain enumeration.
  Passive; still runs behind the lane targets gate. Feeds fast-band asset maps only.
- `~/bin/interactsh-client` / `interactsh-server` (v1.4.1, checksum-verified) — out-of-band
  callback confirmation. Client use is per-lane, ONLY where the programme's scope explicitly
  allows OOB callbacks; server self-host on X (pending, see `tools/x_stack_pull.sh`).
- `mitmproxy` (already installed) — headless traffic capture, wireguard mode for the Quest.
- `cdp_net_drive.py` now fills null POST bodies via `Network.getRequestPostData`
  (self-tested; the orphan-diff fix).

## Still NOT installed (ruling 2026-11-18)
- `ffuf` — rejected by ledger (82% dead conventional-sweep history); revisit only when a
  sitting card names a specific lens-flagged path.
- Watch-list, unverified: pentester-mcp, rea-plus, Pentest-AI, XBOW, BBOT — provenance and
  gate self-test required before any install (supply-chain rule).

## Local model / Ollama (always allowed, zero API cost)
- `qwen2.5-coder:14b` — local Codex-style completion on X
- `deepseek-r1:14b` — local reasoning on X
- `xploiter` — local model on X
- Python scripts under `tools/` (dupecheck, redact, etc.)
- `jq`, `gron`, `sqlite3` — as above

## EXPLICITLY FORBIDDEN in pipeline code (will cause guard to trigger)
- `httpx`, `hakrawler`, `kotlinx`, `curl` (agent-invoked live requests)
- `nuclei`, `dalfox`, `ffuf`, `sqlmap`, `xsser` — active vulnerability scanners
- Any tool that sends HTTP requests to live/authenticated targets
- Platform APIs without explicit operator credential env-var

## How the guard works
`orchestrate.sh` reads this file (future: parses tool references from prompts).
If any prompt or agent output references a forbidden tool, the stage is aborted and
the operator is notified: `"Forbidden tool '<name>' referenced — aborting stage, operator to run manually."`

## Operators’ hand-tools (outside pipeline, allowed)
- Anything you scp/run manually from your own terminal is fine.
- The pipeline only constrains **agent-invoked** tool usage.
- When in doubt: if the tool touches a live target or sends an HTTP request, run it yourself.
## MCP tier (added 2026-11-19, doctrine: `research/MCP-TOOLS-2026-11-19.md`)
- `rea` (local MCP, 170 tools) — artifact identification and script export are free and offline:
  `open_binary`, `close_binary`, `export_web_scripts`, `trace_web_module_imports`,
  `compare_web_captures`. **Deep analysis is currently unavailable**: `rea doctor` reports
  `providers: []`, so `binary_overview`, `batch_decompile`, `procedure_pseudo_code` and friends
  return `provider_unavailable` until `rea setup` installs an engine (Hopper) or
  `GHIDRA_INSTALL_DIR` is set. Socket-opening tools (`inspect_web_page`, `analyze_web_bundle`,
  `capture_browser_scenario`, `observe_web_session`, `list_browser_targets`) need a CDP endpoint
  and are target-facing: lane gate + programme header + operator GO.
- `beatapi` (remote MCP, 7 tools) — `capabilities_search` -> `capabilities_inspect` (free) ->
  `capabilities_run`. Free models are 1 req/min, balance was 0.5 credit at last measurement.
  `web_read` / `web_map` / `web_research` fetch from BeatAPI's own IPs with none of our headers
  and therefore may never touch a host in any bounty scope (same rule as Firecrawl).
- `burp` (remote MCP at `127.0.0.1:9876`, 27 tools) — `create_repeater_tab[_http2]` is
  preparation and safe; **sending** is target traffic: operator GO plus the programme header in
  the raw request. One approved request at a time, never a loop.
- `memory` (local MCP, 9 tools) — graph notes for facts that must survive compaction. A graph
  entry without a file under `research/` is a note nobody audits.
- `ghidra` (remote MCP at `127.0.0.1:18081`) — configured, unverified, treat as UNREACHABLE until
  a call returns.
- Wiring into agent prompts: `tools/install_mcp_wiring.py` (`--check` for drift, `--selftest`).
