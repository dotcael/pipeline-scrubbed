# Fixtures — labelled evidence for the judge

**Purpose.** Decide whether the evaluator can be fooled **before** it is given a
network connection and two live accounts. If a trap here is promoted as
`reproduced`, the design is dead and nothing built on top of it is worth
building.

Run it:

```bash
python3 tools/pipeline/fixture_eval.py --self        # exits 1 on any disagreement
```

## The cases

| id | what it is | expected |
|---|---|---|
| `F1` | genuine cross-tenant leak with a proper control | `reproduced` |
| `F2` | **echo trap** — the marker is the id we sent | `refuted` |
| `F3` | SPA shell — same body unauthenticated | `refuted` |
| `F4` | HTTP 200 carrying `"error": "not found"` | `refuted` |
| `F5` | the owner was refused too | `invalid` |
| `F6` | no control request at all | `invalid` |
| `F7` | a count changed, no protected value | `insufficient` |
| `F8` | marker not in the owner's record either | `invalid` |

## Why these eight

They are the failure modes the 2026-10-30 advisor round converged on, plus the
two this repo has already been bitten by:

- **Echo**: a server reflects your path parameter, so "the marker appears in the
  response" is true for every request, including ones that leak nothing.
- **Public shell**: a SPA returns 200 and the same HTML to everyone; the data
  calls behind it are the only thing that proves anything.
- **200 with an error body**: the status lies, the body refuses.
- **Control failure**: without the owner's successful request you cannot tell a
  boundary from a dead path. This is the one that turns a broken harness into a
  filed report.

## The rule these encode

A verdict is only reachable from evidence, never from a narrative:

- `reproduced` requires the marker **and** a passing control **and** the marker
  not being ours.
- `invalid` is not a negative — it means the experiment did not run properly and
  must be repeated.
- `insufficient` is not a finding. It is a lead with a named next step.

`count-only` is deliberately `insufficient` rather than `reproduced`: a query
seeing a row proves the index lacks a filter, not that protected content crossed
the boundary. Some programmes will pay for the oracle; the judge will not call it
a disclosure on its own.

## Self-test of the self-test

`selftest.sh` runs the fixtures twice: once as labelled (must exit 0), and once
with a deliberately corrupted expectation (must exit 1). A harness that cannot
fail is not a check — it is decoration.
