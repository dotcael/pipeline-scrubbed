# Firecracker pipeline, scrubbed reference copy

A stage-gated multi-agent research pipeline. This is a reference implementation: config files are
examples, targets and programme names are placeholders, and no credentials are included.

## What it does

- deterministic routing across scout, recon, hypothesis, triage, evaluator, challenger and reporter
- model selection from a priced roster with provider health circuit breakers
- committees with independent evaluator and challenger on different providers
- disagreement parking instead of majority voting
- severity computed from a model-emitted vector by `cvss31.py`
- evidence packets and an append-only outcomes ledger

## Running it

Fill `targets.yaml` and `program-aliases.yaml` with names you are authorised to work with, set the
provider credentials in your environment, then invoke `orchestrate.sh <stage> <target> <prompt>`.

The pipeline refuses to spend when the committee is under capacity, a provider is in cooldown, or a
deduplication gate finds an unresolved source.

## Safety

No target names, credentials, ntfy topics or local paths are included. Example hostnames use
`example.test`. Provider pricing URLs are public documentation links.
