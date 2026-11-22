#!/usr/bin/env python3
"""
extract_text.py — Pull the model's actual answer out of an `opencode run --format json` event stream.

`opencode run` in agent mode emits tool calls (bash, grep, read) alongside the
final answer, so the raw text output is a mix of the agent's trace and the
answer we want. With `--format json` the trace becomes machine-readable: every
event is a JSON object on its own line, and the answer arrives as one or more
events with part.type == "text".

This reads that JSONL stream on stdin and prints ONLY the text parts, joined
and flattened to a single line (newlines -> spaces) so the caller can embed it
in a "model:text" record without breaking the record format.

Robustness: if the stream contains no parseable JSON events (e.g. a plain-text
error like "Rate limit exceeded"), the raw text is passed through as-is so the
caller can still surface the real error.

Usage: opencode run -m MODEL --format json -- "prompt" | python3 extract_text.py
Prints the extracted answer (single line) to stdout. Exit 0 either way.
"""
import json
import sys


def main():
    raw = sys.stdin.read()

    texts = []
    errors = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        if not isinstance(event, dict):
            continue

        # Error events: {"type":"error","error":{"type":"provider.quota",
        #                 "message":"...","status":429}}
        if event.get("type") == "error":
            err = event.get("error")
            if isinstance(err, dict):
                errors.append(
                    "ERROR {} (HTTP {}): {}".format(
                        err.get("type", "unknown"),
                        err.get("status", "?"),
                        err.get("message", "no message"),
                    )
                )
            else:
                errors.append("ERROR: {}".format(err))
            continue

        # Text events: {"type":"text","part":{"type":"text","text":"..."}}
        part = event.get("part")
        if isinstance(part, dict):
            if part.get("type") == "text" and isinstance(part.get("text"), str):
                texts.append(part["text"])

    if errors:
        # Surface the structured error (quota, auth, provider failure) verbatim.
        for e in errors:
            sys.stdout.write(e + "\n")
        return

    if not texts:
        # No JSON text events. Either the stream wasn't JSON at all (plain
        # error text) or the model produced no text. Pass the raw through so
        # the real error is visible instead of being swallowed.
        sys.stdout.write(raw.replace("\n", " "))
        sys.stdout.write("\n")
        return

    answer = " ".join(t for t in texts if t.strip())
    # Flatten to one line so it stays a single "model:text" record.
    answer = " ".join(answer.split())
    sys.stdout.write(answer + "\n")


if __name__ == "__main__":
    main()
