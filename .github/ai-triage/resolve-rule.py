#!/usr/bin/env python3
"""Look up the rule for a label and tell the workflow what to do.

Reads the label name from LABEL and the rule table from CONFIG. Writes any
prompt or static text into WORKDIR so it never has to survive a shell round
trip, and emits only small scalars as step outputs.

Outputs: found, action, mode.
"""

import os
import pathlib
import sys

import yaml

label = os.environ["LABEL"]
config = pathlib.Path(os.environ["CONFIG"])
workdir = pathlib.Path(os.environ["WORKDIR"])
workdir.mkdir(parents=True, exist_ok=True)


def emit(**pairs):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
        for key, value in pairs.items():
            handle.write(f"{key}={value}\n")


def fail(message):
    print(f"::error file={config}::{message}")
    sys.exit(1)


rules = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
if not isinstance(rules, dict):
    fail("Top level of the rule file must be a mapping of label name to rule.")

rule = rules.get(label)
if rule is None:
    print(f"No rule configured for label {label!r}. Nothing to do.")
    emit(found="false")
    sys.exit(0)

if not isinstance(rule, dict):
    fail(f"Rule for {label!r} must be a mapping, got {type(rule).__name__}.")

action = rule.get("action", "comment")
if action not in ("comment", "update-body"):
    fail(f"Rule for {label!r} has unknown action {action!r}.")

has_static = "static" in rule
has_prompt = "prompt" in rule
if has_static == has_prompt:
    fail(f"Rule for {label!r} needs exactly one of 'static' or 'prompt'.")

if has_static:
    mode = "static"
    (workdir / "output.md").write_text(str(rule["static"]).strip() + "\n", encoding="utf-8")
else:
    mode = "ai"
    (workdir / "prompt.txt").write_text(str(rule["prompt"]).strip() + "\n", encoding="utf-8")

print(f"Label {label!r} matched: action={action} mode={mode}")
emit(found="true", action=action, mode=mode)
