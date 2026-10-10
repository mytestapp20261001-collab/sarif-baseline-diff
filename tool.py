#!/usr/bin/env python3
"""Offline, bounded contract audit. Python 3.12 standard library only."""
import argparse
import json
import math
import sys
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 10000
class BadInput(ValueError):
    pass
class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise BadInput("invalid command arguments")

def require(condition, message):
    if not condition:
        raise BadInput(message)

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result

def reject_constant(value):
    raise BadInput("nonfinite JSON number")

def read_text(path):
    require(Path(path).is_file(), "input must be a regular file")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "input exceeds 2 MiB limit")
    return raw.decode("utf-8-sig")

def finite_float(value):
    parsed = float(value)
    require(math.isfinite(parsed), "nonfinite JSON number")
    return parsed

def load_json(path):
    return json.loads(read_text(path), object_pairs_hook=pairs, parse_constant=reject_constant, parse_float=finite_float)

def report(findings, **summary):
    return {"schema_version": 1, "tool": TOOL, "status": "findings" if findings else "pass", "summary": summary, "findings": findings}

def finding(code, **where):
    return {"code": code, **where}

def run(build_parser, action):
    try:
        parser = Parser(description=__doc__)
        build_parser(parser)
        result = action(parser.parse_args())
        status = 1 if result["status"] == "findings" else 0
    except (ValueError, OSError, UnicodeError, RecursionError, OverflowError) as exc:
        message = str(exc) if isinstance(exc, BadInput) else "unreadable or malformed input"
        result = {"schema_version": 1, "tool": TOOL, "status": "error", "error": message}
        status = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return status

import hashlib
TOOL = "sarif-baseline-diff"

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()

def extract(data, side):
    require(isinstance(data, dict) and data.get("version") == "2.1.0", "SARIF version must be 2.1.0")
    runs = data.get("runs")
    require(isinstance(runs, list) and len(runs) <= 100, "runs must be an array of at most 100 runs")
    indexed, findings, total = {}, [], 0
    for ri, run_data in enumerate(runs):
        require(isinstance(run_data, dict), "run must be an object")
        driver = run_data.get("tool", {})
        require(isinstance(driver, dict) and isinstance(driver.get("driver"), dict), "run requires tool.driver")
        name = driver["driver"].get("name")
        require(isinstance(name, str) and 0 < len(name) <= 256, "driver requires a nonempty name")
        automation = run_data.get("automationDetails", {})
        require(isinstance(automation, dict) and isinstance(automation.get("id", ""), str), "invalid automationDetails.id")
        scope = [name, automation.get("id", "")]
        results = run_data.get("results")
        require(isinstance(results, list), "run requires an explicit results array")
        total += len(results); require(total <= MAX_ITEMS, "result budget exceeded")
        for i, result in enumerate(results):
            require(isinstance(result, dict), "result must be an object")
            rule = result.get("ruleId")
            require(isinstance(rule, str) and 0 < len(rule) <= 1024, "subset requires explicit ruleId")
            message = result.get("message")
            require(isinstance(message, dict) and isinstance(message.get("text"), str), "subset requires message.text")
            level = result.get("level", "warning")
            require(level in ("none", "note", "warning", "error"), "invalid result level")
            locations = result.get("locations", [])
            require(isinstance(locations, list) and len(locations) <= 100, "invalid locations array")
            position = None
            if locations:
                require(isinstance(locations[0], dict), "invalid primary location")
                physical = locations[0].get("physicalLocation")
                require(isinstance(physical, dict), "subset requires primary physicalLocation")
                artifact, region = physical.get("artifactLocation"), physical.get("region", {})
                require(isinstance(artifact, dict) and isinstance(artifact.get("uri"), str) and artifact["uri"], "subset requires artifactLocation.uri")
                require(isinstance(region, dict), "invalid region")
                require(isinstance(artifact.get("uriBaseId", ""), str), "invalid uriBaseId")
                for key in ("startLine", "startColumn", "endLine", "endColumn"):
                    if key in region:
                        require(type(region[key]) is int and 1 <= region[key] <= 10**9, "region positions must be positive integers")
                position = [artifact["uri"], artifact.get("uriBaseId", ""), region.get("startLine"), region.get("startColumn"), region.get("endLine"), region.get("endColumn")]
            identity = None
            for field in ("fingerprints", "partialFingerprints"):
                values = result.get(field, {})
                require(isinstance(values, dict) and len(values) <= 100 and all(isinstance(k, str) and k and isinstance(v, str) and v for k, v in values.items()), "fingerprint maps must contain nonempty string keys and values")
                if identity is None and values:
                    identity = [field, sorted(values.items())]
            if identity is None:
                require(position is not None, "result needs fingerprints or an explicit primary URI")
                identity = ["rule_location", position[:4]]
            key = digest([scope, rule, identity])
            projection = {"level": level, "message": digest(message["text"]), "primary_location": position}
            if key in indexed:
                findings.append(finding("duplicate_result_identity", side=side, run_index=ri, result_index=i, identity_sha256=key))
            else:
                indexed[key] = projection
    return indexed, findings, total

def audit(baseline, current):
    before, findings, old_count = extract(baseline, "baseline")
    after, next_findings, new_count = extract(current, "current"); findings += next_findings
    for key in sorted(before.keys() - after.keys()):
        findings.append(finding("removed_result", identity_sha256=key))
    for key in sorted(after.keys() - before.keys()):
        findings.append(finding("added_result", identity_sha256=key))
    changed = 0
    for key in sorted(before.keys() & after.keys()):
        fields = [field for field in ("level", "message", "primary_location") if before[key][field] != after[key][field]]
        if fields:
            changed += 1
            findings.append(finding("changed_result", identity_sha256=key, changed_fields=fields))
    return report(findings, baseline_results=old_count, current_results=new_count, unchanged=len(before.keys() & after.keys())-changed)

def configure(parser):
    parser.add_argument("baseline"); parser.add_argument("current")
if __name__ == "__main__":
    sys.exit(run(configure, lambda args: audit(load_json(args.baseline), load_json(args.current))))
