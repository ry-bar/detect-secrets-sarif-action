#!/usr/bin/env python3
"""
converter.py

Convert detect-secrets JSON output into SARIF 2.1.0 format.

Behavior:
- Parse detect-secrets JSON (baseline or scan output that contains a top-level "results" mapping)
- Extract findings with file, line number, type, and metadata
- Map unique finding types into SARIF rules
- Map findings into SARIF results with level="warning"
- Handle empty or missing input gracefully (produce valid SARIF with zero results)
- Validate minimal SARIF structure before writing
- Print two lines to stdout on success:
    sarif_file=<path>
    findings_count=<n>

This script is intentionally dependency-free (only stdlib) so it can run in GitHub Actions.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple


SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "detect-secrets"


def slugify_rule_id(s: str) -> str:
    """Create a stable rule id from a detect-secrets type string.

    Replace non-word characters with '_' and collapse duplicates.
    Keep case-sensitivity minimal and readable.
    """
    if not s:
        return "unknown"
    s = s.strip()
    # Replace non-alphanumeric with underscore
    slug = re.sub(r"[^0-9A-Za-z]+", "_", s)
    # collapse multiple underscores
    slug = re.sub(r"_+", "_", slug)
    # strip leading/trailing underscores
    slug = slug.strip("_")
    if not slug:
        return "unknown"
    return slug


def load_detect_secrets_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def build_sarif_from_results(results: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Convert detect-secrets 'results' mapping into a SARIF structure and count findings.

    results: mapping of file -> list of findings
    Returns (sarif_dict, findings_count)
    """
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for file_path, findings in results.items():
        # normalize file path to relative
        rel_path = file_path
        if rel_path.startswith("/"):
            # make relative if possible
            rel_path = os.path.relpath(rel_path)

        if not isinstance(findings, list):
            continue

        for entry in findings:
            if not isinstance(entry, dict):
                continue

            # Determine type/name of finding
            ftype = entry.get("type") or entry.get("plugin") or entry.get("name") or entry.get("secret_type")

            rule_id = slugify_rule_id(ftype or "unknown")

            # Collect rule metadata if new
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": ftype or rule_id,
                    "shortDescription": {"text": ftype or "detect-secrets finding"},
                    "fullDescription": {"text": entry.get("comment", "") or ""},
                    "properties": {"tags": ["detect-secrets"]},
                }

            # Determine line number
            line = entry.get("line_number") or entry.get("line") or entry.get("start_line")
            try:
                if line is not None:
                    line = int(line)
            except Exception:
                line = None

            message_text = f"{ftype or 'Secret'} found in {rel_path}"
            if entry.get("is_verified") is True:
                message_text += " (verified)"

            result = {
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": rel_path},
                        }
                    }
                ],
            }
            if line is not None:
                # attach region only when we have a line
                result["locations"][0]["physicalLocation"]["region"] = {"startLine": line}

            # Determine security severity
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }
            sec_sev = entry.get("severity", "medium").lower()
            sec_sev = severity_map.get(sec_sev, "medium")

            result_properties = {"security-severity": sec_sev}

            if "hashed_secret" in entry:
                result_properties["detect_secrets"] = {"hashed_secret": entry.get("hashed_secret")}

            result["properties"] = result_properties

            sarif_results.append(result)

    # Build rules list preserving insertion order
    rules_list = [rules_by_id[k] for k in rules_by_id]

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "rules": rules_list,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return sarif, len(sarif_results)


def validate_sarif(sarif: Dict[str, Any]) -> None:
    """Perform minimal SARIF validation. Raises ValueError if invalid."""
    if not isinstance(sarif, dict):
        raise ValueError("SARIF document must be an object")
    if sarif.get("version") != SARIF_VERSION:
        raise ValueError(f"SARIF version must be {SARIF_VERSION}")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF must contain at least one run")
    tool = runs[0].get("tool")
    if not tool or not tool.get("driver") or tool["driver"].get("name") != TOOL_NAME:
        raise ValueError(f"SARIF run must have tool.driver.name = {TOOL_NAME}")


def write_json_file(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert detect-secrets JSON to SARIF 2.1.0")
    parser.add_argument("--input", "-i", dest="input", required=True, help="detect-secrets JSON input file")
    parser.add_argument("--output", "-o", dest="output", required=True, help="SARIF output file path")
    args = parser.parse_args(argv)

    data = load_detect_secrets_json(args.input)

    results = data.get("results") if isinstance(data, dict) else None
    if not results:
        # Empty or missing results: produce a minimal SARIF with zero results
        sarif = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [{"tool": {"driver": {"name": TOOL_NAME, "rules": []}}, "results": []}]}
        findings_count = 0
    else:
        sarif, findings_count = build_sarif_from_results(results)

    # Validate
    try:
        validate_sarif(sarif)
    except Exception as e:
        print(f"SARIF validation failed: {e}", file=sys.stderr)
        return 2

    # Ensure output directory exists
    out_dir = os.path.dirname(args.output) or "."
    os.makedirs(out_dir, exist_ok=True)

    # Write SARIF
    try:
        write_json_file(args.output, sarif)
    except Exception as e:
        print(f"Failed writing SARIF file: {e}", file=sys.stderr)
        return 3

    # Print summary lines for the composite action to capture
    # Use keys that are easy to parse in bash: sarif_file and findings_count
    print(f"sarif_file={args.output}")
    print(f"findings_count={findings_count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
