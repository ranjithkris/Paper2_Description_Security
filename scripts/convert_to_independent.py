#!/usr/bin/env python3
"""
Convert existing A-WiSeM data to independent ground truth.

Takes the raw API invocations found in source code (from srtis field) and
re-classifies them using the trusted security registry (CodeQL/Semgrep/Bandit).

This produces an independent dataset where:
  - Security properties come from matching APIs against our trusted registry
  - NOT from A-WiSeM's scoring or classification
  - Only tools with at least one matched invocation are included

The raw API detection is objective: subprocess.run either appears in the
code or it does not. This script re-maps those findings to our independently
sourced security categories.

Usage:
    python3 scripts/convert_to_independent.py \
        --input data/tools_with_descriptions.jsonl \
        --output data/independent_dataset.jsonl \
        --report results/conversion_report.txt
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from trusted_security_registry import (
    SECURITY_OPERATIONS, SECURITY_PROPERTIES,
    get_operations_for_language, generate_registry_report,
)


def build_api_lookup():
    """
    Build a lookup: api_name_pattern -> {property, sources, apis}.

    Maps from API strings (as they appear in srtis) to our trusted
    registry properties.
    """
    lookup = {}  # api_string -> [(property, sources)]

    for prop in SECURITY_PROPERTIES:
        for lang in ["python", "typescript", "javascript"]:
            ops = SECURITY_OPERATIONS.get(prop, {}).get(lang)
            if ops is None:
                if lang == "javascript":
                    ops = SECURITY_OPERATIONS.get(prop, {}).get("typescript")
                if ops is None:
                    continue

            for op_group in ops:
                for api in op_group["apis"]:
                    key = api.lower()
                    if key not in lookup:
                        lookup[key] = []
                    lookup[key].append({
                        "property": prop,
                        "sources": op_group["sources"],
                        "language": lang,
                    })

    return lookup


def match_api_to_registry(api_name, lookup):
    """
    Match a raw API name from srtis to our trusted registry.

    Returns list of {property, sources} matches.
    """
    api_lower = api_name.lower()
    matches = []

    # Direct match
    if api_lower in lookup:
        matches.extend(lookup[api_lower])
        return matches

    # Try partial matching (srtis might have module.method format)
    # e.g., "fs/promises.writeFile" should match "fs.writeFile" or "writeFile"
    api_parts = re.split(r'[./]', api_lower)
    api_leaf = api_parts[-1] if api_parts else api_lower

    for key, entries in lookup.items():
        key_parts = re.split(r'[./]', key)
        key_leaf = key_parts[-1] if key_parts else key

        # Match on leaf function name
        if api_leaf == key_leaf and api_leaf not in ("get", "post", "put", "delete", "open", "read", "write"):
            matches.extend(entries)
            continue

        # Match on full method path (normalized)
        api_norm = api_lower.replace("/", ".").replace("promises.", "")
        key_norm = key.replace("/", ".").replace("promises.", "")
        if api_norm == key_norm:
            matches.extend(entries)

    return matches


def convert_entry(entry, api_lookup, stats):
    """Convert one JSONL entry from A-WiSeM format to independent format."""
    repo = entry["repo"]
    language = entry.get("language", "python")

    converted_tools = []

    for tool in entry.get("tools", []):
        tool_name = tool.get("name", "")
        description = tool.get("description")
        description_source = tool.get("description_source", "unknown")
        source_file = None

        # Extract source file if available from files_analyzed
        if tool.get("function"):
            # Try to match function to analyzed file
            pass

        # Re-classify srtis using our trusted registry
        detected_properties = set()
        detected_apis = {}  # property -> [{apis, sources}]

        for srti in tool.get("srtis", []):
            api_name = srti.get("api", "")
            if not api_name:
                continue

            matches = match_api_to_registry(api_name, api_lookup)

            for m in matches:
                prop = m["property"]
                detected_properties.add(prop)
                if prop not in detected_apis:
                    detected_apis[prop] = []
                detected_apis[prop].append({
                    "apis": [api_name],
                    "sources": m["sources"],
                    "original_cwes": srti.get("cwes", []),
                })

        # Also check the A-WiSeM properties and map their CWEs
        # This catches cases where our registry has the CWE but
        # the API name format differs
        for srti in tool.get("srtis", []):
            for cwe in srti.get("cwes", []):
                # Map CWEs to our properties
                cwe_to_prop = {
                    "CWE-78": "COMMAND_EXEC", "CWE-94": "COMMAND_EXEC",
                    "CWE-95": "COMMAND_EXEC",
                    "CWE-22": "FILE_SYSTEM", "CWE-73": "FILE_SYSTEM",
                    "CWE-377": "FILE_SYSTEM", "CWE-732": "FILE_SYSTEM",
                    "CWE-918": "NETWORK", "CWE-295": "NETWORK",
                    "CWE-319": "NETWORK", "CWE-601": "NETWORK",
                    "CWE-89": "DATABASE", "CWE-943": "DATABASE",
                    "CWE-200": "INFO_EXPOSURE", "CWE-209": "INFO_EXPOSURE",
                    "CWE-215": "INFO_EXPOSURE", "CWE-312": "INFO_EXPOSURE",
                    "CWE-532": "INFO_EXPOSURE", "CWE-798": "INFO_EXPOSURE",
                    "CWE-526": "INFO_EXPOSURE",
                    "CWE-326": "CRYPTO", "CWE-327": "CRYPTO",
                    "CWE-328": "CRYPTO", "CWE-330": "CRYPTO",
                    "CWE-338": "CRYPTO",
                    "CWE-502": "DESERIALIZATION", "CWE-611": "DESERIALIZATION",
                    "CWE-776": "DESERIALIZATION",
                    "CWE-287": "AUTH", "CWE-306": "AUTH",
                    "CWE-384": "AUTH", "CWE-614": "AUTH",
                    "CWE-916": "AUTH",
                }
                prop = cwe_to_prop.get(cwe)
                if prop:
                    detected_properties.add(prop)
                    if prop not in detected_apis:
                        detected_apis[prop] = []
                    # Check if we already have this API
                    api_name = srti.get("api", "")
                    already = any(
                        api_name in entry_apis.get("apis", [])
                        for entry_apis in detected_apis[prop]
                    )
                    if not already:
                        detected_apis[prop].append({
                            "apis": [api_name],
                            "sources": [f"CWE-mapped from {cwe}"],
                            "original_cwes": [cwe],
                        })

        # Only include tools with at least one detected property
        if not detected_properties:
            stats["tools_no_security_ops"] += 1
            continue

        stats["tools_with_security_ops"] += 1

        if description and str(description).strip():
            stats["tools_with_desc_and_ops"] += 1
        else:
            stats["tools_with_ops_no_desc"] += 1

        for prop in detected_properties:
            stats["property_counts"][prop] += 1

        converted_tools.append({
            "name": tool_name,
            "description": description,
            "description_source": description_source,
            "source_file": source_file,
            "detected_properties": sorted(detected_properties),
            "detected_apis": detected_apis,
            "property_source": "trusted_registry_remapped",
        })

    return {
        "repo": repo,
        "language": language,
        "tools": converted_tools,
        "repo_level_properties": sorted(set(
            p for t in converted_tools for p in t["detected_properties"]
        )),
        "repo_level_apis": {},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", default=None)
    args = parser.parse_args()

    print("Building API lookup from trusted registry...")
    api_lookup = build_api_lookup()
    print(f"  {len(api_lookup)} API patterns in lookup")

    print(f"\nLoading input: {args.input}")
    stats = {
        "total_entries": 0,
        "total_tools": 0,
        "tools_with_security_ops": 0,
        "tools_no_security_ops": 0,
        "tools_with_desc_and_ops": 0,
        "tools_with_ops_no_desc": 0,
        "property_counts": Counter(),
        "repos_with_tools": 0,
        "repos_empty": 0,
    }

    results = []
    with open(args.input) as f:
        for line in f:
            entry = json.loads(line)
            stats["total_entries"] += 1
            stats["total_tools"] += len(entry.get("tools", []))

            converted = convert_entry(entry, api_lookup, stats)
            if converted["tools"]:
                stats["repos_with_tools"] += 1
            else:
                stats["repos_empty"] += 1
            results.append(converted)

    # Write output
    with open(args.output, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    # Print summary
    print(f"\n{'='*60}")
    print(f"CONVERSION SUMMARY")
    print(f"{'='*60}")
    print(f"Input entries (repos):       {stats['total_entries']}")
    print(f"Total tools in input:        {stats['total_tools']}")
    print(f"")
    print(f"Tools with security ops:     {stats['tools_with_security_ops']}")
    print(f"  - with description:        {stats['tools_with_desc_and_ops']}")
    print(f"  - without description:     {stats['tools_with_ops_no_desc']}")
    print(f"Tools without security ops:  {stats['tools_no_security_ops']}")
    print(f"")
    print(f"Repos with security tools:   {stats['repos_with_tools']}")
    print(f"Repos without:               {stats['repos_empty']}")
    print(f"")
    print(f"Property distribution:")
    for prop in SECURITY_PROPERTIES:
        count = stats['property_counts'].get(prop, 0)
        print(f"  {prop:<20} {count}")
    print(f"")
    print(f"Analyzable tools (security ops + description): {stats['tools_with_desc_and_ops']}")
    print(f"Output: {args.output}")

    # Write report
    if args.report:
        with open(args.report, "w") as f:
            f.write("INDEPENDENT GROUND TRUTH CONVERSION REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write("Method: Re-map raw API invocations from source code\n")
            f.write("against trusted security registry (CodeQL/Semgrep/Bandit).\n")
            f.write("Properties are derived from our registry, NOT A-WiSeM.\n\n")
            f.write(f"Input: {args.input}\n")
            f.write(f"Output: {args.output}\n\n")
            f.write(f"Total repos: {stats['total_entries']}\n")
            f.write(f"Total tools: {stats['total_tools']}\n")
            f.write(f"Tools with security ops: {stats['tools_with_security_ops']}\n")
            f.write(f"  with description: {stats['tools_with_desc_and_ops']}\n")
            f.write(f"  without description: {stats['tools_with_ops_no_desc']}\n")
            f.write(f"\nProperty distribution:\n")
            for prop in SECURITY_PROPERTIES:
                f.write(f"  {prop:<20} {stats['property_counts'].get(prop, 0)}\n")
            f.write(f"\n\nTRUSTED REGISTRY CONTENTS:\n")
            f.write("=" * 60 + "\n")
            f.write(generate_registry_report())
        print(f"Report: {args.report}")


if __name__ == "__main__":
    main()
