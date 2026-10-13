#!/usr/bin/env python3
"""
RQ1: Keyword-based analysis of security transparency in MCP tool descriptions.

For each tool that has both:
  1. Security properties detected by A-WiSeM (from SRM analysis in code)
  2. A natural-language description extracted from source

This script checks whether the description contains keywords related to
each security property. A "transparent" description mentions at least one
keyword for each security property the code actually uses.

Keyword lists are derived from CodeQL sink categories, Semgrep rule IDs,
and Bandit check names - all established, public static analysis sources.
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


# =========================================================================
# Security property keyword sets
# Derived from CodeQL, Semgrep, and Bandit rule categories
# =========================================================================

SECURITY_KEYWORDS = {
    "COMMAND_EXEC": {
        # Keywords that indicate command/process execution
        "command", "execute", "exec", "shell", "subprocess", "process",
        "spawn", "run command", "system command", "terminal", "bash",
        "script", "invoke", "cli", "cmd", "os command", "child_process",
        "popen", "eval", "code execution", "arbitrary code",
        "run script", "shell command", "system call",
    },
    "FILE_SYSTEM": {
        # Keywords that indicate file system operations
        "file", "read file", "write file", "directory", "folder", "path",
        "filesystem", "file system", "upload", "download", "save",
        "delete file", "remove file", "rename", "move file", "copy file",
        "create file", "open file", "disk", "storage", "local file",
        "file access", "file operation", "write to", "read from",
        "overwrite", "append", "mkdir", "rmdir", "unlink",
    },
    "NETWORK": {
        # Keywords that indicate network operations
        "network", "http", "https", "request", "api", "url", "endpoint",
        "fetch", "send request", "web request", "connect", "socket",
        "tcp", "udp", "dns", "port", "remote", "server", "client",
        "download", "upload", "webhook", "proxy", "ssl", "tls",
        "internet", "external service", "third-party", "outbound",
        "inbound", "api call", "rest", "graphql", "grpc",
    },
    "DATABASE": {
        # Keywords that indicate database operations
        "database", "db", "query", "sql", "table", "schema", "record",
        "insert", "update", "delete", "select", "join", "index",
        "collection", "document", "nosql", "mongo", "postgres",
        "mysql", "sqlite", "redis", "dynamodb", "firestore",
        "data store", "datastore", "crud", "transaction",
    },
    "INFO_EXPOSURE": {
        # Keywords that indicate information exposure / env access
        "environment", "env", "config", "configuration", "secret",
        "credential", "password", "token", "key", "api key",
        "sensitive", "private", "confidential", "expose", "leak",
        "disclosure", "logging", "log", "debug", "trace", "error message",
        "stack trace", "personal data", "pii", "environment variable",
    },
    "CRYPTO": {
        # Keywords that indicate cryptographic operations
        "encrypt", "decrypt", "hash", "cipher", "cryptograph",
        "signature", "sign", "verify", "certificate", "ssl", "tls",
        "key generation", "random", "seed", "digest", "hmac",
        "aes", "rsa", "sha", "md5", "bcrypt", "scrypt", "pbkdf",
    },
    "DESERIALIZATION": {
        # Keywords that indicate deserialization
        "deserializ", "serializ", "parse", "unmarshal", "marshal",
        "pickle", "yaml", "xml", "json parse", "decode",
        "object injection", "prototype pollution",
    },
    "AUTH": {
        # Keywords that indicate authentication/authorization
        "auth", "login", "logout", "session", "permission",
        "access control", "role", "privilege", "oauth", "jwt",
        "bearer", "credential", "identity", "user account",
        "sign in", "sign out", "authenticate", "authorize",
        "access token", "refresh token", "rbac", "acl",
    },
}


def normalize_text(text):
    """Normalize text for keyword matching."""
    if not text:
        return ""
    # Lowercase, collapse whitespace
    text = text.lower()
    text = re.sub(r'[_\-]', ' ', text)  # Replace underscores/hyphens with spaces
    text = re.sub(r'\s+', ' ', text)
    return text


def check_keywords(description, property_name):
    """Check if description contains keywords for a security property.

    Returns (is_mentioned, matched_keywords).
    """
    if not description:
        return False, []

    norm_desc = normalize_text(description)
    keywords = SECURITY_KEYWORDS.get(property_name, set())
    matched = []

    for kw in keywords:
        kw_lower = kw.lower()
        # Use word boundary matching for short keywords to avoid false positives
        if len(kw_lower) <= 3:
            pattern = r'\b' + re.escape(kw_lower) + r'\b'
            if re.search(pattern, norm_desc):
                matched.append(kw)
        else:
            if kw_lower in norm_desc:
                matched.append(kw)

    return len(matched) > 0, matched


def analyze_tool(tool):
    """Analyze a single tool's description against its security properties.

    Returns dict with analysis results.
    """
    description = tool.get("description")
    properties = tool.get("properties", [])
    has_srms = len(tool.get("srtis", [])) > 0

    result = {
        "name": tool["name"],
        "has_description": description is not None and len(str(description).strip()) > 0,
        "has_srms": has_srms,
        "properties": properties,
        "description_length": len(description) if description else 0,
        "property_analysis": {},
    }

    if not properties or not description:
        return result

    total_props = len(properties)
    mentioned_props = 0

    for prop in properties:
        is_mentioned, matched_kws = check_keywords(description, prop)
        result["property_analysis"][prop] = {
            "mentioned": is_mentioned,
            "matched_keywords": matched_kws,
        }
        if is_mentioned:
            mentioned_props += 1

    result["mentioned_count"] = mentioned_props
    result["total_properties"] = total_props
    result["transparency_score"] = mentioned_props / total_props if total_props > 0 else None

    return result


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="tools_with_descriptions.jsonl")
    parser.add_argument("--output", required=True, help="Output analysis JSONL")
    parser.add_argument("--summary", required=True, help="Output summary JSON")
    args = parser.parse_args()

    # Load data
    all_tools = []
    with open(args.input) as f:
        for line in f:
            entry = json.loads(line)
            repo = entry["repo"]
            language = entry["language"]
            for tool in entry["tools"]:
                tool["_repo"] = repo
                tool["_language"] = language
                all_tools.append(tool)

    print(f"Total tools loaded: {len(all_tools)}")

    # Analyze
    results = []
    for tool in all_tools:
        result = analyze_tool(tool)
        result["repo"] = tool["_repo"]
        result["language"] = tool["_language"]
        results.append(result)

    # Write detailed results
    with open(args.output, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    # Compute summary statistics
    tools_with_srms = [r for r in results if r["has_srms"]]
    tools_with_srms_and_desc = [r for r in tools_with_srms if r["has_description"]]
    tools_with_props_and_desc = [
        r for r in results
        if r["properties"] and r["has_description"]
    ]

    # Per-property stats
    per_property = {}
    for prop in SECURITY_KEYWORDS:
        tools_with_prop = [
            r for r in tools_with_props_and_desc
            if prop in r["properties"]
        ]
        mentioned = [
            r for r in tools_with_prop
            if r["property_analysis"].get(prop, {}).get("mentioned", False)
        ]
        per_property[prop] = {
            "total_tools": len(tools_with_prop),
            "mentioned_in_desc": len(mentioned),
            "rate": len(mentioned) / len(tools_with_prop) if tools_with_prop else 0,
        }

    # Transparency score distribution
    scores = [
        r["transparency_score"]
        for r in tools_with_props_and_desc
        if r["transparency_score"] is not None
    ]

    fully_transparent = sum(1 for s in scores if s == 1.0)
    partially_transparent = sum(1 for s in scores if 0 < s < 1.0)
    not_transparent = sum(1 for s in scores if s == 0.0)

    avg_score = sum(scores) / len(scores) if scores else 0

    summary = {
        "total_tools": len(all_tools),
        "tools_with_srms": len(tools_with_srms),
        "tools_without_srms": len(all_tools) - len(tools_with_srms),
        "tools_with_description": sum(1 for r in results if r["has_description"]),
        "tools_without_description": sum(1 for r in results if not r["has_description"]),
        "tools_with_srms_and_description": len(tools_with_srms_and_desc),
        "tools_analyzable": len(tools_with_props_and_desc),
        "transparency": {
            "average_score": round(avg_score, 4),
            "fully_transparent": fully_transparent,
            "partially_transparent": partially_transparent,
            "not_transparent": not_transparent,
            "total_scored": len(scores),
        },
        "per_property": per_property,
    }

    with open(args.summary, "w") as f:
        json.dump(summary, f, indent=2)

    # Print summary
    print(f"\n{'='*60}")
    print(f"RQ1 KEYWORD ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"Total tools: {len(all_tools)}")
    print(f"Tools with SRMs (security-relevant): {len(tools_with_srms)}")
    print(f"Tools with description: {sum(1 for r in results if r['has_description'])}")
    print(f"Analyzable (SRM properties + description): {len(tools_with_props_and_desc)}")
    print()
    print(f"TRANSPARENCY SCORES (keyword-based):")
    print(f"  Average: {avg_score:.2%}")
    print(f"  Fully transparent (100%): {fully_transparent} ({fully_transparent/max(len(scores),1):.1%})")
    print(f"  Partially transparent: {partially_transparent} ({partially_transparent/max(len(scores),1):.1%})")
    print(f"  Not transparent (0%): {not_transparent} ({not_transparent/max(len(scores),1):.1%})")
    print()
    print(f"PER-PROPERTY MENTION RATES:")
    for prop, stats in sorted(per_property.items(), key=lambda x: -x[1]["rate"]):
        if stats["total_tools"] > 0:
            print(f"  {prop:20s}: {stats['mentioned_in_desc']:4d}/{stats['total_tools']:4d} ({stats['rate']:.1%})")


if __name__ == "__main__":
    main()
