#!/usr/bin/env python3
"""
Independent Ground Truth Builder

Clones MCP server repos, extracts tool descriptions AND scans source code
for security-relevant API invocations. Produces an independent dataset
with NO dependency on A-WiSeM.

Ground truth: a tool has a security property if the source file defining
that tool contains an invocation of any API from the trusted registry
(CodeQL/Semgrep/Bandit) for that property.

Usage:
    python3 scripts/build_ground_truth.py \
        --repo-list data/tools_with_descriptions.jsonl \
        --output data/independent_dataset.jsonl \
        --registry-report results/registry_report.txt \
        --resume

The --repo-list can be the existing tools_with_descriptions.jsonl (we only
use the repo URLs and language from it) or mass_analysis_results.jsonl.

Output: one JSONL line per repo, each containing tools with:
  - name, description (re-extracted)
  - detected_properties (from code scanning, independent of A-WiSeM)
  - detected_apis (specific APIs found, with trusted sources)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Add scripts dir to path for registry import
sys.path.insert(0, str(Path(__file__).parent))
from trusted_security_registry import (
    SECURITY_OPERATIONS, SECURITY_PROPERTIES, get_operations_for_language,
    generate_registry_report,
)


# =========================================================================
# Tool definition extraction (from extract_descriptions.py)
# =========================================================================

def extract_python_tools(content, file_path):
    """Extract MCP tool definitions from Python source code."""
    import ast

    tools = []

    # --- AST-based extraction ---
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                dec_str = ast.dump(dec)
                if 'tool' not in dec_str.lower():
                    continue

                tool_name = node.name
                description = None

                # Check docstring
                docstring = ast.get_docstring(node)
                if docstring:
                    description = docstring.strip()

                # Check decorator kwargs for description=
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg == 'description' and isinstance(kw.value, ast.Constant):
                            description = str(kw.value.value)
                    # Check positional args for name
                    for arg in dec.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if not description:
                                # Might be tool name, not description
                                pass

                    # Check for name kwarg
                    for kw in dec.keywords:
                        if kw.arg == 'name' and isinstance(kw.value, ast.Constant):
                            tool_name = str(kw.value.value)

                tools.append({
                    "name": tool_name,
                    "description": description,
                    "description_source": "docstring" if description else None,
                    "source_file": str(file_path),
                })
                break
    except SyntaxError:
        pass

    # --- Regex fallback ---
    if not tools:
        patterns = [
            r'@\w*\.tool\s*\(\s*["\']([^"\']+)["\']\s*(?:,\s*description\s*=\s*["\']([^"\']+)["\'])?\s*\)',
            r'\.tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\']\s*,\s*description\s*=\s*["\']([^"\']+)["\']\s*\)',
        ]
        for pat in patterns:
            for m in re.finditer(pat, content):
                name = m.group(1)
                desc = m.group(2) if m.lastindex >= 2 else None
                if name and not any(t["name"] == name for t in tools):
                    tools.append({
                        "name": name,
                        "description": desc,
                        "description_source": "regex" if desc else None,
                        "source_file": str(file_path),
                    })

    return tools


def extract_ts_tools(content, file_path):
    """Extract MCP tool definitions from TypeScript/JavaScript source."""
    tools = []
    patterns = [
        # server.tool("name", "description", ...)
        r'\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*"((?:[^"\\]|\\.)*)"\s*,',
        r"\.tool\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*'((?:[^'\\]|\\.)*)'\s*,",
        # { name: "...", description: "..." }
        r'name\s*:\s*["\']([^"\']+)["\']\s*,\s*description\s*:\s*["\']([^"\']+)["\']',
        # name and description separated by other fields
        r'name\s*:\s*["\']([^"\']+)["\']\s*,(?:[^{}]*?)description\s*:\s*["\']([^"\']+)["\']',
        # server.tool("name", { description: "..." })
        r'\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*?description\s*:\s*["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        for m in re.finditer(pat, content, re.DOTALL):
            name = m.group(1)
            desc = m.group(2) if m.lastindex >= 2 else None
            if name and not any(t["name"] == name for t in tools):
                tools.append({
                    "name": name,
                    "description": desc,
                    "description_source": "regex" if desc else None,
                    "source_file": str(file_path),
                })

    return tools


# =========================================================================
# Security operation scanning
# =========================================================================

def scan_file_for_operations(content, language):
    """
    Scan a source file for security-relevant API invocations.

    Returns: {property: [{"api": str, "sources": [str]}]}
    """
    detected = {}

    for prop in SECURITY_PROPERTIES:
        ops = get_operations_for_language(prop, language)
        if not ops:
            continue

        prop_matches = []
        for op_group in ops:
            pattern = op_group["pattern"]
            import_pattern = op_group.get("import_pattern")

            # Check if the pattern matches in the content
            has_call = bool(re.search(pattern, content))

            # For patterns that require an import, also check import
            has_import = True
            if import_pattern:
                has_import = bool(re.search(import_pattern, content))

            if has_call and has_import:
                prop_matches.append({
                    "apis": op_group["apis"],
                    "sources": op_group["sources"],
                })

        if prop_matches:
            detected[prop] = prop_matches

    return detected


def scan_repo_for_operations(repo_dir, language):
    """
    Scan all source files in a repo for security operations.

    Returns per-file results: {file_path: {property: [matches]}}
    """
    extensions = {
        "python": [".py"],
        "typescript": [".ts", ".tsx"],
        "javascript": [".js", ".jsx", ".mjs"],
    }

    exts = extensions.get(language, [])
    # For typescript repos, also check .js files
    if language == "typescript":
        exts += [".js", ".jsx", ".mjs"]

    results = {}
    repo_path = Path(repo_dir)

    for ext in exts:
        for fpath in repo_path.rglob(f"*{ext}"):
            # Skip node_modules, .git, test files, etc.
            rel = str(fpath.relative_to(repo_path))
            if any(skip in rel for skip in [
                "node_modules/", ".git/", "__pycache__/", "dist/",
                "build/", ".tox/", ".venv/", "venv/", ".egg-info/",
            ]):
                continue

            try:
                content = fpath.read_text(errors='ignore')
                if len(content) > 500000:  # Skip very large files
                    continue
                detected = scan_file_for_operations(content, language)
                if detected:
                    results[rel] = detected
            except Exception:
                continue

    return results


# =========================================================================
# Main pipeline
# =========================================================================

def clone_repo(repo_url, dest_dir, timeout=120):
    """Clone a repo (shallow)."""
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo_url, dest_dir],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


def process_repo(repo_url, language, tmp_base):
    """
    Process one repo: clone, extract tools, scan for operations.

    Returns: {
        "repo": str,
        "language": str,
        "tools": [
            {
                "name": str,
                "description": str or None,
                "source_file": str,
                "detected_properties": [str],
                "detected_apis": {prop: [{apis, sources}]},
            }
        ],
        "repo_level_properties": [str],  # all properties found anywhere in repo
        "repo_level_apis": {prop: [{apis, sources}]},
    }
    """
    repo_dir = os.path.join(tmp_base, "repo")

    try:
        # Clone
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        if not clone_repo(repo_url, repo_dir):
            return None

        # Find source files with tool definitions
        repo_path = Path(repo_dir)
        extensions = {
            "python": [".py"],
            "typescript": [".ts", ".tsx", ".js", ".jsx"],
            "javascript": [".js", ".jsx", ".mjs", ".ts", ".tsx"],
        }

        all_tools = []
        all_repo_ops = {}  # Aggregated repo-level operations

        for ext in extensions.get(language, []):
            for fpath in repo_path.rglob(f"*{ext}"):
                rel = str(fpath.relative_to(repo_path))
                if any(skip in rel for skip in [
                    "node_modules/", ".git/", "__pycache__/", "dist/",
                    "build/", ".tox/", ".venv/", "venv/", ".egg-info/",
                ]):
                    continue

                try:
                    content = fpath.read_text(errors='ignore')
                    if len(content) > 500000:
                        continue
                except Exception:
                    continue

                # Extract tool definitions from this file
                if language == "python" and ext == ".py":
                    file_tools = extract_python_tools(content, rel)
                elif ext in [".ts", ".tsx", ".js", ".jsx", ".mjs"]:
                    file_tools = extract_ts_tools(content, rel)
                else:
                    file_tools = []

                # Scan this file for security operations
                scan_lang = language
                if ext in [".ts", ".tsx"]:
                    scan_lang = "typescript"
                elif ext in [".js", ".jsx", ".mjs"]:
                    scan_lang = "javascript"

                file_ops = scan_file_for_operations(content, scan_lang)

                # Merge file operations into repo-level
                for prop, matches in file_ops.items():
                    if prop not in all_repo_ops:
                        all_repo_ops[prop] = []
                    all_repo_ops[prop].extend(matches)

                # Assign file-level properties to tools found in this file
                for tool in file_tools:
                    tool["detected_properties"] = list(file_ops.keys())
                    tool["detected_apis"] = file_ops
                    all_tools.append(tool)

        # For tools without file-level properties, assign repo-level properties
        # (the tool might call functions defined in other files)
        for tool in all_tools:
            if not tool["detected_properties"] and all_repo_ops:
                tool["detected_properties"] = list(all_repo_ops.keys())
                tool["detected_apis"] = all_repo_ops
                tool["property_source"] = "repo_level"
            else:
                tool["property_source"] = "file_level"

        return {
            "repo": repo_url,
            "language": language,
            "tools": all_tools,
            "repo_level_properties": list(all_repo_ops.keys()),
            "repo_level_apis": {
                prop: [{"apis": m["apis"], "sources": m["sources"]} for m in matches]
                for prop, matches in all_repo_ops.items()
            },
        }

    except Exception as e:
        print(f"    ERROR: {e}")
        return None
    finally:
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir, ignore_errors=True)


def load_repo_list(path):
    """Load repo URLs and languages from JSONL."""
    repos = []
    with open(path) as f:
        for line in f:
            entry = json.loads(line)
            repo = entry.get("repo", "")
            language = entry.get("language", "python")
            if repo and repo.startswith("http"):
                repos.append({"repo": repo, "language": language})
    return repos


def main():
    parser = argparse.ArgumentParser(description="Build independent ground truth")
    parser.add_argument("--repo-list", required=True,
                        help="JSONL file with repo URLs (e.g., tools_with_descriptions.jsonl)")
    parser.add_argument("--output", required=True,
                        help="Output JSONL file (independent_dataset.jsonl)")
    parser.add_argument("--registry-report", default=None,
                        help="Save registry report to this file")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from partial output")
    parser.add_argument("--limit", type=int, default=0,
                        help="Process only this many repos (for testing)")
    args = parser.parse_args()

    # Save registry report
    if args.registry_report:
        report = generate_registry_report()
        with open(args.registry_report, "w") as f:
            f.write(report)
        print(f"Registry report saved to: {args.registry_report}")

    # Load repos
    repos = load_repo_list(args.repo_list)
    print(f"Loaded {len(repos)} repos")

    if args.limit:
        repos = repos[:args.limit]
        print(f"Limited to {len(repos)} repos")

    # Check for resume
    processed = set()
    if args.resume and os.path.exists(args.output):
        with open(args.output) as f:
            for line in f:
                entry = json.loads(line)
                processed.add(entry["repo"])
        print(f"Resuming: {len(processed)} already processed")

    remaining = [r for r in repos if r["repo"] not in processed]
    print(f"Remaining: {len(remaining)} repos to process")

    # Process repos
    tmp_base = tempfile.mkdtemp(prefix="mcp_scan_")
    mode = "a" if args.resume else "w"

    total_tools = 0
    total_with_props = 0
    total_with_desc = 0
    total_analyzable = 0

    try:
        with open(args.output, mode) as f:
            for i, repo_info in enumerate(remaining):
                repo_url = repo_info["repo"]
                language = repo_info["language"]
                repo_name = repo_url.split("/")[-1] if "/" in repo_url else repo_url

                print(f"[{i+1}/{len(remaining)}] {repo_name} ({language})...",
                      end=" ", flush=True)

                result = process_repo(repo_url, language, tmp_base)

                if result is None:
                    print("FAILED")
                    # Write empty entry so resume skips it
                    f.write(json.dumps({
                        "repo": repo_url,
                        "language": language,
                        "tools": [],
                        "repo_level_properties": [],
                        "repo_level_apis": {},
                    }) + "\n")
                    f.flush()
                    continue

                n_tools = len(result["tools"])
                n_with_props = sum(1 for t in result["tools"] if t["detected_properties"])
                n_with_desc = sum(1 for t in result["tools"] if t.get("description"))
                n_analyzable = sum(
                    1 for t in result["tools"]
                    if t["detected_properties"] and t.get("description")
                )

                total_tools += n_tools
                total_with_props += n_with_props
                total_with_desc += n_with_desc
                total_analyzable += n_analyzable

                # Serialize (handle non-serializable types)
                f.write(json.dumps(result, default=str) + "\n")
                f.flush()

                repo_props = result["repo_level_properties"]
                print(f"{n_tools} tools, {n_with_props} with security ops, "
                      f"{n_with_desc} with desc, props: {repo_props}")

    finally:
        shutil.rmtree(tmp_base, ignore_errors=True)

    print(f"\n{'='*60}")
    print(f"GROUND TRUTH BUILDING COMPLETE")
    print(f"{'='*60}")
    print(f"Total tools found: {total_tools}")
    print(f"Tools with security operations: {total_with_props}")
    print(f"Tools with descriptions: {total_with_desc}")
    print(f"Analyzable (both): {total_analyzable}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
