#!/usr/bin/env python3
"""
Extract MCP tool descriptions from source code.

Clones repos (shallow, --depth 1) and parses source files to extract
natural-language descriptions of MCP tools.

Supports resume mode to continue from a partial extraction.
"""

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tempfile
from pathlib import Path


CLONE_TIMEOUT = 90
CLONE_BASE = tempfile.mkdtemp(prefix="paper2_clone_")


def clone_repo(repo_slug, target_dir):
    """Shallow clone a GitHub repo. Returns True on success."""
    url = f"https://github.com/{repo_slug}.git"
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch",
             "--quiet", url, target_dir],
            capture_output=True, text=True, timeout=CLONE_TIMEOUT
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


# =========================================================================
# Python description extraction
# =========================================================================

def extract_python_descriptions(source):
    """Extract tool descriptions from Python MCP server source."""
    descriptions = {}

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _extract_python_regex(source)

    for node in ast.walk(tree):
        # Decorated functions: @server.tool, @mcp.tool, @app.tool
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool_name = None
            desc = None

            for decorator in node.decorator_list:
                dec_str = _decorator_to_string(decorator)
                if dec_str and any(p in dec_str for p in ['.tool', '.call_tool', 'tool']):
                    if isinstance(decorator, ast.Call):
                        tool_name = node.name
                        if decorator.args:
                            a = decorator.args[0]
                            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                                tool_name = a.value
                        for kw in decorator.keywords:
                            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                                tool_name = kw.value.value
                            if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                                desc = kw.value.value
                    else:
                        tool_name = node.name

            if tool_name:
                if not desc:
                    docstring = ast.get_docstring(node)
                    if docstring:
                        desc = docstring
                if desc:
                    descriptions[tool_name] = desc.strip()

        # add_tool/register_tool calls
        if isinstance(node, ast.Call):
            func_str = _node_to_string(node.func)
            if func_str and any(p in func_str for p in ['add_tool', 'register_tool']):
                name = desc = None
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        name = kw.value.value
                    if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                        desc = kw.value.value
                if not name and node.args and isinstance(node.args[0], ast.Constant):
                    name = node.args[0].value
                if not desc and len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    desc = node.args[1].value
                if name and desc:
                    descriptions[name] = desc.strip()

    # Supplement with regex
    for k, v in _extract_python_regex(source).items():
        if k not in descriptions:
            descriptions[k] = v

    return descriptions


def _decorator_to_string(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _decorator_to_string(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _decorator_to_string(node.func)
    return None


def _node_to_string(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _node_to_string(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _extract_python_regex(source):
    descriptions = {}
    # @xxx.tool(...) def name(...): """docstring"""
    p1 = r'@\w+\.tool\([^)]*\)\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*(?:"""((?:[^"]|"(?!""))*?)"""|\'\'\'((?:[^\']|\'(?!\'\'))*?)\'\'\')'
    for m in re.finditer(p1, source, re.DOTALL):
        desc = m.group(2) or m.group(3)
        if desc:
            descriptions[m.group(1)] = desc.strip()

    # Tool(name="...", description="...")
    p2 = r'Tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\']\s*,\s*description\s*=\s*["\']([^"\']+)["\']'
    for m in re.finditer(p2, source):
        descriptions[m.group(1)] = m.group(2).strip()

    # .tool("name", "description")
    p3 = r'\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']'
    for m in re.finditer(p3, source):
        descriptions[m.group(1)] = m.group(2).strip()

    return descriptions


# =========================================================================
# TypeScript/JavaScript description extraction
# =========================================================================

def extract_ts_descriptions(source):
    """Extract tool descriptions from TypeScript/JS source.

    Handles multiple common patterns found in MCP servers.
    """
    descriptions = {}

    # === Pattern 1: server.tool("name", "description", ...) ===
    p1 = r'\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']((?:[^"\'\\]|\\.)*)["\']\s*[,)]'
    for m in re.finditer(p1, source, re.DOTALL):
        name = m.group(1)
        desc = m.group(2).replace('\\"', '"').replace("\\'", "'").strip()
        if desc and len(desc) > 3:
            descriptions[name] = desc

    # === Pattern 2: server.tool("name", `template literal desc`) ===
    p2 = r'\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*`([^`]*)`'
    for m in re.finditer(p2, source, re.DOTALL):
        if m.group(1) not in descriptions:
            desc = m.group(2).strip()
            if len(desc) > 5:
                descriptions[m.group(1)] = desc

    # === Pattern 3: Object literal with name + description ===
    # Handles cases like:
    #   { name: "tool_name", ... description: "..." }
    #   { name: "tool_name", ... description: `...` }
    # Name and description may not be adjacent (other fields in between)
    # Use a block-based approach: find objects with both name and description

    # Find all object-like blocks (between balanced braces at top level of arrays/assignments)
    # Instead of trying to parse braces, use a simpler approach:
    # Find all name: "..." followed by description: "..." or `...` within reasonable distance

    # Forward: name then description
    p3a = r'name\s*:\s*["\']([^"\']+)["\']\s*,(?:[^{}]*?)description\s*:\s*(?:"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'|`([^`]*)`)'
    for m in re.finditer(p3a, source, re.DOTALL):
        name = m.group(1)
        desc = (m.group(2) or m.group(3) or m.group(4) or "").strip()
        if name not in descriptions and desc and len(desc) > 3:
            # Clean escape sequences
            desc = desc.replace('\\"', '"').replace("\\'", "'").replace("\\n", "\n")
            descriptions[name] = desc

    # Backward: description then name
    p3b = r'description\s*:\s*(?:"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'|`([^`]*)`)\s*,(?:[^{}]*?)name\s*:\s*["\']([^"\']+)["\']'
    for m in re.finditer(p3b, source, re.DOTALL):
        desc = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        name = m.group(4)
        if name not in descriptions and desc and len(desc) > 3:
            desc = desc.replace('\\"', '"').replace("\\'", "'").replace("\\n", "\n")
            descriptions[name] = desc

    # === Pattern 4: Multi-line description with + concatenation ===
    # description: "line1" +
    #   "line2"
    # We handle this by joining adjacent string literals
    p4 = r'name\s*:\s*["\']([^"\']+)["\']'
    for m in re.finditer(p4, source):
        name = m.group(1)
        if name in descriptions:
            continue
        # Look for description within the next 2000 chars
        after = source[m.end():m.end()+2000]
        desc_match = re.search(
            r'description\s*:\s*\n?\s*(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)',
            after, re.DOTALL
        )
        if desc_match:
            desc = (desc_match.group(1) or desc_match.group(2) or "").strip()
            if desc and len(desc) > 3:
                desc = desc.replace('\\"', '"').replace("\\n", "\n")
                descriptions[name] = desc

    # === Pattern 5: server.tool("name", { description: "..." }) ===
    p5 = r'\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*?description\s*:\s*(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)'
    for m in re.finditer(p5, source, re.DOTALL):
        name = m.group(1)
        if name not in descriptions:
            desc = (m.group(2) or m.group(3) or "").strip()
            if desc:
                descriptions[name] = desc

    return descriptions


def extract_json_descriptions(content):
    descriptions = {}
    try:
        data = json.loads(content)
        _walk_json(data, descriptions)
    except (json.JSONDecodeError, RecursionError):
        pass
    return descriptions


def _walk_json(obj, descriptions, depth=0):
    if depth > 10:
        return
    if isinstance(obj, dict):
        if "name" in obj and "description" in obj:
            n, d = obj["name"], obj["description"]
            if isinstance(n, str) and isinstance(d, str) and d:
                descriptions[n] = d.strip()
        for v in obj.values():
            _walk_json(v, descriptions, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _walk_json(item, descriptions, depth + 1)


# =========================================================================
# File discovery
# =========================================================================

SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    ".next", "coverage", ".cache", "vendor",
})

MCP_PATTERNS_PY = [
    "@server.tool", "@mcp.tool", "@app.tool",
    "add_tool(", ".tool(", "fastmcp",
    "McpServer", "mcp.server",
]

MCP_PATTERNS_TS = [
    "server.tool(", ".tool(",
    "McpServer", "@modelcontextprotocol",
    "listTools", "CallToolRequest",
]


def find_mcp_files(repo_dir, language):
    """Find files that likely contain MCP tool definitions."""
    exts = {".py"} if language == "python" else {".ts", ".tsx", ".js", ".jsx", ".mjs"}
    patterns = MCP_PATTERNS_PY if language == "python" else MCP_PATTERNS_TS

    server_files = []
    # Also search for name+description patterns (covers ToolDefinition objects)
    desc_patterns = ["description:", "description\":", "description':", 'description":']

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in exts:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    head = f.read(8000)
                if any(p in head for p in patterns) or any(p in head for p in desc_patterns):
                    server_files.append(fpath)
            except Exception:
                pass

    return server_files


def extract_from_repo(repo_dir, language, tool_names):
    """Extract descriptions for tools from a repo directory."""
    all_descriptions = {}

    server_files = find_mcp_files(repo_dir, language)

    for fpath in server_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            continue

        if language == "python":
            descs = extract_python_descriptions(source)
        else:
            descs = extract_ts_descriptions(source)

        all_descriptions.update(descs)

    # Also check JSON files for tool manifests
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not fname.endswith(".json"):
                continue
            if "package-lock" in fname or "tsconfig" in fname:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(50000)
                if any(tn in content for tn in tool_names):
                    descs = extract_json_descriptions(content)
                    for k, v in descs.items():
                        if k not in all_descriptions:
                            all_descriptions[k] = v
            except Exception:
                pass

    return all_descriptions


# =========================================================================
# Main
# =========================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract MCP tool descriptions")
    parser.add_argument("--results", required=True, help="mass_analysis_results.jsonl")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument("--limit", type=int, default=0, help="Limit repos (0=all)")
    parser.add_argument("--resume", action="store_true", help="Resume from existing output")
    args = parser.parse_args()

    entries = []
    with open(args.results) as f:
        for line in f:
            entries.append(json.loads(line))

    print(f"Loaded {len(entries)} server entries, {sum(len(e['tools']) for e in entries)} tools")

    done_repos = set()
    if args.resume and os.path.exists(args.output):
        with open(args.output) as f:
            for line in f:
                done_repos.add(json.loads(line)["repo"])
        print(f"Resuming: {len(done_repos)} already done")

    total_tools = 0
    tools_with_desc = 0
    tools_without_desc = 0
    processed = 0
    clone_failures = 0

    mode = "a" if args.resume and done_repos else "w"
    with open(args.output, mode) as out_f:
        for i, entry in enumerate(entries):
            repo = entry["repo"]
            language = entry["language"]

            if repo in done_repos:
                continue
            if args.limit and processed >= args.limit:
                break

            tool_names = {t["name"] for t in entry["tools"]}
            entry_copy = dict(entry)

            if repo.startswith("existing/"):
                descriptions = {}
                desc_source = "local_not_available"
                print(f"[{i+1}/{len(entries)}] {repo} -> local (skipped)")
            else:
                clone_dir = os.path.join(CLONE_BASE, repo.replace("/", "_"))
                print(f"[{i+1}/{len(entries)}] {repo} ({language})...", end=" ", flush=True)

                if os.path.exists(clone_dir):
                    shutil.rmtree(clone_dir, ignore_errors=True)

                success = clone_repo(repo, clone_dir)
                if success:
                    descriptions = extract_from_repo(clone_dir, language, tool_names)
                    desc_source = "extracted"
                    matched = len(set(descriptions.keys()) & tool_names)
                    print(f"{matched}/{len(tool_names)} descriptions")
                else:
                    descriptions = {}
                    desc_source = "clone_failed"
                    clone_failures += 1
                    print("CLONE FAILED")

                if os.path.exists(clone_dir):
                    shutil.rmtree(clone_dir, ignore_errors=True)

            for tool in entry_copy["tools"]:
                tn = tool["name"]
                if tn in descriptions:
                    tool["description"] = descriptions[tn]
                    tool["description_source"] = desc_source
                    tools_with_desc += 1
                else:
                    tool["description"] = None
                    tool["description_source"] = (
                        desc_source if desc_source != "extracted" else "not_found"
                    )
                    tools_without_desc += 1
                total_tools += 1

            out_f.write(json.dumps(entry_copy) + "\n")
            out_f.flush()
            processed += 1

    shutil.rmtree(CLONE_BASE, ignore_errors=True)

    print(f"\n{'='*60}")
    print(f"Processed: {processed} repos")
    print(f"Clone failures: {clone_failures}")
    print(f"Total tools: {total_tools}")
    print(f"With description: {tools_with_desc} ({100*tools_with_desc/max(total_tools,1):.1f}%)")
    print(f"Without description: {tools_without_desc}")


if __name__ == "__main__":
    main()
