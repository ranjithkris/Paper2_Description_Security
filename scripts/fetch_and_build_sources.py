#!/usr/bin/env python3
"""
Programmatically fetch security source descriptions and build derived
analysis data (keywords + reference texts).

Sources:
  1. MITRE CWE XML database (cwec_latest.xml.zip)
  2. CodeQL query metadata (github/codeql repository)
  3. Semgrep rule descriptions (semgrep/semgrep-rules repository)
  4. Bandit check descriptions (PyCQA/bandit repository)

Outputs:
  data/security_source_corpus.json   - Raw fetched descriptions
  data/derived_keywords.json         - Keywords with source citations
  data/reference_texts.json          - Concatenated reference texts

Usage:
    python3 scripts/fetch_and_build_sources.py [--work-dir /tmp/security_sources]

The --work-dir flag keeps cloned repos for inspection (default: temp dir, cleaned up).

Requirements: requests, pyyaml, git
"""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

try:
    import yaml
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml"])
    import yaml

# ─── Paths ───────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
DATA_DIR = PROJECT_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Import SECURITY_OPERATIONS to know which sources to look up
sys.path.insert(0, str(SCRIPT_DIR))
from trusted_security_registry import SECURITY_OPERATIONS, SECURITY_PROPERTIES


# ─── English stop words (NLTK list + generic terms) ──────────────────────

STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "also", "am",
    "an", "and", "any", "are", "aren", "as", "at", "be", "because", "been",
    "before", "being", "below", "between", "both", "but", "by", "can", "could",
    "d", "did", "didn", "do", "does", "doesn", "doing", "don", "down", "during",
    "each", "even", "few", "for", "from", "further", "get", "got", "had", "has",
    "hasn", "have", "haven", "having", "he", "her", "here", "hers", "herself",
    "him", "himself", "his", "how", "however", "i", "if", "in", "into", "is",
    "isn", "it", "its", "itself", "just", "ll", "m", "ma", "me", "might",
    "more", "most", "much", "must", "my", "myself", "need", "no", "nor", "not",
    "now", "o", "of", "off", "on", "once", "only", "or", "other", "our", "ours",
    "ourselves", "out", "over", "own", "re", "s", "same", "shan", "she", "should",
    "shouldn", "so", "some", "such", "t", "than", "that", "the", "their",
    "theirs", "them", "themselves", "then", "there", "therefore", "these", "they",
    "this", "those", "through", "thus", "to", "too", "under", "until", "up",
    "upon", "us", "ve", "very", "was", "wasn", "we", "were", "weren", "what",
    "when", "where", "which", "while", "who", "whom", "whose", "why", "will",
    "with", "won", "would", "wouldn", "y", "you", "your", "yours", "yourself",
    "yourselves",
    # Additional generic terms not useful as keywords
    "also", "another", "since", "still", "without", "within", "along", "among",
    "around", "either", "neither", "whether", "although", "though", "unless",
    "towards", "toward", "across", "yet", "already", "often", "always", "never",
    "sometimes", "usually", "rather", "may", "shall",
    "example", "following", "note", "see", "e.g", "i.e", "etc",
}


# ─── Utility ─────────────────────────────────────────────────────────────

def run_git(args, cwd=None):
    """Run a git command, return (success, stdout)."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.returncode == 0, result.stdout
    except Exception as e:
        return False, str(e)


def clean_text(text):
    """Normalize whitespace in text."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


# ═══════════════════════════════════════════════════════════════════════════
# PART 1: FETCH CWE DESCRIPTIONS
# ═══════════════════════════════════════════════════════════════════════════

def fetch_cwe_descriptions(work_dir):
    """Download MITRE CWE XML database and extract descriptions."""
    print("=" * 70)
    print("FETCHING CWE DESCRIPTIONS FROM MITRE")
    print("=" * 70)

    # Collect all CWE IDs we need
    all_cwe_ids = set()
    for prop_data in SECURITY_OPERATIONS.values():
        for cwe_id in prop_data.get("cwes", []):
            # Normalize: "CWE-078" -> "78"
            num = cwe_id.replace("CWE-", "").lstrip("0") or "0"
            all_cwe_ids.add(num)

    print(f"  Need {len(all_cwe_ids)} CWE definitions: {sorted(all_cwe_ids, key=int)}")

    xml_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    zip_path = os.path.join(work_dir, "cwec_latest.xml.zip")

    print(f"  Downloading {xml_url} ...")
    try:
        resp = requests.get(xml_url, timeout=180, stream=True)
        resp.raise_for_status()
        with open(zip_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"  Downloaded {os.path.getsize(zip_path) / 1024 / 1024:.1f} MB")
    except Exception as e:
        print(f"  ERROR downloading CWE XML: {e}")
        print("  Falling back to individual page fetching...")
        return _fetch_cwe_individual(all_cwe_ids)

    # Extract ZIP
    print("  Extracting XML...")
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            xml_files = [f for f in z.namelist() if f.endswith(".xml")]
            if not xml_files:
                print("  ERROR: No XML file found in ZIP")
                return {}
            z.extractall(work_dir, xml_files)
            xml_path = os.path.join(work_dir, xml_files[0])
            print(f"  Extracted: {xml_files[0]}")
    except Exception as e:
        print(f"  ERROR extracting ZIP: {e}")
        return {}

    # Parse XML
    print("  Parsing CWE definitions...")
    import xml.etree.ElementTree as ET

    try:
        tree = ET.parse(xml_path)
    except Exception as e:
        print(f"  ERROR parsing XML: {e}")
        return {}

    root = tree.getroot()

    # Detect namespace
    ns_uri = ""
    ns_match = re.match(r"\{(.+?)\}", root.tag)
    if ns_match:
        ns_uri = ns_match.group(1)

    def tag(name):
        return f"{{{ns_uri}}}{name}" if ns_uri else name

    cwe_data = {}

    for weakness in root.iter(tag("Weakness")):
        cwe_id = weakness.get("ID", "")
        if cwe_id not in all_cwe_ids:
            continue

        name = weakness.get("Name", "")

        # Description
        desc_elem = weakness.find(tag("Description"))
        desc = clean_text("".join(desc_elem.itertext())) if desc_elem is not None else ""

        # Extended_Description
        ext_elem = weakness.find(tag("Extended_Description"))
        ext_desc = clean_text("".join(ext_elem.itertext())) if ext_elem is not None else ""

        cwe_data[cwe_id] = {
            "id": f"CWE-{cwe_id}",
            "name": name,
            "description": desc,
            "extended_description": ext_desc,
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            "source": "MITRE CWE XML Database",
        }
        print(f"    CWE-{cwe_id}: {name}")

    missing = all_cwe_ids - set(cwe_data.keys())
    if missing:
        print(f"  WARNING: Missing CWEs: {sorted(missing, key=int)}")

    print(f"  Fetched {len(cwe_data)}/{len(all_cwe_ids)} CWE definitions")
    return cwe_data


def _fetch_cwe_individual(cwe_ids):
    """Fallback: fetch individual CWE pages via web."""
    cwe_data = {}
    for cwe_id in sorted(cwe_ids, key=int):
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            html = resp.text

            # Extract name from title
            name_match = re.search(r"<title>CWE\s*-\s*CWE-\d+:\s*(.+?)</title>", html)
            name = name_match.group(1).strip() if name_match else ""

            # Extract description (div with id="Description")
            desc_match = re.search(
                r'<div\s+id="Description"[^>]*>(.*?)</div>',
                html, re.DOTALL
            )
            desc = ""
            if desc_match:
                desc = re.sub(r"<[^>]+>", " ", desc_match.group(1))
                desc = clean_text(desc)

            cwe_data[cwe_id] = {
                "id": f"CWE-{cwe_id}",
                "name": name,
                "description": desc,
                "extended_description": "",
                "url": url,
                "source": "MITRE CWE Website (individual page)",
            }
            print(f"    CWE-{cwe_id}: {name}")
        except Exception as e:
            print(f"    ERROR fetching CWE-{cwe_id}: {e}")

    return cwe_data


# ═══════════════════════════════════════════════════════════════════════════
# PART 2: FETCH CODEQL QUERY DESCRIPTIONS
# ═══════════════════════════════════════════════════════════════════════════

def fetch_codeql_descriptions(work_dir):
    """Clone CodeQL repo (sparse) and extract query metadata."""
    print("\n" + "=" * 70)
    print("FETCHING CODEQL QUERY DESCRIPTIONS")
    print("=" * 70)

    repo_dir = os.path.join(work_dir, "codeql")

    # Collect all CodeQL query IDs we need from SECURITY_OPERATIONS
    needed_ids = set()
    for prop_data in SECURITY_OPERATIONS.values():
        for lang_data in ["python", "typescript", "javascript"]:
            ops = prop_data.get(lang_data, [])
            if not ops:
                continue
            for op in ops:
                for src in op.get("sources", []):
                    if src.startswith("CodeQL "):
                        qid = src.replace("CodeQL ", "").strip()
                        needed_ids.add(qid)
    print(f"  Need {len(needed_ids)} CodeQL queries: {sorted(needed_ids)}")

    # Sparse clone
    sparse_dirs = [
        "python/ql/src/Security",
        "javascript/ql/src/Security",
    ]

    print("  Cloning github/codeql (sparse checkout, depth 1)...")
    ok, _ = run_git([
        "clone", "--depth", "1", "--filter=blob:none", "--sparse",
        "https://github.com/github/codeql.git", repo_dir,
    ])
    if not ok:
        print("  ERROR: Failed to clone CodeQL repo")
        return {}

    ok, _ = run_git(
        ["-C", repo_dir, "sparse-checkout", "set"] + sparse_dirs
    )
    if not ok:
        print("  WARNING: Sparse checkout failed, trying full checkout...")

    # Parse all .ql files
    queries = {}
    for sdir in sparse_dirs:
        full_dir = os.path.join(repo_dir, sdir)
        if not os.path.isdir(full_dir):
            print(f"  WARNING: Directory not found: {sdir}")
            continue

        for root_path, dirs, files in os.walk(full_dir):
            for fname in files:
                if not fname.endswith(".ql"):
                    continue
                fpath = os.path.join(root_path, fname)
                meta = _parse_ql_metadata(fpath)
                if meta and meta.get("id"):
                    qid = meta["id"]
                    meta["file_path"] = os.path.relpath(fpath, repo_dir)
                    meta["source"] = f"github/codeql:{meta['file_path']}"
                    queries[qid] = meta

    # Also parse .qhelp files for extended help text
    for sdir in sparse_dirs:
        full_dir = os.path.join(repo_dir, sdir)
        if not os.path.isdir(full_dir):
            continue
        for root_path, dirs, files in os.walk(full_dir):
            for fname in files:
                if not fname.endswith(".qhelp"):
                    continue
                fpath = os.path.join(root_path, fname)
                try:
                    with open(fpath) as f:
                        content = f.read()
                    text = re.sub(r"<[^>]+>", " ", content)
                    text = clean_text(text)
                    # Match to query by filename
                    base = fname.replace(".qhelp", "")
                    for qid, qdata in queries.items():
                        qfile = os.path.basename(qdata.get("file_path", ""))
                        if qfile.replace(".ql", "") == base:
                            qdata["help_text"] = text
                except Exception:
                    pass

    # Report
    found = set(queries.keys()) & needed_ids
    missing = needed_ids - set(queries.keys())
    print(f"  Found {len(found)}/{len(needed_ids)} needed CodeQL queries")
    for qid in sorted(found):
        desc = queries[qid].get("description", "")[:80]
        print(f"    {qid}: {desc}...")
    if missing:
        print(f"  Missing: {sorted(missing)}")

    return queries


def _parse_ql_metadata(filepath):
    """Parse @key value metadata from a CodeQL .ql file doc comment."""
    try:
        with open(filepath) as f:
            content = f.read()
    except Exception:
        return None

    match = re.search(r"/\*\*(.*?)\*/", content, re.DOTALL)
    if not match:
        return None

    comment = match.group(1)
    meta = {}

    # Parse @key value (value may span multiple lines until next @key)
    parts = re.split(r"\n\s*\*\s*@", comment)
    for i, part in enumerate(parts):
        if i == 0:
            continue  # skip text before first @
        kv = re.match(r"(\w[\w-]*)\s+(.*)", part, re.DOTALL)
        if kv:
            key = kv.group(1)
            val = kv.group(2)
            # Clean up: remove leading * from continuation lines
            val = re.sub(r"\n\s*\*\s*", " ", val).strip()
            meta[key] = val

    return meta


# ═══════════════════════════════════════════════════════════════════════════
# PART 3: FETCH SEMGREP RULE DESCRIPTIONS
# ═══════════════════════════════════════════════════════════════════════════

def fetch_semgrep_descriptions(work_dir):
    """Clone Semgrep rules repo and extract rule descriptions."""
    print("\n" + "=" * 70)
    print("FETCHING SEMGREP RULE DESCRIPTIONS")
    print("=" * 70)

    repo_dir = os.path.join(work_dir, "semgrep-rules")

    # Collect needed Semgrep rule IDs from SECURITY_OPERATIONS
    needed_ids = set()
    for prop_data in SECURITY_OPERATIONS.values():
        for lang_data in ["python", "typescript", "javascript"]:
            ops = prop_data.get(lang_data, [])
            if not ops:
                continue
            for op in ops:
                for src in op.get("sources", []):
                    if src.startswith("Semgrep "):
                        rule_id = src.replace("Semgrep ", "").strip()
                        needed_ids.add(rule_id)
    print(f"  Need {len(needed_ids)} Semgrep rules: {sorted(needed_ids)}")

    # Shallow clone
    print("  Cloning semgrep/semgrep-rules (depth 1)...")
    ok, _ = run_git([
        "clone", "--depth", "1",
        "https://github.com/semgrep/semgrep-rules.git", repo_dir,
    ])
    if not ok:
        print("  ERROR: Failed to clone Semgrep rules repo")
        return {}

    # Parse all YAML rule files
    rules = {}
    search_dirs = ["python", "javascript", "typescript", "generic"]

    for sdir in search_dirs:
        full_dir = os.path.join(repo_dir, sdir)
        if not os.path.isdir(full_dir):
            continue
        for root_path, dirs, files in os.walk(full_dir):
            # Skip test directories
            if any(skip in root_path for skip in ["test", "tests", "__pycache__"]):
                continue
            for fname in files:
                if not fname.endswith((".yaml", ".yml")):
                    continue
                fpath = os.path.join(root_path, fname)
                try:
                    with open(fpath) as f:
                        data = yaml.safe_load(f)
                    if not data or "rules" not in data:
                        continue
                    for rule in data["rules"]:
                        rule_id = rule.get("id", "")
                        if not rule_id:
                            continue
                        # Build full rule path ID
                        rel_path = os.path.relpath(fpath, repo_dir)
                        # Convert path to dotted ID: python/lang/security/foo.yaml -> python.lang.security.foo
                        full_id = rel_path.replace(os.sep, ".").replace("/", ".")
                        full_id = re.sub(r"\.(yaml|yml)$", "", full_id)

                        entry = {
                            "id": rule_id,
                            "full_id": full_id,
                            "message": rule.get("message", ""),
                            "severity": rule.get("severity", ""),
                            "metadata": rule.get("metadata", {}),
                            "file_path": rel_path,
                            "source": f"semgrep/semgrep-rules:{rel_path}",
                        }
                        # Store by both short and full ID
                        rules[full_id] = entry
                        rules[rule_id] = entry
                except Exception:
                    pass

    # Match needed IDs
    matched = {}
    for needed in needed_ids:
        # Try exact match
        if needed in rules:
            matched[needed] = rules[needed]
            continue
        # Try partial match (the needed ID might be a substring)
        for rid, rdata in rules.items():
            if needed in rid or rid.endswith(needed.split(".")[-1]):
                matched[needed] = rdata
                break

    print(f"  Found {len(matched)}/{len(needed_ids)} needed Semgrep rules")
    for rid in sorted(matched):
        msg = matched[rid].get("message", "")[:80]
        print(f"    {rid}: {msg}...")

    missing = needed_ids - set(matched.keys())
    if missing:
        print(f"  Missing: {sorted(missing)}")

    # Return all security-related rules (not just needed ones)
    # This gives more text for TF-IDF reference building
    all_security = {}
    for rid, rdata in rules.items():
        meta = rdata.get("metadata", {})
        if (
            "security" in rid.lower()
            or "security" in str(meta.get("category", "")).lower()
            or meta.get("cwe")
            or "injection" in rid.lower()
            or "audit" in rid.lower()
        ):
            all_security[rid] = rdata

    print(f"  Total security-related rules found: {len(all_security)}")
    return {"matched": matched, "all_security": all_security}


# ═══════════════════════════════════════════════════════════════════════════
# PART 4: FETCH BANDIT CHECK DESCRIPTIONS
# ═══════════════════════════════════════════════════════════════════════════

def fetch_bandit_descriptions(work_dir):
    """Clone Bandit repo and extract check descriptions from plugin docstrings."""
    print("\n" + "=" * 70)
    print("FETCHING BANDIT CHECK DESCRIPTIONS")
    print("=" * 70)

    repo_dir = os.path.join(work_dir, "bandit")

    # Collect needed Bandit check IDs
    needed_ids = set()
    for prop_data in SECURITY_OPERATIONS.values():
        for lang_data in ["python", "typescript", "javascript"]:
            ops = prop_data.get(lang_data, [])
            if not ops:
                continue
            for op in ops:
                for src in op.get("sources", []):
                    if src.startswith("Bandit "):
                        # Extract check ID: "Bandit B603 (desc)" -> "B603"
                        bid_match = re.match(r"Bandit (B\d+)", src)
                        if bid_match:
                            needed_ids.add(bid_match.group(1))
    print(f"  Need {len(needed_ids)} Bandit checks: {sorted(needed_ids)}")

    # Clone
    print("  Cloning PyCQA/bandit (depth 1)...")
    ok, _ = run_git([
        "clone", "--depth", "1",
        "https://github.com/PyCQA/bandit.git", repo_dir,
    ])
    if not ok:
        print("  ERROR: Failed to clone Bandit repo")
        return {}

    checks = {}

    # Parse plugin files
    plugins_dir = os.path.join(repo_dir, "bandit", "plugins")
    if not os.path.isdir(plugins_dir):
        print(f"  WARNING: plugins dir not found at {plugins_dir}")
        # Try alternative path
        plugins_dir = os.path.join(repo_dir, "src", "bandit", "plugins")
        if not os.path.isdir(plugins_dir):
            print("  ERROR: Cannot find bandit plugins directory")
            return {}

    for fname in sorted(os.listdir(plugins_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        fpath = os.path.join(plugins_dir, fname)
        try:
            with open(fpath) as f:
                content = f.read()

            # Extract module docstring
            docstring = ""
            # Try triple-double-quote
            ds_match = re.match(
                r'(?:\s*#[^\n]*\n)*\s*r?"""(.*?)"""', content, re.DOTALL
            )
            if not ds_match:
                # Try triple-single-quote
                ds_match = re.match(
                    r"(?:\s*#[^\n]*\n)*\s*r?'''(.*?)'''", content, re.DOTALL
                )
            if ds_match:
                docstring = clean_text(ds_match.group(1))

            # Find all check IDs in the file
            check_ids = set(re.findall(r"\b(B\d{3})\b", content))

            for cid in check_ids:
                if cid not in checks:
                    checks[cid] = {
                        "id": cid,
                        "file": fname,
                        "docstring": docstring,
                        "file_path": os.path.relpath(fpath, repo_dir),
                        "source": f"PyCQA/bandit:{os.path.relpath(fpath, repo_dir)}",
                    }
        except Exception as e:
            print(f"    ERROR parsing {fname}: {e}")

    # Also check docs directory for .rst documentation
    for doc_dir_candidate in [
        os.path.join(repo_dir, "doc", "source", "plugins"),
        os.path.join(repo_dir, "docs", "source", "plugins"),
        os.path.join(repo_dir, "doc", "plugins"),
    ]:
        if os.path.isdir(doc_dir_candidate):
            for fname in os.listdir(doc_dir_candidate):
                if not fname.endswith(".rst"):
                    continue
                fpath = os.path.join(doc_dir_candidate, fname)
                try:
                    with open(fpath) as f:
                        doc_text = clean_text(f.read())
                    cids = set(re.findall(r"\b(B\d{3})\b", doc_text))
                    for cid in cids:
                        if cid in checks:
                            checks[cid]["doc_text"] = doc_text
                        else:
                            checks[cid] = {
                                "id": cid,
                                "file": fname,
                                "docstring": doc_text,
                                "file_path": os.path.relpath(fpath, repo_dir),
                                "source": f"PyCQA/bandit:{os.path.relpath(fpath, repo_dir)}",
                            }
                except Exception:
                    pass
            break

    found = needed_ids & set(checks.keys())
    missing = needed_ids - set(checks.keys())
    print(f"  Found {len(found)}/{len(needed_ids)} needed Bandit checks")
    for cid in sorted(found):
        doc = checks[cid].get("docstring", "")[:80]
        print(f"    {cid}: {doc}...")
    if missing:
        print(f"  Missing: {sorted(missing)}")

    return checks


# ═══════════════════════════════════════════════════════════════════════════
# PART 5: MAP SOURCES TO PROPERTIES
# ═══════════════════════════════════════════════════════════════════════════

def map_sources_to_properties(cwe_data, codeql_data, semgrep_data, bandit_data):
    """
    Map all fetched source descriptions to security properties.

    Returns: {property: [{"source_id": ..., "text": ..., "source_type": ...}, ...]}
    """
    print("\n" + "=" * 70)
    print("MAPPING SOURCES TO PROPERTIES")
    print("=" * 70)

    property_texts = defaultdict(list)

    for prop, prop_data in SECURITY_OPERATIONS.items():
        # 1. CWE descriptions
        for cwe_id in prop_data.get("cwes", []):
            num = cwe_id.replace("CWE-", "").lstrip("0") or "0"
            if num in cwe_data:
                cwe = cwe_data[num]
                texts = []
                if cwe.get("name"):
                    texts.append(f"CWE name: {cwe['name']}")
                if cwe.get("description"):
                    texts.append(cwe["description"])
                if cwe.get("extended_description"):
                    texts.append(cwe["extended_description"])
                combined = " ".join(texts)
                if combined.strip():
                    property_texts[prop].append({
                        "source_id": cwe["id"],
                        "source_type": "CWE",
                        "text": combined,
                        "name": cwe.get("name", ""),
                        "url": cwe.get("url", ""),
                    })

        # 2. CodeQL + Semgrep + Bandit from operation sources
        for lang in ["python", "typescript", "javascript"]:
            ops = prop_data.get(lang, [])
            if not ops:
                continue
            for op in ops:
                for src in op.get("sources", []):
                    if src.startswith("CodeQL "):
                        qid = src.replace("CodeQL ", "").strip()
                        if qid in codeql_data:
                            q = codeql_data[qid]
                            texts = []
                            if q.get("name"):
                                texts.append(f"Query: {q['name']}")
                            if q.get("description"):
                                texts.append(q["description"])
                            if q.get("help_text"):
                                texts.append(q["help_text"])
                            combined = " ".join(texts)
                            # Avoid duplicates
                            if not any(
                                e["source_id"] == f"CodeQL {qid}"
                                for e in property_texts[prop]
                            ):
                                property_texts[prop].append({
                                    "source_id": f"CodeQL {qid}",
                                    "source_type": "CodeQL",
                                    "text": combined,
                                    "file_path": q.get("file_path", ""),
                                })

                    elif src.startswith("Semgrep "):
                        rule_id = src.replace("Semgrep ", "").strip()
                        semgrep_matched = semgrep_data.get("matched", {})
                        if rule_id in semgrep_matched:
                            r = semgrep_matched[rule_id]
                            text = r.get("message", "")
                            if not any(
                                e["source_id"] == f"Semgrep {rule_id}"
                                for e in property_texts[prop]
                            ):
                                property_texts[prop].append({
                                    "source_id": f"Semgrep {rule_id}",
                                    "source_type": "Semgrep",
                                    "text": text,
                                    "file_path": r.get("file_path", ""),
                                })

                    elif src.startswith("Bandit "):
                        bid_match = re.match(r"Bandit (B\d+)", src)
                        if bid_match:
                            bid = bid_match.group(1)
                            if bid in bandit_data:
                                b = bandit_data[bid]
                                text = b.get("docstring", "") or b.get("doc_text", "")
                                if not any(
                                    e["source_id"] == f"Bandit {bid}"
                                    for e in property_texts[prop]
                                ):
                                    property_texts[prop].append({
                                        "source_id": f"Bandit {bid}",
                                        "source_type": "Bandit",
                                        "text": text,
                                        "file_path": b.get("file_path", ""),
                                    })

    # Report
    for prop in SECURITY_PROPERTIES:
        sources = property_texts.get(prop, [])
        total_chars = sum(len(s["text"]) for s in sources)
        print(f"  {prop}: {len(sources)} sources, {total_chars} chars total")
        for s in sources:
            print(f"    - {s['source_id']} ({len(s['text'])} chars)")

    return dict(property_texts)


# ═══════════════════════════════════════════════════════════════════════════
# PART 6: EXTRACT KEYWORDS PROGRAMMATICALLY
# ═══════════════════════════════════════════════════════════════════════════

def tokenize(text):
    """Tokenize text into lowercase words."""
    return re.findall(r"[a-z][a-z0-9_-]*(?:'[a-z]+)?", text.lower())


def extract_ngrams(tokens, n=2):
    """Extract n-grams from token list."""
    return [" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


def extract_keywords(property_texts):
    """
    Extract keywords for each property from source descriptions.

    Methodology:
      1. Tokenize all source descriptions for each property
      2. Build unigram and bigram candidates
      3. Remove stop words
      4. Score by TF-IDF (term frequency-inverse property frequency)
      5. Keep terms with score above threshold
      6. Record exact source citation for each keyword
    """
    print("\n" + "=" * 70)
    print("EXTRACTING KEYWORDS")
    print("=" * 70)

    # Step 1: Build term-property document matrix
    # Each property's combined source text is one "document"
    property_tokens = {}
    for prop in SECURITY_PROPERTIES:
        sources = property_texts.get(prop, [])
        all_text = " ".join(s["text"] for s in sources)
        tokens = tokenize(all_text)
        # Filter stop words for unigrams
        filtered = [t for t in tokens if t not in STOP_WORDS and len(t) >= 3]
        # Also get bigrams (from unfiltered tokens, then filter)
        bigrams = extract_ngrams(tokens, 2)
        bigrams_filtered = [
            bg for bg in bigrams
            if not all(w in STOP_WORDS for w in bg.split())
        ]
        property_tokens[prop] = {
            "unigrams": filtered,
            "bigrams": bigrams_filtered,
        }

    # Step 2: Compute TF-IDF for each term per property
    # TF = count(term in property) / total_terms_in_property
    # IDF = log(N / (1 + properties_containing_term))

    N = len(SECURITY_PROPERTIES)

    # Count which properties contain each term
    term_property_count = Counter()  # term -> number of properties containing it
    for prop in SECURITY_PROPERTIES:
        tdata = property_tokens.get(prop, {})
        terms_in_prop = set(tdata.get("unigrams", []) + tdata.get("bigrams", []))
        for term in terms_in_prop:
            term_property_count[term] += 1

    # Compute TF-IDF scores
    property_keywords = {}

    for prop in SECURITY_PROPERTIES:
        tdata = property_tokens.get(prop, {})
        all_terms = tdata.get("unigrams", []) + tdata.get("bigrams", [])
        if not all_terms:
            property_keywords[prop] = {}
            continue

        term_counts = Counter(all_terms)
        total_terms = len(all_terms)

        scored = {}
        for term, count in term_counts.items():
            tf = count / total_terms
            idf = math.log(N / (1 + term_property_count.get(term, 0)))
            tfidf = tf * idf
            scored[term] = {
                "tfidf_score": round(tfidf, 6),
                "tf": round(tf, 6),
                "idf": round(idf, 4),
                "count": count,
            }

        # Step 3: Keep terms above threshold OR that appear in CWE names
        # Use adaptive threshold: top percentile of scores
        if scored:
            scores = sorted([s["tfidf_score"] for s in scored.values()], reverse=True)
            # Keep top terms: at least 15, at most 50, or 20th percentile
            n_keep = max(15, min(50, len(scores) // 5))
            threshold = scores[min(n_keep, len(scores) - 1)]

            # Also always include terms from CWE names (they are definitional)
            cwe_name_terms = set()
            for src in property_texts.get(prop, []):
                if src["source_type"] == "CWE" and src.get("name"):
                    name_tokens = tokenize(src["name"])
                    for t in name_tokens:
                        if t not in STOP_WORDS and len(t) >= 3:
                            cwe_name_terms.add(t)
                    # Also add bigrams from CWE name
                    for bg in extract_ngrams(name_tokens, 2):
                        if not all(w in STOP_WORDS for w in bg.split()):
                            cwe_name_terms.add(bg)

            kept = {}
            for term, data in scored.items():
                if data["tfidf_score"] >= threshold or term in cwe_name_terms:
                    kept[term] = data

            property_keywords[prop] = kept
        else:
            property_keywords[prop] = {}

        print(f"  {prop}: {len(property_keywords[prop])} keywords")

    # Step 4: Add source citations for each keyword
    keyword_output = {}
    for prop in SECURITY_PROPERTIES:
        sources = property_texts.get(prop, [])
        keywords_with_citations = {}

        for term, score_data in property_keywords.get(prop, {}).items():
            # Find which sources contain this term
            citations = []
            for src in sources:
                text_lower = src["text"].lower()
                if term in text_lower:
                    # Extract context (surrounding words)
                    idx = text_lower.find(term)
                    start = max(0, idx - 40)
                    end = min(len(src["text"]), idx + len(term) + 40)
                    context = src["text"][start:end].strip()
                    if start > 0:
                        context = "..." + context
                    if end < len(src["text"]):
                        context = context + "..."

                    citations.append({
                        "source": src["source_id"],
                        "context": context,
                    })

            if citations:
                # Format citation string (compatible with existing format)
                first_citation = citations[0]
                citation_str = (
                    f"{first_citation['source']}: "
                    f"'{first_citation['context']}'"
                )
                keywords_with_citations[term] = {
                    "citation": citation_str,
                    "all_citations": citations,
                    "tfidf_score": score_data["tfidf_score"],
                    "count": score_data["count"],
                }

        keyword_output[prop] = {"keywords": keywords_with_citations}
        # Show top 5 per property
        top5 = sorted(
            keywords_with_citations.items(),
            key=lambda x: x[1]["tfidf_score"],
            reverse=True,
        )[:5]
        for kw, kdata in top5:
            print(f"    '{kw}' (score={kdata['tfidf_score']:.4f}) <- {kdata['citation'][:60]}...")

    return keyword_output


# ═══════════════════════════════════════════════════════════════════════════
# PART 7: BUILD REFERENCE TEXTS
# ═══════════════════════════════════════════════════════════════════════════

def build_reference_texts(property_texts):
    """
    Build reference texts for TF-IDF similarity by concatenating all
    source descriptions verbatim for each property.

    Each segment is labeled with its source ID.
    """
    print("\n" + "=" * 70)
    print("BUILDING REFERENCE TEXTS")
    print("=" * 70)

    reference_texts = {}

    for prop in SECURITY_PROPERTIES:
        sources = property_texts.get(prop, [])
        if not sources:
            reference_texts[prop] = {
                "text": "",
                "segments": [],
            }
            continue

        segments = []
        text_parts = []

        for src in sources:
            if not src["text"].strip():
                continue
            segments.append({
                "source_id": src["source_id"],
                "source_type": src["source_type"],
                "text": src["text"],
                "char_count": len(src["text"]),
            })
            text_parts.append(src["text"])

        combined = " ".join(text_parts)
        reference_texts[prop] = {
            "text": combined,
            "segments": segments,
            "total_chars": len(combined),
            "num_sources": len(segments),
        }

        print(f"  {prop}: {len(combined)} chars from {len(segments)} sources")

    return reference_texts


# ═══════════════════════════════════════════════════════════════════════════
# PART 8: MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Fetch security source descriptions and build derived data"
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help="Directory for cloned repos (default: temp dir, cleaned up after)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("SECURITY SOURCE DESCRIPTION FETCHER & BUILDER")
    print("=" * 70)
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Output dir: {DATA_DIR}")
    print()

    # Determine working directory
    if args.work_dir:
        work_dir = args.work_dir
        os.makedirs(work_dir, exist_ok=True)
        cleanup = False
    else:
        work_dir = tempfile.mkdtemp(prefix="security_sources_")
        cleanup = True

    print(f"Working directory: {work_dir}")
    print(f"  (cleanup after: {cleanup})")
    print()

    try:
        # FETCH from all sources
        cwe_data = fetch_cwe_descriptions(work_dir)
        codeql_data = fetch_codeql_descriptions(work_dir)
        semgrep_data = fetch_semgrep_descriptions(work_dir)
        bandit_data = fetch_bandit_descriptions(work_dir)

        # SAVE raw corpus
        corpus = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator": "fetch_and_build_sources.py",
                "sources": {
                    "cwe": {
                        "origin": "MITRE CWE XML Database (cwec_latest.xml.zip)",
                        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
                        "count": len(cwe_data),
                    },
                    "codeql": {
                        "origin": "github/codeql repository (main branch)",
                        "url": "https://github.com/github/codeql",
                        "count": len(codeql_data),
                    },
                    "semgrep": {
                        "origin": "semgrep/semgrep-rules repository",
                        "url": "https://github.com/semgrep/semgrep-rules",
                        "matched": len(semgrep_data.get("matched", {})),
                        "total_security": len(semgrep_data.get("all_security", {})),
                    },
                    "bandit": {
                        "origin": "PyCQA/bandit repository",
                        "url": "https://github.com/PyCQA/bandit",
                        "count": len(bandit_data),
                    },
                },
            },
            "cwe": cwe_data,
            "codeql": codeql_data,
            "semgrep_matched": semgrep_data.get("matched", {}),
            "bandit": bandit_data,
        }

        corpus_path = DATA_DIR / "security_source_corpus.json"
        with open(corpus_path, "w") as f:
            json.dump(corpus, f, indent=2, default=str)
        print(f"\nCorpus saved: {corpus_path}")

        # MAP sources to properties
        property_texts = map_sources_to_properties(
            cwe_data, codeql_data, semgrep_data, bandit_data
        )

        # Save property_texts for reproducibility
        prop_texts_path = DATA_DIR / "property_source_texts.json"
        with open(prop_texts_path, "w") as f:
            json.dump(property_texts, f, indent=2, default=str)
        print(f"Property texts saved: {prop_texts_path}")

        # EXTRACT keywords
        keywords = extract_keywords(property_texts)

        # Save keywords in format compatible with trusted_security_registry.py
        # Format: {prop: {"keywords": {term: "citation string", ...}}}
        keywords_compat = {}
        for prop in SECURITY_PROPERTIES:
            kws = keywords.get(prop, {}).get("keywords", {})
            keywords_compat[prop] = {
                "keywords": {
                    term: data["citation"]
                    for term, data in kws.items()
                }
            }

        keywords_path = DATA_DIR / "derived_keywords.json"
        with open(keywords_path, "w") as f:
            json.dump(keywords_compat, f, indent=2)
        print(f"Keywords saved: {keywords_path}")

        # Also save detailed keywords (with scores and all citations)
        keywords_detail_path = DATA_DIR / "derived_keywords_detailed.json"
        with open(keywords_detail_path, "w") as f:
            json.dump(keywords, f, indent=2, default=str)
        print(f"Detailed keywords saved: {keywords_detail_path}")

        # BUILD reference texts
        ref_texts = build_reference_texts(property_texts)

        # Save reference texts in compatible format
        # Format: {prop: "concatenated text"}
        ref_compat = {
            prop: data["text"]
            for prop, data in ref_texts.items()
        }
        ref_path = DATA_DIR / "reference_texts.json"
        with open(ref_path, "w") as f:
            json.dump(ref_compat, f, indent=2)
        print(f"Reference texts saved: {ref_path}")

        # Also save detailed reference texts (with segments)
        ref_detail_path = DATA_DIR / "reference_texts_detailed.json"
        with open(ref_detail_path, "w") as f:
            json.dump(ref_texts, f, indent=2, default=str)
        print(f"Detailed reference texts saved: {ref_detail_path}")

        # SUMMARY
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"CWE definitions fetched: {len(cwe_data)}")
        print(f"CodeQL queries fetched:  {len(codeql_data)}")
        print(f"Semgrep rules matched:   {len(semgrep_data.get('matched', {}))}")
        print(f"Bandit checks fetched:   {len(bandit_data)}")
        print()
        for prop in SECURITY_PROPERTIES:
            n_kw = len(keywords.get(prop, {}).get("keywords", {}))
            n_src = len(property_texts.get(prop, []))
            ref_len = len(ref_texts.get(prop, {}).get("text", ""))
            print(f"  {prop:<20} {n_kw:>3} keywords, {n_src:>2} sources, {ref_len:>5} chars ref text")
        print()
        print("Output files:")
        print(f"  {corpus_path}")
        print(f"  {prop_texts_path}")
        print(f"  {keywords_path}")
        print(f"  {keywords_detail_path}")
        print(f"  {ref_path}")
        print(f"  {ref_detail_path}")
        print()
        print("Next steps:")
        print("  1. Verify the generated data in data/*.json")
        print("  2. Run: python3 scripts/analyze_transparency_v2.py")
        print("     (trusted_security_registry.py will load the generated data)")
        print("=" * 70)

    finally:
        if cleanup and os.path.exists(work_dir):
            print(f"\nCleaning up: {work_dir}")
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
