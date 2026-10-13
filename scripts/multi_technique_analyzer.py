#!/usr/bin/env python3
"""
Multi-technique security transparency analysis for RQ1 and RQ3.

Applies FIVE techniques to measure whether MCP tool descriptions
communicate the security-relevant capabilities found in the code:

1. KEYWORD MATCHING   - exact/substring keyword lookup (baseline)
2. TF-IDF COSINE      - TF-IDF vectors + cosine similarity
3. SENTENCE EMBEDDINGS - all-MiniLM-L6-v2 semantic similarity
4. WORD MOVER DISTANCE - WMD via word embeddings (gensim)
5. BM25               - probabilistic information retrieval scoring

Each technique answers the same question per (tool, property) pair:
"Does the description communicate that the tool has this property?"

For techniques 2-5, a reference corpus of security property descriptions
is compared against each tool description.

Usage:
  pip install scikit-learn numpy scipy sentence-transformers gensim rank-bm25
  python3 scripts/multi_technique_analyzer.py \
    --input data/tools_with_descriptions.jsonl \
    --output results/multi_technique_results.jsonl \
    --summary results/multi_technique_summary.json

If sentence-transformers or gensim are not installed, those techniques
are skipped gracefully.
"""

import json
import math
import os
import re
import sys
import warnings
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")


# =========================================================================
# Security property definitions
# =========================================================================

SECURITY_PROPERTIES = [
    "COMMAND_EXEC", "FILE_SYSTEM", "NETWORK", "DATABASE",
    "INFO_EXPOSURE", "CRYPTO", "DESERIALIZATION", "AUTH",
]

PROPERTY_RISK = {
    "COMMAND_EXEC": "Critical",
    "FILE_SYSTEM": "High",
    "NETWORK": "High",
    "DATABASE": "High",
    "INFO_EXPOSURE": "Medium",
    "CRYPTO": "Medium",
    "DESERIALIZATION": "High",
    "AUTH": "High",
}

# Keywords per property (from CodeQL, Semgrep, Bandit categories)
SECURITY_KEYWORDS = {
    "COMMAND_EXEC": {
        "command", "execute", "exec", "shell", "subprocess", "process",
        "spawn", "run command", "system command", "terminal", "bash",
        "script", "invoke", "cli", "cmd", "os command", "child_process",
        "popen", "eval", "code execution", "arbitrary code",
        "run script", "shell command", "system call",
    },
    "FILE_SYSTEM": {
        "file", "read file", "write file", "directory", "folder", "path",
        "filesystem", "file system", "upload", "download", "save",
        "delete file", "remove file", "rename", "move file", "copy file",
        "create file", "open file", "disk", "storage", "local file",
        "file access", "file operation", "write to", "read from",
        "overwrite", "append", "mkdir", "rmdir", "unlink",
    },
    "NETWORK": {
        "network", "http", "https", "request", "api", "url", "endpoint",
        "fetch", "send request", "web request", "connect", "socket",
        "tcp", "udp", "dns", "port", "remote", "server", "client",
        "download", "upload", "webhook", "proxy", "ssl", "tls",
        "internet", "external service", "third-party", "outbound",
        "inbound", "api call", "rest", "graphql", "grpc",
    },
    "DATABASE": {
        "database", "db", "query", "sql", "table", "schema", "record",
        "insert", "update", "delete", "select", "join", "index",
        "collection", "document", "nosql", "mongo", "postgres",
        "mysql", "sqlite", "redis", "dynamodb", "firestore",
        "data store", "datastore", "crud", "transaction",
    },
    "INFO_EXPOSURE": {
        "environment", "env", "config", "configuration", "secret",
        "credential", "password", "token", "key", "api key",
        "sensitive", "private", "confidential", "expose", "leak",
        "disclosure", "logging", "log", "debug", "trace", "error message",
        "stack trace", "personal data", "pii", "environment variable",
    },
    "CRYPTO": {
        "encrypt", "decrypt", "hash", "cipher", "cryptograph",
        "signature", "sign", "verify", "certificate", "ssl", "tls",
        "key generation", "random", "seed", "digest", "hmac",
        "aes", "rsa", "sha", "md5", "bcrypt", "scrypt", "pbkdf",
    },
    "DESERIALIZATION": {
        "deserializ", "serializ", "parse", "unmarshal", "marshal",
        "pickle", "yaml", "xml", "json parse", "decode",
        "object injection", "prototype pollution",
    },
    "AUTH": {
        "auth", "login", "logout", "session", "permission",
        "access control", "role", "privilege", "oauth", "jwt",
        "bearer", "credential", "identity", "user account",
        "sign in", "sign out", "authenticate", "authorize",
        "access token", "refresh token", "rbac", "acl",
    },
}

# Reference texts for similarity-based techniques
# These describe what each security property means in natural language
PROPERTY_REFERENCE_TEXTS = {
    "COMMAND_EXEC": (
        "This tool executes system commands, shell commands, or spawns "
        "child processes. It can run arbitrary commands on the operating "
        "system through subprocess, exec, or shell invocation. It may "
        "execute scripts, CLI tools, bash commands, or invoke programs."
    ),
    "FILE_SYSTEM": (
        "This tool reads, writes, creates, deletes, or modifies files "
        "and directories on the local file system. It performs file I/O "
        "operations such as opening files, saving data to disk, uploading "
        "or downloading files, managing folders, or accessing storage."
    ),
    "NETWORK": (
        "This tool makes network requests, HTTP calls, or connects to "
        "external services over the internet. It may fetch data from URLs, "
        "call APIs, open sockets, or communicate with remote servers using "
        "protocols like HTTP, HTTPS, TCP, UDP, WebSocket, or gRPC."
    ),
    "DATABASE": (
        "This tool queries, inserts, updates, or deletes data in a database. "
        "It interacts with SQL or NoSQL databases such as PostgreSQL, MySQL, "
        "SQLite, MongoDB, Redis, or DynamoDB. It may execute queries, manage "
        "schemas, perform CRUD operations, or handle transactions."
    ),
    "INFO_EXPOSURE": (
        "This tool accesses environment variables, configuration settings, "
        "secrets, API keys, tokens, or other sensitive information. It may "
        "expose credentials, read .env files, access process environment, "
        "or handle confidential data that could leak if not properly managed."
    ),
    "CRYPTO": (
        "This tool performs cryptographic operations such as encryption, "
        "decryption, hashing, digital signatures, or certificate management. "
        "It may use algorithms like AES, RSA, SHA, HMAC, bcrypt, or manage "
        "SSL/TLS certificates and cryptographic key generation."
    ),
    "DESERIALIZATION": (
        "This tool deserializes data from potentially untrusted sources. "
        "It may parse pickle, YAML, XML, or JSON data, unmarshal objects, "
        "or decode serialized formats that could lead to code injection "
        "or prototype pollution if input is not properly validated."
    ),
    "AUTH": (
        "This tool handles authentication, authorization, or access control. "
        "It may manage user sessions, login/logout flows, OAuth tokens, JWTs, "
        "bearer tokens, role-based access control (RBAC), permissions, or "
        "identity verification and credential management."
    ),
}


def normalize_text(text):
    """Normalize text for analysis."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[_\-]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


# =========================================================================
# Technique 1: Keyword Matching
# =========================================================================

def keyword_match(description, property_name):
    """Check if description contains keywords for a security property."""
    if not description:
        return False, 0.0, []

    norm = normalize_text(description)
    keywords = SECURITY_KEYWORDS.get(property_name, set())
    matched = []

    for kw in keywords:
        kw_lower = kw.lower()
        if len(kw_lower) <= 3:
            if re.search(r'\b' + re.escape(kw_lower) + r'\b', norm):
                matched.append(kw)
        else:
            if kw_lower in norm:
                matched.append(kw)

    score = len(matched) / len(keywords) if keywords else 0
    return len(matched) > 0, score, matched


# =========================================================================
# Technique 2: TF-IDF Cosine Similarity
# =========================================================================

class TFIDFAnalyzer:
    def __init__(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            stop_words='english',
            sublinear_tf=True,
        )
        self.cosine_similarity = cosine_similarity

        # Fit on reference texts + a broad corpus hint
        all_texts = list(PROPERTY_REFERENCE_TEXTS.values())
        self.vectorizer.fit(all_texts)

        # Pre-compute reference vectors
        self.ref_vectors = {}
        for prop, text in PROPERTY_REFERENCE_TEXTS.items():
            self.ref_vectors[prop] = self.vectorizer.transform([text])

    def analyze(self, description, property_name):
        if not description:
            return False, 0.0

        desc_vec = self.vectorizer.transform([normalize_text(description)])
        ref_vec = self.ref_vectors.get(property_name)
        if ref_vec is None:
            return False, 0.0

        sim = self.cosine_similarity(desc_vec, ref_vec)[0][0]
        return sim > 0.15, float(sim)  # Threshold determined empirically


# =========================================================================
# Technique 3: Sentence Embeddings (all-MiniLM-L6-v2)
# =========================================================================

class EmbeddingAnalyzer:
    def __init__(self):
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer('all-MiniLM-L6-v2')

        # Pre-compute reference embeddings
        self.ref_embeddings = {}
        for prop, text in PROPERTY_REFERENCE_TEXTS.items():
            self.ref_embeddings[prop] = self.model.encode(text, normalize_embeddings=True)

    def analyze(self, description, property_name):
        if not description:
            return False, 0.0

        desc_emb = self.model.encode(
            normalize_text(description), normalize_embeddings=True
        )
        ref_emb = self.ref_embeddings.get(property_name)
        if ref_emb is None:
            return False, 0.0

        sim = float(np.dot(desc_emb, ref_emb))
        return sim > 0.35, sim  # Threshold for semantic similarity


# =========================================================================
# Technique 4: Word Mover's Distance (WMD via gensim)
# =========================================================================

class WMDAnalyzer:
    def __init__(self):
        import gensim.downloader as api
        self.model = api.load("glove-wiki-gigaword-50")

    def analyze(self, description, property_name):
        if not description:
            return False, 0.0

        ref_text = PROPERTY_REFERENCE_TEXTS.get(property_name, "")
        desc_tokens = normalize_text(description).split()
        ref_tokens = normalize_text(ref_text).split()

        if not desc_tokens or not ref_tokens:
            return False, 0.0

        try:
            dist = self.model.wmdistance(desc_tokens, ref_tokens)
            # WMD: lower = more similar. Convert to similarity score.
            sim = 1.0 / (1.0 + dist)
            return sim > 0.25, float(sim)
        except Exception:
            return False, 0.0


# =========================================================================
# Technique 5: BM25
# =========================================================================

class BM25Analyzer:
    def __init__(self):
        from rank_bm25 import BM25Okapi

        # Build BM25 index from reference texts
        self.ref_docs = {}
        for prop, text in PROPERTY_REFERENCE_TEXTS.items():
            self.ref_docs[prop] = normalize_text(text).split()

        # Also index all keywords as additional documents
        self.keyword_docs = {}
        for prop, kws in SECURITY_KEYWORDS.items():
            self.keyword_docs[prop] = " ".join(kws).split()

    def analyze(self, description, property_name):
        if not description:
            return False, 0.0

        ref_tokens = self.ref_docs.get(property_name, [])
        kw_tokens = self.keyword_docs.get(property_name, [])

        if not ref_tokens:
            return False, 0.0

        from rank_bm25 import BM25Okapi

        # Use description as the corpus, query with reference text
        desc_tokens = normalize_text(description).split()
        if not desc_tokens:
            return False, 0.0

        # Build BM25 from the description (treated as a single doc)
        # and query with the property reference
        corpus = [desc_tokens]
        bm25 = BM25Okapi(corpus)

        # Score using reference text as query
        scores_ref = bm25.get_scores(ref_tokens)
        scores_kw = bm25.get_scores(kw_tokens)

        score = max(float(scores_ref[0]), float(scores_kw[0]))

        # Normalize to [0,1] range roughly
        norm_score = min(score / 50.0, 1.0)
        return norm_score > 0.1, norm_score


# =========================================================================
# Technique 6: Jaccard N-gram Overlap
# =========================================================================

def jaccard_ngram(description, property_name, n=2):
    """Compute Jaccard similarity on character n-grams."""
    if not description:
        return False, 0.0

    ref_text = PROPERTY_REFERENCE_TEXTS.get(property_name, "")
    desc_norm = normalize_text(description)
    ref_norm = normalize_text(ref_text)

    def get_ngrams(text, n):
        return set(text[i:i+n] for i in range(len(text) - n + 1))

    desc_ngrams = get_ngrams(desc_norm, n)
    ref_ngrams = get_ngrams(ref_norm, n)

    if not desc_ngrams or not ref_ngrams:
        return False, 0.0

    intersection = len(desc_ngrams & ref_ngrams)
    union = len(desc_ngrams | ref_ngrams)
    sim = intersection / union if union > 0 else 0

    return sim > 0.1, float(sim)


# =========================================================================
# Main analysis
# =========================================================================

def load_tools(input_path):
    """Load tools from enriched JSONL."""
    all_tools = []
    with open(input_path) as f:
        for line in f:
            entry = json.loads(line)
            for tool in entry["tools"]:
                tool["_repo"] = entry["repo"]
                tool["_language"] = entry["language"]
                all_tools.append(tool)
    return all_tools


def initialize_analyzers():
    """Initialize all technique analyzers, skipping unavailable ones."""
    analyzers = {"keyword": None, "jaccard_ngram": None}  # Always available

    # TF-IDF
    try:
        analyzers["tfidf_cosine"] = TFIDFAnalyzer()
        print("  TF-IDF Cosine: ready")
    except ImportError:
        print("  TF-IDF Cosine: SKIPPED (install scikit-learn)")

    # Sentence Embeddings
    try:
        analyzers["sentence_embedding"] = EmbeddingAnalyzer()
        print("  Sentence Embeddings: ready")
    except ImportError:
        print("  Sentence Embeddings: SKIPPED (install sentence-transformers)")

    # Word Mover's Distance
    try:
        analyzers["wmd"] = WMDAnalyzer()
        print("  WMD: ready")
    except (ImportError, Exception) as e:
        print(f"  WMD: SKIPPED ({e})")

    # BM25
    try:
        analyzers["bm25"] = BM25Analyzer()
        print("  BM25: ready")
    except ImportError:
        print("  BM25: SKIPPED (install rank-bm25)")

    return analyzers


def analyze_tool_all_techniques(tool, analyzers):
    """Run all techniques on a single tool."""
    description = tool.get("description")
    properties = tool.get("properties", [])

    result = {
        "name": tool["name"],
        "repo": tool["_repo"],
        "language": tool["_language"],
        "has_description": bool(description and str(description).strip()),
        "has_srms": len(tool.get("srtis", [])) > 0,
        "properties": properties,
        "description_length": len(description) if description else 0,
        "techniques": {},
    }

    if not properties or not description:
        return result

    for tech_name in ["keyword", "tfidf_cosine", "sentence_embedding",
                       "wmd", "bm25", "jaccard_ngram"]:
        tech_result = {}
        mentioned_count = 0

        for prop in properties:
            if tech_name == "keyword":
                mentioned, score, matched = keyword_match(description, prop)
                tech_result[prop] = {
                    "mentioned": mentioned,
                    "score": round(score, 4),
                }
            elif tech_name == "jaccard_ngram":
                mentioned, score = jaccard_ngram(description, prop)
                tech_result[prop] = {
                    "mentioned": mentioned,
                    "score": round(score, 4),
                }
            elif tech_name in analyzers and analyzers[tech_name] is not None:
                mentioned, score = analyzers[tech_name].analyze(description, prop)
                tech_result[prop] = {
                    "mentioned": mentioned,
                    "score": round(score, 4),
                }
            else:
                continue  # Technique not available

            if mentioned:
                mentioned_count += 1

        if tech_result:
            n = len(properties)
            result["techniques"][tech_name] = {
                "property_results": tech_result,
                "mentioned_count": mentioned_count,
                "total_properties": n,
                "transparency_score": round(mentioned_count / n, 4) if n > 0 else None,
            }

    return result


def compute_summary(results, technique_names):
    """Compute summary statistics across all techniques."""
    summary = {"techniques": {}}

    analyzable = [r for r in results if r["properties"] and r["has_description"]]

    summary["total_tools"] = len(results)
    summary["tools_with_srms"] = sum(1 for r in results if r["has_srms"])
    summary["tools_with_description"] = sum(1 for r in results if r["has_description"])
    summary["analyzable"] = len(analyzable)

    for tech in technique_names:
        tech_data = {"per_property": {}, "overall": {}}

        scores = []
        for r in analyzable:
            t = r["techniques"].get(tech)
            if t and t["transparency_score"] is not None:
                scores.append(t["transparency_score"])

        if not scores:
            continue

        fully = sum(1 for s in scores if s == 1.0)
        partial = sum(1 for s in scores if 0 < s < 1.0)
        none_t = sum(1 for s in scores if s == 0.0)

        tech_data["overall"] = {
            "avg_transparency": round(sum(scores) / len(scores), 4),
            "median_transparency": round(sorted(scores)[len(scores) // 2], 4),
            "fully_transparent": fully,
            "partially_transparent": partial,
            "not_transparent": none_t,
            "total_scored": len(scores),
        }

        # Per property
        for prop in SECURITY_PROPERTIES:
            tools_with_prop = [
                r for r in analyzable
                if prop in r["properties"]
                and tech in r["techniques"]
                and prop in r["techniques"][tech].get("property_results", {})
            ]
            mentioned = [
                r for r in tools_with_prop
                if r["techniques"][tech]["property_results"][prop]["mentioned"]
            ]

            if tools_with_prop:
                avg_sim = np.mean([
                    r["techniques"][tech]["property_results"][prop]["score"]
                    for r in tools_with_prop
                ])
                tech_data["per_property"][prop] = {
                    "total": len(tools_with_prop),
                    "mentioned": len(mentioned),
                    "rate": round(len(mentioned) / len(tools_with_prop), 4),
                    "avg_similarity": round(float(avg_sim), 4),
                    "risk": PROPERTY_RISK.get(prop, "Unknown"),
                }

        # By language
        by_lang = defaultdict(list)
        for r in analyzable:
            t = r["techniques"].get(tech)
            if t and t["transparency_score"] is not None:
                by_lang[r["language"]].append(t["transparency_score"])

        tech_data["by_language"] = {
            lang: {
                "count": len(scores_l),
                "avg_transparency": round(sum(scores_l) / len(scores_l), 4),
            }
            for lang, scores_l in by_lang.items()
        }

        # RQ3: Missing rates
        missing_rates = {}
        for prop in SECURITY_PROPERTIES:
            pp = tech_data["per_property"].get(prop)
            if pp and pp["total"] > 0:
                missing_rates[prop] = {
                    "total": pp["total"],
                    "missing": pp["total"] - pp["mentioned"],
                    "missing_rate": round(1 - pp["rate"], 4),
                    "risk": pp["risk"],
                }
        tech_data["missing_rates"] = dict(
            sorted(missing_rates.items(), key=lambda x: -x[1]["missing_rate"])
        )

        # Description length impact
        short = [r for r in analyzable if r["description_length"] < 50 and tech in r["techniques"]]
        medium = [r for r in analyzable if 50 <= r["description_length"] < 200 and tech in r["techniques"]]
        long = [r for r in analyzable if r["description_length"] >= 200 and tech in r["techniques"]]

        def avg_t(tools):
            vals = [t["techniques"][tech]["transparency_score"]
                    for t in tools if t["techniques"].get(tech, {}).get("transparency_score") is not None]
            return round(sum(vals) / len(vals), 4) if vals else 0

        tech_data["desc_length_impact"] = {
            "short_lt50": {"count": len(short), "avg_transparency": avg_t(short)},
            "medium_50_200": {"count": len(medium), "avg_transparency": avg_t(medium)},
            "long_gt200": {"count": len(long), "avg_transparency": avg_t(long)},
        }

        summary["techniques"][tech] = tech_data

    return summary


def print_comparison_table(summary):
    """Print a comparison table across all techniques."""
    techs = list(summary["techniques"].keys())
    if not techs:
        print("No techniques computed.")
        return

    print("\n" + "=" * 90)
    print("COMPARISON TABLE: RQ1 - Transparency Scores Across Techniques")
    print("=" * 90)

    # Header
    header = f"{'Metric':<35}"
    for t in techs:
        header += f" {t:<14}"
    print(header)
    print("-" * (35 + 15 * len(techs)))

    # Overall metrics
    row = f"{'Avg Transparency Score':<35}"
    for t in techs:
        val = summary["techniques"][t]["overall"]["avg_transparency"]
        row += f" {val:.1%}{'':>8}"
    print(row)

    row = f"{'Median Transparency Score':<35}"
    for t in techs:
        val = summary["techniques"][t]["overall"]["median_transparency"]
        row += f" {val:.1%}{'':>8}"
    print(row)

    row = f"{'Fully Transparent (100%)':<35}"
    for t in techs:
        val = summary["techniques"][t]["overall"]["fully_transparent"]
        total = summary["techniques"][t]["overall"]["total_scored"]
        row += f" {val}/{total}{'':>5}"
    print(row)

    row = f"{'Not Transparent (0%)':<35}"
    for t in techs:
        val = summary["techniques"][t]["overall"]["not_transparent"]
        total = summary["techniques"][t]["overall"]["total_scored"]
        row += f" {val}/{total}{'':>5}"
    print(row)

    # Per property
    print(f"\n{'='*90}")
    print("PER-PROPERTY MENTION RATES")
    print("=" * 90)

    header = f"{'Property':<20} {'Risk':<10}"
    for t in techs:
        header += f" {t:<14}"
    print(header)
    print("-" * (30 + 15 * len(techs)))

    for prop in SECURITY_PROPERTIES:
        row = f"{prop:<20} {PROPERTY_RISK.get(prop, '?'):<10}"
        for t in techs:
            pp = summary["techniques"][t]["per_property"].get(prop)
            if pp:
                row += f" {pp['rate']:.1%} ({pp['mentioned']}/{pp['total']})"
            else:
                row += f" {'N/A':>14}"
        print(row)

    # RQ3 table
    print(f"\n{'='*90}")
    print("COMPARISON TABLE: RQ3 - Missing Rates Across Techniques")
    print("=" * 90)

    header = f"{'Property':<20} {'Risk':<10}"
    for t in techs:
        header += f" {t:<14}"
    print(header)
    print("-" * (30 + 15 * len(techs)))

    for prop in SECURITY_PROPERTIES:
        row = f"{prop:<20} {PROPERTY_RISK.get(prop, '?'):<10}"
        for t in techs:
            mr = summary["techniques"][t].get("missing_rates", {}).get(prop)
            if mr:
                row += f" {mr['missing_rate']:.1%}{'':>8}"
            else:
                row += f" {'N/A':>14}"
        print(row)

    # By language
    print(f"\n{'='*90}")
    print("AVG TRANSPARENCY BY LANGUAGE")
    print("=" * 90)

    langs = set()
    for t in techs:
        langs |= set(summary["techniques"][t].get("by_language", {}).keys())

    header = f"{'Language':<15}"
    for t in techs:
        header += f" {t:<14}"
    print(header)
    print("-" * (15 + 15 * len(techs)))

    for lang in sorted(langs):
        row = f"{lang:<15}"
        for t in techs:
            bl = summary["techniques"][t].get("by_language", {}).get(lang)
            if bl:
                row += f" {bl['avg_transparency']:.1%} (n={bl['count']})"
            else:
                row += f" {'N/A':>14}"
        print(row)

    # Description length impact
    print(f"\n{'='*90}")
    print("TRANSPARENCY BY DESCRIPTION LENGTH")
    print("=" * 90)

    header = f"{'Length Category':<20}"
    for t in techs:
        header += f" {t:<14}"
    print(header)
    print("-" * (20 + 15 * len(techs)))

    for cat in ["short_lt50", "medium_50_200", "long_gt200"]:
        labels = {"short_lt50": "Short (<50)", "medium_50_200": "Medium (50-200)", "long_gt200": "Long (>200)"}
        row = f"{labels[cat]:<20}"
        for t in techs:
            dl = summary["techniques"][t].get("desc_length_impact", {}).get(cat)
            if dl:
                row += f" {dl['avg_transparency']:.1%} (n={dl['count']})"
            else:
                row += f" {'N/A':>14}"
        print(row)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()

    print("Loading tools...")
    all_tools = load_tools(args.input)
    print(f"  {len(all_tools)} tools loaded")

    print("\nInitializing analyzers...")
    print("  Keyword Matching: ready")
    print("  Jaccard N-gram: ready")
    analyzers = initialize_analyzers()

    print(f"\nAnalyzing {len(all_tools)} tools...")
    results = []
    for i, tool in enumerate(all_tools):
        if (i + 1) % 500 == 0:
            print(f"  {i+1}/{len(all_tools)}...")
        results.append(analyze_tool_all_techniques(tool, analyzers))

    print(f"  Done. {len(results)} results.")

    # Write detailed results
    def json_default(obj):
        """Handle numpy types that aren't JSON-serializable."""
        if isinstance(obj, (np.bool_,)):
            return bool(obj)
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return str(obj)

    with open(args.output, "w") as f:
        for r in results:
            f.write(json.dumps(r, default=json_default) + "\n")

    # Get active technique names
    active_techs = set()
    for r in results:
        active_techs |= set(r["techniques"].keys())
    active_techs = sorted(active_techs)

    print(f"\nActive techniques: {active_techs}")

    # Compute summary
    summary = compute_summary(results, active_techs)

    with open(args.summary, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    # Print comparison tables
    print_comparison_table(summary)

    # Save report
    report_path = args.summary.replace(".json", "_report.txt")
    import io
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    print_comparison_table(summary)
    report_text = buffer.getvalue()
    sys.stdout = old_stdout

    with open(report_path, "w") as f:
        f.write(report_text)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
