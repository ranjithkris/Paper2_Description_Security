#!/usr/bin/env python3
"""
Multi-Technique Transparency Analyzer v2

Analyzes whether MCP tool descriptions communicate security-relevant
capabilities detected in their source code.

Improvements over v1:
  1. Keywords derived from CodeQL/Semgrep/Bandit (trusted_security_registry.py)
  2. Empirical thresholds: each similarity technique runs at multiple thresholds
  3. Statistical analysis: chi-square, Mann-Whitney U, Spearman, CI, Cramér's V
  4. Uses independent ground truth (from build_ground_truth.py)

Techniques:
  - KEYWORD MATCHING: exact/substring keyword lookup (baseline)
  - TF-IDF COSINE: TF-IDF vectors + cosine similarity
  - SENTENCE EMBEDDINGS: all-MiniLM-L6-v2 semantic similarity (optional)

Usage:
  pip install numpy scikit-learn scipy
  pip install sentence-transformers  # optional, for embeddings

  python3 scripts/analyze_transparency_v2.py \
    --input data/independent_dataset.jsonl \
    --output results/v2_results.jsonl \
    --summary results/v2_summary.json
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
from scipy import stats as scipy_stats

warnings.filterwarnings("ignore")

# Add scripts dir to path
sys.path.insert(0, str(Path(__file__).parent))
from trusted_security_registry import (
    SECURITY_PROPERTIES, PROPERTY_RISK, DERIVED_KEYWORDS,
    PROPERTY_REFERENCE_TEXTS, get_keyword_set,
)


# =========================================================================
# Thresholds to evaluate
# =========================================================================

TFIDF_THRESHOLDS = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50]
EMBEDDING_THRESHOLDS = [0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]


# =========================================================================
# Text normalization
# =========================================================================

def normalize_text(text):
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[_\-]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


# =========================================================================
# Technique 1: Keyword Matching (trusted-source keywords)
# =========================================================================

def keyword_match(description, property_name):
    """Check if description contains keywords for a security property."""
    if not description:
        return False, 0.0, []

    norm = normalize_text(description)
    keywords = get_keyword_set(property_name)
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

        all_texts = list(PROPERTY_REFERENCE_TEXTS.values())
        self.vectorizer.fit(all_texts)

        self.ref_vectors = {}
        for prop, text in PROPERTY_REFERENCE_TEXTS.items():
            self.ref_vectors[prop] = self.vectorizer.transform([text])

    def score(self, description, property_name):
        """Return raw similarity score (threshold applied externally)."""
        if not description:
            return 0.0
        desc_vec = self.vectorizer.transform([normalize_text(description)])
        ref_vec = self.ref_vectors.get(property_name)
        if ref_vec is None:
            return 0.0
        return float(self.cosine_similarity(desc_vec, ref_vec)[0][0])


# =========================================================================
# Technique 3: Sentence Embeddings
# =========================================================================

class EmbeddingAnalyzer:
    def __init__(self):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.ref_embeddings = {}
        for prop, text in PROPERTY_REFERENCE_TEXTS.items():
            self.ref_embeddings[prop] = self.model.encode(text, normalize_embeddings=True)

    def score(self, description, property_name):
        """Return raw similarity score."""
        if not description:
            return 0.0
        desc_emb = self.model.encode(normalize_text(description), normalize_embeddings=True)
        ref_emb = self.ref_embeddings.get(property_name)
        if ref_emb is None:
            return 0.0
        return float(np.dot(desc_emb, ref_emb))


# =========================================================================
# Data loading
# =========================================================================

def load_tools(input_path):
    """Load tools from independent_dataset.jsonl."""
    all_tools = []
    with open(input_path) as f:
        for line in f:
            entry = json.loads(line)
            for tool in entry.get("tools", []):
                all_tools.append({
                    "name": tool["name"],
                    "description": tool.get("description"),
                    "source_file": tool.get("source_file"),
                    "properties": tool.get("detected_properties", []),
                    "detected_apis": tool.get("detected_apis", {}),
                    "property_source": tool.get("property_source", "unknown"),
                    "repo": entry["repo"],
                    "language": entry["language"],
                })
    return all_tools


# =========================================================================
# Analysis
# =========================================================================

def analyze_all_tools(tools, tfidf_analyzer, embedding_analyzer):
    """
    Compute raw similarity scores for every (tool, property) pair.
    Threshold decisions are applied later to support multi-threshold analysis.
    """
    results = []

    for i, tool in enumerate(tools):
        if (i + 1) % 500 == 0:
            print(f"  {i+1}/{len(tools)}...")

        desc = tool["description"]
        props = tool["properties"]
        has_desc = bool(desc and str(desc).strip())

        result = {
            "name": tool["name"],
            "repo": tool["repo"],
            "language": tool["language"],
            "has_description": has_desc,
            "properties": props,
            "description_length": len(desc) if desc else 0,
            "property_source": tool["property_source"],
            "scores": {},  # {property: {technique: score}}
            "keyword_matches": {},  # {property: [matched_keywords]}
        }

        if not props or not has_desc:
            results.append(result)
            continue

        for prop in props:
            prop_scores = {}

            # Keyword matching
            mentioned, kw_score, matched = keyword_match(desc, prop)
            prop_scores["keyword"] = 1.0 if mentioned else 0.0
            result["keyword_matches"][prop] = matched

            # TF-IDF
            if tfidf_analyzer:
                prop_scores["tfidf"] = tfidf_analyzer.score(desc, prop)

            # Sentence embeddings
            if embedding_analyzer:
                prop_scores["embedding"] = embedding_analyzer.score(desc, prop)

            result["scores"][prop] = prop_scores

        results.append(result)

    return results


def compute_transparency_at_threshold(results, technique, threshold):
    """
    Compute transparency scores for a given technique and threshold.
    For keyword matching, threshold is 0.5 (any match = mentioned).
    """
    analyzable = [r for r in results if r["properties"] and r["has_description"]]

    scores = []
    per_property = defaultdict(lambda: {"total": 0, "mentioned": 0, "sim_values": []})

    for r in analyzable:
        mentioned_count = 0
        total = len(r["properties"])

        for prop in r["properties"]:
            prop_scores = r["scores"].get(prop, {})
            sim = prop_scores.get(technique, 0.0)

            per_property[prop]["total"] += 1
            per_property[prop]["sim_values"].append(sim)

            if technique == "keyword":
                is_mentioned = sim > 0
            else:
                is_mentioned = sim >= threshold

            if is_mentioned:
                mentioned_count += 1
                per_property[prop]["mentioned"] += 1

        transparency = mentioned_count / total if total > 0 else 0
        scores.append(transparency)

    if not scores:
        return None

    return {
        "threshold": threshold,
        "avg_transparency": float(np.mean(scores)),
        "median_transparency": float(np.median(scores)),
        "fully_transparent": sum(1 for s in scores if s == 1.0),
        "partially_transparent": sum(1 for s in scores if 0 < s < 1.0),
        "not_transparent": sum(1 for s in scores if s == 0.0),
        "total_scored": len(scores),
        "per_property": {
            prop: {
                "total": data["total"],
                "mentioned": data["mentioned"],
                "rate": data["mentioned"] / data["total"] if data["total"] > 0 else 0,
                "missing_rate": 1 - (data["mentioned"] / data["total"]) if data["total"] > 0 else 1,
                "avg_similarity": float(np.mean(data["sim_values"])) if data["sim_values"] else 0,
                "risk": PROPERTY_RISK.get(prop, "Unknown"),
            }
            for prop, data in per_property.items()
        },
    }


# =========================================================================
# Statistical Analysis
# =========================================================================

def wilson_confidence_interval(successes, total, confidence=0.95):
    """Wilson score interval for binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    z = scipy_stats.norm.ppf(1 - (1 - confidence) / 2)
    p = successes / total
    denominator = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total) / denominator
    return (max(0, center - margin), min(1, center + margin))


def compute_statistical_tests(results, technique, threshold):
    """Compute statistical tests for a given technique/threshold."""
    analyzable = [r for r in results if r["properties"] and r["has_description"]]
    if not analyzable:
        return {}

    stats_results = {}

    # 1. Per-property transparency scores
    property_mentioned = defaultdict(list)  # prop -> [0/1 per tool-property pair]
    for r in analyzable:
        for prop in r["properties"]:
            sim = r["scores"].get(prop, {}).get(technique, 0.0)
            if technique == "keyword":
                mentioned = 1 if sim > 0 else 0
            else:
                mentioned = 1 if sim >= threshold else 0
            property_mentioned[prop].append(mentioned)

    # 2. Chi-square test: are transparency rates significantly different across properties?
    props_with_data = [p for p in SECURITY_PROPERTIES if len(property_mentioned.get(p, [])) > 0]
    if len(props_with_data) >= 2:
        contingency = []
        for prop in props_with_data:
            vals = property_mentioned[prop]
            mentioned = sum(vals)
            not_mentioned = len(vals) - mentioned
            contingency.append([mentioned, not_mentioned])

        contingency = np.array(contingency)
        if contingency.min() >= 0 and contingency.sum() > 0:
            try:
                chi2, p_val, dof, expected = scipy_stats.chi2_contingency(contingency)
                n = contingency.sum()
                k = min(contingency.shape)
                cramers_v = math.sqrt(chi2 / (n * (k - 1))) if n * (k - 1) > 0 else 0

                stats_results["chi_square_property_rates"] = {
                    "chi2": round(float(chi2), 4),
                    "p_value": float(p_val),
                    "dof": int(dof),
                    "cramers_v": round(float(cramers_v), 4),
                    "significant_005": p_val < 0.05,
                    "significant_001": p_val < 0.01,
                }
            except Exception:
                pass

    # 3. Pairwise Fisher's exact test between properties (for small samples)
    pairwise_tests = {}
    for i, p1 in enumerate(props_with_data):
        for p2 in props_with_data[i+1:]:
            v1 = property_mentioned[p1]
            v2 = property_mentioned[p2]
            m1, n1 = sum(v1), len(v1) - sum(v1)
            m2, n2 = sum(v2), len(v2) - sum(v2)
            try:
                _, p_val = scipy_stats.fisher_exact([[m1, n1], [m2, n2]])
                pairwise_tests[f"{p1}_vs_{p2}"] = {
                    "rate_1": round(sum(v1) / len(v1), 4) if v1 else 0,
                    "rate_2": round(sum(v2) / len(v2), 4) if v2 else 0,
                    "p_value": float(p_val),
                    "significant_005": p_val < 0.05,
                }
            except Exception:
                pass
    stats_results["pairwise_fisher_exact"] = pairwise_tests

    # 4. Confidence intervals for per-property rates
    ci_results = {}
    for prop in props_with_data:
        vals = property_mentioned[prop]
        n = len(vals)
        s = sum(vals)
        rate = s / n if n > 0 else 0
        ci_low, ci_high = wilson_confidence_interval(s, n)
        ci_results[prop] = {
            "rate": round(rate, 4),
            "n": n,
            "ci_95_low": round(ci_low, 4),
            "ci_95_high": round(ci_high, 4),
        }
    stats_results["confidence_intervals"] = ci_results

    # 5. Mann-Whitney U: transparency across languages
    lang_scores = defaultdict(list)
    for r in analyzable:
        mentioned_count = 0
        total = len(r["properties"])
        for prop in r["properties"]:
            sim = r["scores"].get(prop, {}).get(technique, 0.0)
            if technique == "keyword":
                is_m = sim > 0
            else:
                is_m = sim >= threshold
            if is_m:
                mentioned_count += 1
        transparency = mentioned_count / total if total > 0 else 0
        lang_scores[r["language"]].append(transparency)

    lang_comparisons = {}
    langs = sorted(lang_scores.keys())
    for i, l1 in enumerate(langs):
        for l2 in langs[i+1:]:
            s1 = lang_scores[l1]
            s2 = lang_scores[l2]
            if len(s1) >= 5 and len(s2) >= 5:
                try:
                    u_stat, p_val = scipy_stats.mannwhitneyu(s1, s2, alternative='two-sided')
                    # Effect size: rank-biserial correlation
                    n1, n2 = len(s1), len(s2)
                    r_rb = 1 - (2 * u_stat) / (n1 * n2)
                    lang_comparisons[f"{l1}_vs_{l2}"] = {
                        "n1": n1, "n2": n2,
                        "mean1": round(float(np.mean(s1)), 4),
                        "mean2": round(float(np.mean(s2)), 4),
                        "U_statistic": float(u_stat),
                        "p_value": float(p_val),
                        "rank_biserial_r": round(float(r_rb), 4),
                        "significant_005": p_val < 0.05,
                    }
                except Exception:
                    pass
    stats_results["mann_whitney_language"] = lang_comparisons

    # 6. Kruskal-Wallis: transparency across all languages simultaneously
    if len(langs) >= 3:
        groups = [lang_scores[l] for l in langs if len(lang_scores[l]) >= 5]
        if len(groups) >= 3:
            try:
                h_stat, p_val = scipy_stats.kruskal(*groups)
                stats_results["kruskal_wallis_language"] = {
                    "H_statistic": round(float(h_stat), 4),
                    "p_value": float(p_val),
                    "significant_005": p_val < 0.05,
                }
            except Exception:
                pass

    # 7. Spearman correlation: description length vs transparency
    desc_lengths = []
    transparencies = []
    for r in analyzable:
        if r["description_length"] > 0:
            mentioned_count = 0
            total = len(r["properties"])
            for prop in r["properties"]:
                sim = r["scores"].get(prop, {}).get(technique, 0.0)
                if technique == "keyword":
                    is_m = sim > 0
                else:
                    is_m = sim >= threshold
                if is_m:
                    mentioned_count += 1
            desc_lengths.append(r["description_length"])
            transparencies.append(mentioned_count / total if total > 0 else 0)

    if len(desc_lengths) >= 10:
        try:
            rho, p_val = scipy_stats.spearmanr(desc_lengths, transparencies)
            stats_results["spearman_length_transparency"] = {
                "rho": round(float(rho), 4),
                "p_value": float(p_val),
                "n": len(desc_lengths),
                "significant_005": p_val < 0.05,
                "interpretation": (
                    "strong positive" if rho > 0.5 else
                    "moderate positive" if rho > 0.3 else
                    "weak positive" if rho > 0.1 else
                    "negligible" if rho > -0.1 else
                    "weak negative" if rho > -0.3 else
                    "moderate negative" if rho > -0.5 else
                    "strong negative"
                ),
            }
        except Exception:
            pass

    # 8. Overall transparency confidence interval
    all_transparency_scores = []
    for r in analyzable:
        mentioned_count = 0
        total = len(r["properties"])
        for prop in r["properties"]:
            sim = r["scores"].get(prop, {}).get(technique, 0.0)
            if technique == "keyword":
                is_m = sim > 0
            else:
                is_m = sim >= threshold
            if is_m:
                mentioned_count += 1
        all_transparency_scores.append(mentioned_count / total if total > 0 else 0)

    if all_transparency_scores:
        mean = float(np.mean(all_transparency_scores))
        se = float(np.std(all_transparency_scores, ddof=1) / np.sqrt(len(all_transparency_scores)))
        ci = scipy_stats.t.interval(0.95, len(all_transparency_scores) - 1, loc=mean, scale=se)
        stats_results["overall_transparency_ci"] = {
            "mean": round(mean, 4),
            "std": round(float(np.std(all_transparency_scores, ddof=1)), 4),
            "se": round(se, 4),
            "ci_95_low": round(float(ci[0]), 4),
            "ci_95_high": round(float(ci[1]), 4),
            "n": len(all_transparency_scores),
        }

    return stats_results


# =========================================================================
# Report generation
# =========================================================================

def print_results(results, tfidf_analyzer, embedding_analyzer):
    """Print comprehensive comparison tables and statistics."""
    analyzable = [r for r in results if r["properties"] and r["has_description"]]
    n = len(analyzable)

    print(f"\n{'='*90}")
    print(f"DATASET OVERVIEW")
    print(f"{'='*90}")
    print(f"Total tools loaded: {len(results)}")
    print(f"Tools with security operations: {sum(1 for r in results if r['properties'])}")
    print(f"Tools with descriptions: {sum(1 for r in results if r['has_description'])}")
    print(f"Analyzable (both): {n}")

    # --- Keyword results (single threshold) ---
    kw = compute_transparency_at_threshold(results, "keyword", 0.5)
    if kw:
        print(f"\n{'='*90}")
        print(f"RQ1: KEYWORD MATCHING (Trusted-Source Keywords)")
        print(f"{'='*90}")
        print(f"Average transparency: {kw['avg_transparency']:.1%}")
        print(f"Median transparency: {kw['median_transparency']:.1%}")
        print(f"Fully transparent: {kw['fully_transparent']}/{kw['total_scored']} ({kw['fully_transparent']/kw['total_scored']:.1%})")
        print(f"Not transparent: {kw['not_transparent']}/{kw['total_scored']} ({kw['not_transparent']/kw['total_scored']:.1%})")

        print(f"\n{'Property':<20} {'Risk':<10} {'Rate':<15} {'Missing':<15} {'Avg Sim':<10}")
        print("-" * 70)
        for prop in SECURITY_PROPERTIES:
            pp = kw["per_property"].get(prop)
            if pp:
                print(f"{prop:<20} {pp['risk']:<10} {pp['rate']:.1%} ({pp['mentioned']}/{pp['total']}) "
                      f"{pp['missing_rate']:.1%}{'':>8} {pp['avg_similarity']:.3f}")

    # --- TF-IDF multi-threshold ---
    if tfidf_analyzer:
        print(f"\n{'='*90}")
        print(f"TF-IDF COSINE SIMILARITY - THRESHOLD SENSITIVITY")
        print(f"{'='*90}")
        header = f"{'Threshold':<12} {'Avg Transp':<12} {'Fully':<10} {'None':<10}"
        for prop in SECURITY_PROPERTIES:
            header += f" {prop[:8]:<10}"
        print(header)
        print("-" * (44 + 10 * len(SECURITY_PROPERTIES)))

        for t in TFIDF_THRESHOLDS:
            r = compute_transparency_at_threshold(results, "tfidf", t)
            if r:
                row = f"{t:<12.2f} {r['avg_transparency']:<12.1%} {r['fully_transparent']:<10} {r['not_transparent']:<10}"
                for prop in SECURITY_PROPERTIES:
                    pp = r["per_property"].get(prop)
                    if pp:
                        row += f" {pp['rate']:<10.1%}"
                    else:
                        row += f" {'N/A':<10}"
                print(row)

    # --- Sentence embeddings multi-threshold ---
    if embedding_analyzer:
        print(f"\n{'='*90}")
        print(f"SENTENCE EMBEDDINGS - THRESHOLD SENSITIVITY")
        print(f"{'='*90}")
        header = f"{'Threshold':<12} {'Avg Transp':<12} {'Fully':<10} {'None':<10}"
        for prop in SECURITY_PROPERTIES:
            header += f" {prop[:8]:<10}"
        print(header)
        print("-" * (44 + 10 * len(SECURITY_PROPERTIES)))

        for t in EMBEDDING_THRESHOLDS:
            r = compute_transparency_at_threshold(results, "embedding", t)
            if r:
                row = f"{t:<12.2f} {r['avg_transparency']:<12.1%} {r['fully_transparent']:<10} {r['not_transparent']:<10}"
                for prop in SECURITY_PROPERTIES:
                    pp = r["per_property"].get(prop)
                    if pp:
                        row += f" {pp['rate']:<10.1%}"
                    else:
                        row += f" {'N/A':<10}"
                print(row)

    # --- RQ3: Missing Rates Comparison ---
    print(f"\n{'='*90}")
    print(f"RQ3: MISSING SECURITY INFORMATION")
    print(f"{'='*90}")

    techniques = [("keyword", 0.5, "Keyword")]
    if tfidf_analyzer:
        techniques.append(("tfidf", 0.15, "TF-IDF@0.15"))
    if embedding_analyzer:
        techniques.append(("embedding", 0.35, "Embed@0.35"))

    header = f"{'Property':<20} {'Risk':<10}"
    for _, _, label in techniques:
        header += f" {label:<16}"
    print(header)
    print("-" * (30 + 17 * len(techniques)))

    for prop in SECURITY_PROPERTIES:
        row = f"{prop:<20} {PROPERTY_RISK.get(prop, '?'):<10}"
        for tech, thresh, _ in techniques:
            r = compute_transparency_at_threshold(results, tech, thresh)
            if r:
                pp = r["per_property"].get(prop)
                if pp:
                    row += f" {pp['missing_rate']:.1%} ({pp['total']-pp['mentioned']}/{pp['total']})"
                else:
                    row += f" {'N/A':<16}"
            else:
                row += f" {'N/A':<16}"
        print(row)

    # --- Statistical Analysis ---
    print(f"\n{'='*90}")
    print(f"STATISTICAL ANALYSIS (Keyword Matching)")
    print(f"{'='*90}")

    kw_stats = compute_statistical_tests(results, "keyword", 0.5)

    # Chi-square
    cs = kw_stats.get("chi_square_property_rates")
    if cs:
        print(f"\nChi-Square Test (transparency rates differ across properties):")
        print(f"  chi2 = {cs['chi2']}, df = {cs['dof']}, p = {cs['p_value']:.2e}")
        print(f"  Cramer's V = {cs['cramers_v']} (effect size)")
        print(f"  Significant at p<0.01: {'Yes' if cs['significant_001'] else 'No'}")

    # Confidence intervals
    ci = kw_stats.get("confidence_intervals", {})
    if ci:
        print(f"\n95% Confidence Intervals (per-property transparency rates):")
        print(f"  {'Property':<20} {'Rate':<10} {'95% CI':<20} {'n':<6}")
        print(f"  {'-'*56}")
        for prop in SECURITY_PROPERTIES:
            c = ci.get(prop)
            if c:
                print(f"  {prop:<20} {c['rate']:.1%}{'':>4} [{c['ci_95_low']:.1%}, {c['ci_95_high']:.1%}]{'':>4} {c['n']}")

    # Mann-Whitney U
    mw = kw_stats.get("mann_whitney_language", {})
    if mw:
        print(f"\nMann-Whitney U Tests (transparency by language):")
        for comp, data in mw.items():
            sig = "*" if data["significant_005"] else ""
            print(f"  {comp}: U={data['U_statistic']:.0f}, p={data['p_value']:.4f}{sig}, "
                  f"r={data['rank_biserial_r']:.3f}, "
                  f"means={data['mean1']:.1%} vs {data['mean2']:.1%}")

    # Kruskal-Wallis
    kw_test = kw_stats.get("kruskal_wallis_language")
    if kw_test:
        print(f"\nKruskal-Wallis Test (transparency across all languages):")
        print(f"  H = {kw_test['H_statistic']}, p = {kw_test['p_value']:.4f}")
        print(f"  Significant at p<0.05: {'Yes' if kw_test['significant_005'] else 'No'}")

    # Spearman
    sp = kw_stats.get("spearman_length_transparency")
    if sp:
        print(f"\nSpearman Correlation (description length vs transparency):")
        print(f"  rho = {sp['rho']}, p = {sp['p_value']:.2e}, n = {sp['n']}")
        print(f"  Interpretation: {sp['interpretation']}")

    # Overall CI
    oci = kw_stats.get("overall_transparency_ci")
    if oci:
        print(f"\nOverall Transparency Score:")
        print(f"  Mean = {oci['mean']:.1%} (95% CI: [{oci['ci_95_low']:.1%}, {oci['ci_95_high']:.1%}])")
        print(f"  SD = {oci['std']:.3f}, n = {oci['n']}")

    # --- By language breakdown ---
    print(f"\n{'='*90}")
    print(f"TRANSPARENCY BY LANGUAGE")
    print(f"{'='*90}")

    by_lang = defaultdict(list)
    for r in analyzable:
        mentioned_count = 0
        total = len(r["properties"])
        for prop in r["properties"]:
            sim = r["scores"].get(prop, {}).get("keyword", 0.0)
            if sim > 0:
                mentioned_count += 1
        by_lang[r["language"]].append(mentioned_count / total if total > 0 else 0)

    for lang in sorted(by_lang.keys()):
        scores = by_lang[lang]
        print(f"  {lang}: n={len(scores)}, mean={np.mean(scores):.1%}, "
              f"median={np.median(scores):.1%}, "
              f"fully_transparent={sum(1 for s in scores if s == 1.0)}, "
              f"not_transparent={sum(1 for s in scores if s == 0.0)}")

    # --- Description length impact ---
    print(f"\n{'='*90}")
    print(f"TRANSPARENCY BY DESCRIPTION LENGTH")
    print(f"{'='*90}")

    for cat, lo, hi in [("Short (<50)", 0, 50), ("Medium (50-200)", 50, 200), ("Long (>200)", 200, 100000)]:
        subset = [r for r in analyzable if lo <= r["description_length"] < hi]
        if subset:
            scores = []
            for r in subset:
                mc = sum(1 for p in r["properties"] if r["scores"].get(p, {}).get("keyword", 0) > 0)
                scores.append(mc / len(r["properties"]) if r["properties"] else 0)
            print(f"  {cat}: n={len(subset)}, mean={np.mean(scores):.1%}")

    return kw_stats


# =========================================================================
# Main
# =========================================================================

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

    # Initialize analyzers
    print("\nInitializing analyzers...")
    print("  Keyword Matching (trusted-source keywords): ready")

    tfidf_analyzer = None
    try:
        tfidf_analyzer = TFIDFAnalyzer()
        print("  TF-IDF Cosine: ready")
    except ImportError:
        print("  TF-IDF Cosine: SKIPPED (install scikit-learn)")

    embedding_analyzer = None
    try:
        embedding_analyzer = EmbeddingAnalyzer()
        print("  Sentence Embeddings: ready")
    except ImportError:
        print("  Sentence Embeddings: SKIPPED (install sentence-transformers)")

    # Analyze
    print(f"\nAnalyzing {len(all_tools)} tools...")
    results = analyze_all_tools(all_tools, tfidf_analyzer, embedding_analyzer)
    print(f"  Done. {len(results)} results.")

    # Write detailed results
    def json_default(obj):
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

    # Build summary
    summary = {
        "dataset": {
            "total_tools": len(results),
            "with_properties": sum(1 for r in results if r["properties"]),
            "with_description": sum(1 for r in results if r["has_description"]),
            "analyzable": sum(1 for r in results if r["properties"] and r["has_description"]),
        },
        "keyword": compute_transparency_at_threshold(results, "keyword", 0.5),
        "tfidf_thresholds": {},
        "embedding_thresholds": {},
        "statistics": compute_statistical_tests(results, "keyword", 0.5),
    }

    if tfidf_analyzer:
        for t in TFIDF_THRESHOLDS:
            summary["tfidf_thresholds"][str(t)] = compute_transparency_at_threshold(results, "tfidf", t)
        summary["tfidf_statistics"] = compute_statistical_tests(results, "tfidf", 0.15)

    if embedding_analyzer:
        for t in EMBEDDING_THRESHOLDS:
            summary["embedding_thresholds"][str(t)] = compute_transparency_at_threshold(results, "embedding", t)
        summary["embedding_statistics"] = compute_statistical_tests(results, "embedding", 0.35)

    with open(args.summary, "w") as f:
        json.dump(summary, f, indent=2, default=json_default)

    # Print report
    import io
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    print_results(results, tfidf_analyzer, embedding_analyzer)
    report_text = buffer.getvalue()
    sys.stdout = old_stdout

    print(report_text)

    report_path = args.summary.replace(".json", "_report.txt")
    with open(report_path, "w") as f:
        f.write(report_text)
    print(f"\nReport saved to: {report_path}")
    print(f"Results saved to: {args.output}")
    print(f"Summary saved to: {args.summary}")


if __name__ == "__main__":
    main()
