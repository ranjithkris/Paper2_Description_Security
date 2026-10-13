#!/usr/bin/env python3
"""
Comprehensive evaluation script for all RQs.

RQ1: How transparent are MCP tool descriptions about security properties?
     (Keyword-based analysis - computed here)
RQ2: Can LLMs assess transparency better than keywords?
     (Requires LLM API - uses pre-computed results if available)
RQ3: What security information is most commonly missing from descriptions?
     (Gap analysis - computed here)

Generates a complete results report.
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

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


def load_keyword_results(path):
    """Load keyword analysis results."""
    results = []
    with open(path) as f:
        for line in f:
            results.append(json.loads(line))
    return results


def load_llm_results(path):
    """Load LLM analysis results if available."""
    if not Path(path).exists():
        return None
    results = []
    with open(path) as f:
        for line in f:
            results.append(json.loads(line))
    return results


def compute_rq1(keyword_results):
    """RQ1: How transparent are MCP tool descriptions about security?"""
    # Filter to analyzable tools (have both properties and description)
    analyzable = [
        r for r in keyword_results
        if r["properties"] and r["has_description"]
    ]

    scores = [
        r["transparency_score"]
        for r in analyzable
        if r["transparency_score"] is not None
    ]

    if not scores:
        return {"error": "No analyzable tools"}

    # Distribution
    fully = sum(1 for s in scores if s == 1.0)
    partial = sum(1 for s in scores if 0 < s < 1.0)
    none = sum(1 for s in scores if s == 0.0)

    # Per-property
    per_prop = {}
    for prop in SECURITY_PROPERTIES:
        tools_with = [r for r in analyzable if prop in r["properties"]]
        mentioned = [
            r for r in tools_with
            if r["property_analysis"].get(prop, {}).get("mentioned", False)
        ]
        if tools_with:
            per_prop[prop] = {
                "total": len(tools_with),
                "mentioned": len(mentioned),
                "rate": len(mentioned) / len(tools_with),
                "risk": PROPERTY_RISK.get(prop, "Unknown"),
            }

    # By language
    by_lang = defaultdict(lambda: {"scores": [], "count": 0})
    for r in analyzable:
        lang = r.get("language", "unknown")
        if r["transparency_score"] is not None:
            by_lang[lang]["scores"].append(r["transparency_score"])
            by_lang[lang]["count"] += 1

    lang_stats = {}
    for lang, data in by_lang.items():
        if data["scores"]:
            lang_stats[lang] = {
                "count": data["count"],
                "avg_score": sum(data["scores"]) / len(data["scores"]),
                "fully_transparent": sum(1 for s in data["scores"] if s == 1.0),
                "not_transparent": sum(1 for s in data["scores"] if s == 0.0),
            }

    return {
        "total_tools": len(keyword_results),
        "tools_with_srms": sum(1 for r in keyword_results if r["has_srms"]),
        "tools_with_description": sum(1 for r in keyword_results if r["has_description"]),
        "analyzable": len(analyzable),
        "avg_transparency": sum(scores) / len(scores),
        "median_transparency": sorted(scores)[len(scores) // 2],
        "fully_transparent": fully,
        "partially_transparent": partial,
        "not_transparent": none,
        "per_property": per_prop,
        "by_language": lang_stats,
    }


def compute_rq3(keyword_results):
    """RQ3: What security information is most commonly missing?"""
    analyzable = [
        r for r in keyword_results
        if r["properties"] and r["has_description"]
    ]

    # Count missing mentions per property
    missing_counts = Counter()
    present_counts = Counter()
    total_counts = Counter()

    for r in analyzable:
        for prop in r["properties"]:
            total_counts[prop] += 1
            analysis = r["property_analysis"].get(prop, {})
            if analysis.get("mentioned", False):
                present_counts[prop] += 1
            else:
                missing_counts[prop] += 1

    # Missing rate per property
    missing_rates = {}
    for prop in SECURITY_PROPERTIES:
        total = total_counts[prop]
        if total > 0:
            missing = missing_counts[prop]
            missing_rates[prop] = {
                "total": total,
                "missing": missing,
                "missing_rate": missing / total,
                "risk": PROPERTY_RISK.get(prop, "Unknown"),
            }

    # Most common missing combinations
    missing_combos = Counter()
    for r in analyzable:
        missing_props = []
        for prop in r["properties"]:
            analysis = r["property_analysis"].get(prop, {})
            if not analysis.get("mentioned", False):
                missing_props.append(prop)
        if missing_props:
            missing_combos[tuple(sorted(missing_props))] += 1

    top_combos = missing_combos.most_common(10)

    # Tools with critical missing info (COMMAND_EXEC not mentioned)
    critical_missing = []
    for r in analyzable:
        if "COMMAND_EXEC" in r["properties"]:
            analysis = r["property_analysis"].get("COMMAND_EXEC", {})
            if not analysis.get("mentioned", False):
                critical_missing.append({
                    "name": r["name"],
                    "repo": r["repo"],
                    "all_properties": r["properties"],
                    "description_length": r["description_length"],
                })

    # Description length vs transparency
    short_descs = [r for r in analyzable if r["description_length"] < 50]
    medium_descs = [r for r in analyzable if 50 <= r["description_length"] < 200]
    long_descs = [r for r in analyzable if r["description_length"] >= 200]

    def avg_score(tools):
        scores = [t["transparency_score"] for t in tools if t["transparency_score"] is not None]
        return sum(scores) / len(scores) if scores else 0

    return {
        "missing_rates": dict(sorted(
            missing_rates.items(),
            key=lambda x: -x[1]["missing_rate"]
        )),
        "top_missing_combinations": [
            {"combination": list(combo), "count": count}
            for combo, count in top_combos
        ],
        "critical_missing_command_exec": {
            "count": len(critical_missing),
            "total_command_exec_tools": total_counts.get("COMMAND_EXEC", 0),
            "examples": critical_missing[:10],
        },
        "description_length_impact": {
            "short_lt50": {"count": len(short_descs), "avg_transparency": avg_score(short_descs)},
            "medium_50_200": {"count": len(medium_descs), "avg_transparency": avg_score(medium_descs)},
            "long_gt200": {"count": len(long_descs), "avg_transparency": avg_score(long_descs)},
        },
    }


def generate_report(rq1, rq3, output_path):
    """Generate the final results report."""
    report = []
    report.append("=" * 70)
    report.append("PAPER 2: SECURITY TRANSPARENCY IN MCP TOOL DESCRIPTIONS")
    report.append("Empirical Study Results")
    report.append("=" * 70)

    # Dataset overview
    report.append("\n1. DATASET OVERVIEW")
    report.append("-" * 40)
    report.append(f"Total MCP tools analyzed: {rq1['total_tools']}")
    report.append(f"Tools with security-relevant methods (SRMs): {rq1['tools_with_srms']}")
    report.append(f"Tools with extracted descriptions: {rq1['tools_with_description']}")
    report.append(f"Analyzable tools (SRM + description): {rq1['analyzable']}")

    # RQ1
    report.append(f"\n\n2. RQ1: HOW TRANSPARENT ARE MCP TOOL DESCRIPTIONS?")
    report.append("-" * 40)
    report.append(f"Average transparency score: {rq1['avg_transparency']:.1%}")
    report.append(f"Median transparency score: {rq1['median_transparency']:.1%}")
    report.append(f"Fully transparent (score=1.0): {rq1['fully_transparent']} ({rq1['fully_transparent']/rq1['analyzable']:.1%})")
    report.append(f"Partially transparent (0<score<1): {rq1['partially_transparent']} ({rq1['partially_transparent']/rq1['analyzable']:.1%})")
    report.append(f"Not transparent at all (score=0): {rq1['not_transparent']} ({rq1['not_transparent']/rq1['analyzable']:.1%})")

    report.append(f"\nPer-Property Transparency Rates:")
    report.append(f"{'Property':<20} {'Risk':<10} {'Mentioned':<12} {'Total':<8} {'Rate':<8}")
    report.append("-" * 58)
    for prop, stats in sorted(rq1["per_property"].items(), key=lambda x: x[1]["rate"]):
        report.append(
            f"{prop:<20} {stats['risk']:<10} {stats['mentioned']:<12} "
            f"{stats['total']:<8} {stats['rate']:.1%}"
        )

    report.append(f"\nBy Language:")
    for lang, stats in sorted(rq1["by_language"].items(), key=lambda x: -x[1]["avg_score"]):
        report.append(
            f"  {lang}: {stats['count']} tools, "
            f"avg transparency {stats['avg_score']:.1%}, "
            f"{stats['fully_transparent']} fully transparent, "
            f"{stats['not_transparent']} not transparent"
        )

    # RQ3
    report.append(f"\n\n3. RQ3: WHAT SECURITY INFO IS MOST COMMONLY MISSING?")
    report.append("-" * 40)
    report.append(f"\nMissing Rates by Property (most to least missing):")
    report.append(f"{'Property':<20} {'Risk':<10} {'Missing':<10} {'Total':<8} {'Missing Rate':<12}")
    report.append("-" * 60)
    for prop, stats in rq3["missing_rates"].items():
        report.append(
            f"{prop:<20} {stats['risk']:<10} {stats['missing']:<10} "
            f"{stats['total']:<8} {stats['missing_rate']:.1%}"
        )

    report.append(f"\nTop Missing Combinations:")
    for item in rq3["top_missing_combinations"][:5]:
        report.append(f"  {' + '.join(item['combination'])}: {item['count']} tools")

    ce = rq3["critical_missing_command_exec"]
    report.append(f"\nCritical Finding - COMMAND_EXEC:")
    report.append(f"  {ce['count']} out of {ce['total_command_exec_tools']} tools with command execution")
    report.append(f"  capability do NOT mention it in their description")
    if ce["examples"]:
        report.append(f"  Examples:")
        for ex in ce["examples"][:5]:
            report.append(f"    - {ex['name']} (repo: {ex['repo']})")

    dl = rq3["description_length_impact"]
    report.append(f"\nDescription Length Impact on Transparency:")
    report.append(f"  Short (<50 chars): {dl['short_lt50']['count']} tools, avg {dl['short_lt50']['avg_transparency']:.1%}")
    report.append(f"  Medium (50-200): {dl['medium_50_200']['count']} tools, avg {dl['medium_50_200']['avg_transparency']:.1%}")
    report.append(f"  Long (>200 chars): {dl['long_gt200']['count']} tools, avg {dl['long_gt200']['avg_transparency']:.1%}")

    # Key findings
    report.append(f"\n\n4. KEY FINDINGS")
    report.append("-" * 40)

    # Find most and least transparent property
    sorted_props = sorted(rq1["per_property"].items(), key=lambda x: x[1]["rate"])
    least = sorted_props[0] if sorted_props else None
    most = sorted_props[-1] if sorted_props else None

    if least:
        report.append(f"- Least transparent property: {least[0]} ({least[1]['rate']:.1%} mention rate)")
    if most:
        report.append(f"- Most transparent property: {most[0]} ({most[1]['rate']:.1%} mention rate)")

    report.append(f"- {rq1['not_transparent']/rq1['analyzable']:.0%} of security-critical tools have ZERO security transparency")
    report.append(f"- Average transparency score is only {rq1['avg_transparency']:.0%}")

    if ce['count'] > 0 and ce['total_command_exec_tools'] > 0:
        pct = ce['count'] / ce['total_command_exec_tools']
        report.append(f"- {pct:.0%} of tools capable of command execution do not disclose this")

    # RQ2 placeholder
    report.append(f"\n\n5. RQ2: CAN LLMs ASSESS TRANSPARENCY BETTER THAN KEYWORDS?")
    report.append("-" * 40)
    report.append("(Requires running llm_analyzer.py with API access)")
    report.append("Script is ready at: scripts/llm_analyzer.py")
    report.append("Run: python3 scripts/llm_analyzer.py --input data/tools_with_descriptions.jsonl \\")
    report.append("     --output results/llm_analysis.jsonl --summary results/llm_summary.json")

    report_text = "\n".join(report)
    with open(output_path, "w") as f:
        f.write(report_text)

    print(report_text)
    return report_text


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyword-results", required=True)
    parser.add_argument("--llm-results", default=None)
    parser.add_argument("--output-report", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    # Load data
    keyword_results = load_keyword_results(args.keyword_results)

    # Compute RQs
    rq1 = compute_rq1(keyword_results)
    rq3 = compute_rq3(keyword_results)

    # Save structured results
    all_results = {
        "rq1": rq1,
        "rq3": rq3,
    }

    # Add LLM results if available
    if args.llm_results and Path(args.llm_results).exists():
        llm_results = load_llm_results(args.llm_results)
        if llm_results:
            all_results["rq2"] = {"status": "computed", "path": args.llm_results}

    with open(args.output_json, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    # Generate report
    generate_report(rq1, rq3, args.output_report)


if __name__ == "__main__":
    main()
