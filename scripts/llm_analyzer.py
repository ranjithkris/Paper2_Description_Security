#!/usr/bin/env python3
"""
RQ2: LLM-based analysis of security transparency in MCP tool descriptions.

Uses open-source models served via vLLM on a local GPU to analyze whether
tool descriptions adequately communicate security-relevant capabilities.

Models (run one at a time via vLLM):
  1. Llama 3.1 70B Instruct (AWQ)
  2. Qwen 2.5 72B Instruct (AWQ)
  3. Gemma 2 27B Instruct (FP16)

SETUP:
  pip install vllm openai

USAGE (run one model at a time):

  Step 1: Start vLLM server for a model:
    vllm serve TechxGenus/Meta-Llama-3.1-70B-Instruct-AWQ \
      --dtype auto --gpu-memory-utilization 0.90 --max-model-len 4096 \
      --tensor-parallel-size 1 --port 8000

  Step 2: Run analysis against the running server:
    python3 scripts/llm_analyzer.py \
      --input data/independent_dataset.jsonl \
      --model-name llama3.1-70b \
      --output results/llm_analysis_llama3.1-70b.jsonl \
      --summary results/llm_summary_llama3.1-70b.json

  Step 3: Stop vLLM (Ctrl+C), start next model, repeat.

  Step 4: After all models are done, combine results:
    python3 scripts/llm_analyzer.py --combine \
      --combine-dir results/ \
      --summary results/llm_summary_combined.json

  Use --limit N to test with a small sample first.
  Use --batch-size N to control concurrent requests (default 8).
  Use --vllm-url to change the server URL (default http://localhost:8000).
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


SECURITY_PROPERTIES = [
    "COMMAND_EXEC", "FILE_SYSTEM", "NETWORK", "DATABASE",
    "INFO_EXPOSURE", "CRYPTO", "DESERIALIZATION", "AUTH",
]

PROPERTY_DESCRIPTIONS = {
    "COMMAND_EXEC": "executing system commands, shell commands, or spawning processes",
    "FILE_SYSTEM": "reading, writing, creating, or deleting files and directories",
    "NETWORK": "making HTTP requests, connecting to external services, or network I/O",
    "DATABASE": "querying, inserting, updating, or deleting data in a database",
    "INFO_EXPOSURE": "accessing environment variables, configuration, secrets, or sensitive data",
    "CRYPTO": "performing encryption, decryption, hashing, or other cryptographic operations",
    "DESERIALIZATION": "deserializing data from untrusted sources (pickle, YAML, XML, etc.)",
    "AUTH": "handling authentication, authorization, sessions, or access control",
}

# Models and their vLLM-compatible identifiers
# Keys are short names used in --model-name, values are HuggingFace model IDs for vLLM
SUPPORTED_MODELS = {
    "llama3.1-70b": {
        "hf_id": "TechxGenus/Meta-Llama-3.1-70B-Instruct-AWQ",
        "display": "Llama 3.1 70B Instruct (AWQ)",
        "vllm_args": "--dtype auto --gpu-memory-utilization 0.90 --max-model-len 4096 --quantization awq",
    },
    "qwen2.5-72b": {
        "hf_id": "Qwen/Qwen2.5-72B-Instruct-AWQ",
        "display": "Qwen 2.5 72B Instruct (AWQ)",
        "vllm_args": "--dtype auto --gpu-memory-utilization 0.90 --max-model-len 4096 --quantization awq",
    },
    "gemma2-27b": {
        "hf_id": "google/gemma-2-27b-it",
        "display": "Gemma 2 27B Instruct (FP16)",
        "vllm_args": "--dtype float16 --gpu-memory-utilization 0.90 --max-model-len 4096",
    },
}


def build_prompt(tool_name, description, properties):
    """Build the analysis prompt for an LLM."""
    props_text = "\n".join(
        f"  - {p}: {PROPERTY_DESCRIPTIONS[p]}" for p in properties
    )

    return f"""You are a security analyst evaluating MCP (Model Context Protocol) tool descriptions.

An MCP tool named "{tool_name}" has the following description:

\"\"\"{description}\"\"\"

Static analysis of the tool's source code has detected that it uses the following security-relevant capabilities:

{props_text}

For EACH security property listed above, determine whether the tool's description adequately communicates that the tool has this capability. Answer with a JSON object where each key is the property name and the value is an object with:
- "mentioned": true/false - whether the description mentions or implies this capability
- "confidence": "high"/"medium"/"low" - your confidence in the assessment
- "evidence": a brief quote or explanation of why you made this determination

Respond ONLY with valid JSON, no other text. Do not wrap in markdown code blocks.
"""


def parse_llm_response(text):
    """
    Parse JSON from LLM response, handling common formatting issues.
    """
    if not text or not text.strip():
        return {"error": "empty response"}

    text = text.strip()

    # Remove markdown code blocks if present
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to extract JSON object from surrounding text
    try:
        start = text.index("{")
        # Find matching closing brace
        depth = 0
        for i, c in enumerate(text[start:], start):
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return json.loads(text[start:i + 1])
    except (ValueError, json.JSONDecodeError):
        pass

    return {"error": f"could not parse JSON from response: {text[:200]}"}


async def call_vllm(client, prompt, model_hf_id):
    """
    Call vLLM's OpenAI-compatible API endpoint.

    vLLM serves an OpenAI-compatible API, so we use the openai client
    pointed at localhost.
    """
    try:
        response = await client.chat.completions.create(
            model=model_hf_id,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=1500,
        )
        text = response.choices[0].message.content
        return parse_llm_response(text)
    except Exception as e:
        return {"error": str(e)}


async def process_batch(client, batch, model_hf_id):
    """Process a batch of tools concurrently."""
    tasks = []
    for tool in batch:
        prompt = build_prompt(tool["name"], tool["description"], tool["properties"])
        tasks.append(call_vllm(client, prompt, model_hf_id))
    return await asyncio.gather(*tasks)


async def main_async(args):
    from openai import AsyncOpenAI

    model_info = SUPPORTED_MODELS.get(args.model_name)
    if not model_info:
        print(f"ERROR: Unknown model '{args.model_name}'")
        print(f"Supported models: {', '.join(SUPPORTED_MODELS.keys())}")
        sys.exit(1)

    model_hf_id = model_info["hf_id"]
    print(f"Model: {model_info['display']}")
    print(f"HuggingFace ID: {model_hf_id}")
    print(f"vLLM server: {args.vllm_url}")

    # Connect to vLLM's OpenAI-compatible API
    # vLLM does not need a real API key, but the client requires one
    client = AsyncOpenAI(
        base_url=f"{args.vllm_url}/v1",
        api_key="not-needed",
    )

    # Verify server is running
    try:
        models = await client.models.list()
        available = [m.id for m in models.data]
        print(f"Available models on server: {available}")
        if model_hf_id not in available:
            print(f"WARNING: Expected model '{model_hf_id}' not found on server.")
            print(f"  The server may be serving under a different name.")
            if available:
                model_hf_id = available[0]
                print(f"  Using: {model_hf_id}")
    except Exception as e:
        print(f"ERROR: Cannot connect to vLLM server at {args.vllm_url}")
        print(f"  {e}")
        print(f"\nStart vLLM first:")
        print(f"  vllm serve {model_hf_id} {model_info['vllm_args']} --port 8000")
        sys.exit(1)

    # Load tools (supports both old and independent format)
    all_tools = []
    with open(args.input) as f:
        for line in f:
            entry = json.loads(line)
            for tool in entry["tools"]:
                props = tool.get("detected_properties") or tool.get("properties")
                if tool.get("description") and props:
                    all_tools.append({
                        "name": tool["name"],
                        "description": tool["description"],
                        "properties": props,
                        "repo": entry["repo"],
                        "language": entry.get("language", "unknown"),
                    })

    print(f"Analyzable tools: {len(all_tools)}")

    if args.limit:
        all_tools = all_tools[:args.limit]
        print(f"Limited to: {len(all_tools)}")

    # Check for existing progress (resume support)
    completed = {}
    if os.path.exists(args.output):
        with open(args.output) as f:
            for line in f:
                r = json.loads(line)
                key = f"{r['repo']}::{r['name']}"
                completed[key] = r
        print(f"Resuming: {len(completed)} tools already processed")

    # Process in batches
    batch_size = args.batch_size
    results = list(completed.values())
    remaining = [t for t in all_tools if f"{t['repo']}::{t['name']}" not in completed]

    if not remaining:
        print("All tools already processed.")
    else:
        print(f"Processing {len(remaining)} tools in batches of {batch_size}...")

    errors = 0
    start_time = time.time()

    for batch_start in range(0, len(remaining), batch_size):
        batch = remaining[batch_start:batch_start + batch_size]
        batch_num = batch_start // batch_size + 1
        total_batches = (len(remaining) + batch_size - 1) // batch_size

        print(f"\nBatch {batch_num}/{total_batches} "
              f"[{batch_start + 1}-{min(batch_start + batch_size, len(remaining))}/{len(remaining)}]")

        batch_results = await process_batch(client, batch, model_hf_id)

        for tool, llm_result in zip(batch, batch_results):
            has_error = "error" in llm_result
            if has_error:
                errors += 1
                print(f"  ERROR: {tool['name']}: {llm_result['error'][:100]}")

            result = {
                "name": tool["name"],
                "repo": tool["repo"],
                "language": tool["language"],
                "properties": tool["properties"],
                "model": args.model_name,
                "model_hf_id": model_hf_id,
                "llm_analysis": llm_result,
                "has_error": has_error,
            }
            results.append(result)

            # Append to output file incrementally (for resume support)
            with open(args.output, "a") as f:
                f.write(json.dumps(result) + "\n")

        # Progress
        done = batch_start + len(batch)
        elapsed = time.time() - start_time
        rate = done / elapsed if elapsed > 0 else 0
        eta = (len(remaining) - done) / rate if rate > 0 else 0
        print(f"  Progress: {done}/{len(remaining)} "
              f"({done/len(remaining)*100:.1f}%) "
              f"| {rate:.1f} tools/sec | ETA: {eta:.0f}s "
              f"| Errors: {errors}")

    elapsed_total = time.time() - start_time
    print(f"\nCompleted in {elapsed_total:.1f}s")
    print(f"Total results: {len(results)}, Errors: {errors}")

    # Compute summary
    compute_model_summary(results, args.model_name, args.summary)


def compute_model_summary(results, model_name, summary_path):
    """Compute summary statistics for a single model run."""
    per_property = {}
    total_assessed = 0
    total_mentioned = 0
    errors = 0

    # Inter-model agreement tracking
    confidence_counts = Counter()

    for r in results:
        analysis = r.get("llm_analysis", {})
        if "error" in analysis:
            errors += 1
            continue

        for prop in r["properties"]:
            prop_result = analysis.get(prop, {})
            if not prop_result or "error" in prop_result:
                continue

            if prop not in per_property:
                per_property[prop] = {
                    "total": 0, "mentioned": 0,
                    "high_conf": 0, "medium_conf": 0, "low_conf": 0,
                }

            per_property[prop]["total"] += 1
            total_assessed += 1

            mentioned = prop_result.get("mentioned", False)
            if mentioned:
                per_property[prop]["mentioned"] += 1
                total_mentioned += 1

            conf = prop_result.get("confidence", "unknown")
            confidence_counts[conf] += 1
            if conf == "high":
                per_property[prop]["high_conf"] += 1
            elif conf == "medium":
                per_property[prop]["medium_conf"] += 1
            elif conf == "low":
                per_property[prop]["low_conf"] += 1

    # Compute rates
    for prop in per_property:
        t = per_property[prop]["total"]
        m = per_property[prop]["mentioned"]
        per_property[prop]["rate"] = m / t if t > 0 else 0
        per_property[prop]["missing_rate"] = 1 - (m / t) if t > 0 else 1

    # Language breakdown
    lang_stats = defaultdict(lambda: {"total": 0, "mentioned": 0})
    for r in results:
        analysis = r.get("llm_analysis", {})
        if "error" in analysis:
            continue
        lang = r.get("language", "unknown")
        for prop in r["properties"]:
            prop_result = analysis.get(prop, {})
            if not prop_result or "error" in prop_result:
                continue
            lang_stats[lang]["total"] += 1
            if prop_result.get("mentioned", False):
                lang_stats[lang]["mentioned"] += 1

    for lang in lang_stats:
        t = lang_stats[lang]["total"]
        m = lang_stats[lang]["mentioned"]
        lang_stats[lang]["rate"] = m / t if t > 0 else 0

    summary = {
        "model_name": model_name,
        "model_hf_id": SUPPORTED_MODELS.get(model_name, {}).get("hf_id", "unknown"),
        "model_display": SUPPORTED_MODELS.get(model_name, {}).get("display", "unknown"),
        "total_tools": len(results),
        "total_assessed": total_assessed,
        "total_mentioned": total_mentioned,
        "total_errors": errors,
        "overall_rate": total_mentioned / total_assessed if total_assessed > 0 else 0,
        "per_property": per_property,
        "confidence_distribution": dict(confidence_counts),
        "language_breakdown": dict(lang_stats),
    }

    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Print summary
    print(f"\n{'='*70}")
    print(f"RQ2: LLM ANALYSIS RESULTS - {SUPPORTED_MODELS.get(model_name, {}).get('display', model_name)}")
    print(f"{'='*70}")
    print(f"Total tools: {len(results)}")
    print(f"Successfully assessed: {total_assessed} property-checks")
    print(f"Errors: {errors}")
    print(f"Overall mention rate: {summary['overall_rate']:.1%}")
    print()
    print(f"{'Property':<20} {'Rate':>10} {'Mentioned':>10} {'Total':>8} {'High':>6} {'Med':>6} {'Low':>6}")
    print("-" * 70)
    for prop in SECURITY_PROPERTIES:
        s = per_property.get(prop)
        if not s:
            continue
        print(f"{prop:<20} {s['rate']:>9.1%} {s['mentioned']:>10}/{s['total']:<6} "
              f"{s['high_conf']:>6} {s['medium_conf']:>6} {s['low_conf']:>6}")
    print()
    print("By language:")
    for lang, ls in sorted(lang_stats.items()):
        print(f"  {lang}: {ls['rate']:.1%} ({ls['mentioned']}/{ls['total']})")
    print()
    print(f"Confidence distribution: {dict(confidence_counts)}")
    print(f"Summary saved to: {summary_path}")


def combine_results(args):
    """Combine results from multiple model runs into a single summary."""
    combine_dir = Path(args.combine_dir)
    all_summaries = {}
    all_results = {}

    for model_name in SUPPORTED_MODELS:
        result_file = combine_dir / f"llm_analysis_{model_name}.jsonl"
        summary_file = combine_dir / f"llm_summary_{model_name}.json"

        if result_file.exists():
            results = []
            with open(result_file) as f:
                for line in f:
                    results.append(json.loads(line))
            all_results[model_name] = results
            print(f"Loaded {len(results)} results for {model_name}")

        if summary_file.exists():
            with open(summary_file) as f:
                all_summaries[model_name] = json.load(f)

    if not all_results:
        print("No result files found. Run individual models first.")
        sys.exit(1)

    # Compute inter-model agreement
    # Build tool-property level comparison
    tool_prop_verdicts = defaultdict(dict)  # (repo, name, prop) -> {model: mentioned}

    for model_name, results in all_results.items():
        for r in results:
            analysis = r.get("llm_analysis", {})
            if "error" in analysis:
                continue
            for prop in r["properties"]:
                prop_result = analysis.get(prop, {})
                if not prop_result or "error" in prop_result:
                    continue
                key = (r["repo"], r["name"], prop)
                tool_prop_verdicts[key][model_name] = prop_result.get("mentioned", False)

    # Agreement statistics
    total_comparisons = 0
    full_agree = 0
    majority_mentioned = 0
    majority_not_mentioned = 0
    pairwise_agree = Counter()
    pairwise_total = Counter()

    models_present = sorted(all_results.keys())

    for key, verdicts in tool_prop_verdicts.items():
        if len(verdicts) < 2:
            continue
        total_comparisons += 1

        values = list(verdicts.values())
        if all(v == values[0] for v in values):
            full_agree += 1

        mentioned_count = sum(1 for v in values if v)
        if mentioned_count > len(values) / 2:
            majority_mentioned += 1
        else:
            majority_not_mentioned += 1

        # Pairwise
        model_list = sorted(verdicts.keys())
        for i in range(len(model_list)):
            for j in range(i + 1, len(model_list)):
                pair = f"{model_list[i]}_vs_{model_list[j]}"
                pairwise_total[pair] += 1
                if verdicts[model_list[i]] == verdicts[model_list[j]]:
                    pairwise_agree[pair] += 1

    # Majority vote transparency per property
    majority_per_property = defaultdict(lambda: {"total": 0, "mentioned": 0})
    for key, verdicts in tool_prop_verdicts.items():
        if len(verdicts) < 2:
            continue
        prop = key[2]
        majority_per_property[prop]["total"] += 1
        mentioned_count = sum(1 for v in verdicts.values() if v)
        if mentioned_count > len(verdicts) / 2:
            majority_per_property[prop]["mentioned"] += 1

    for prop in majority_per_property:
        t = majority_per_property[prop]["total"]
        m = majority_per_property[prop]["mentioned"]
        majority_per_property[prop]["rate"] = m / t if t > 0 else 0

    combined = {
        "models": models_present,
        "per_model_summaries": all_summaries,
        "inter_model_agreement": {
            "total_comparisons": total_comparisons,
            "full_agreement": full_agree,
            "full_agreement_rate": full_agree / total_comparisons if total_comparisons > 0 else 0,
            "majority_mentioned": majority_mentioned,
            "majority_not_mentioned": majority_not_mentioned,
            "pairwise_agreement": {
                pair: {
                    "agree": pairwise_agree[pair],
                    "total": pairwise_total[pair],
                    "rate": pairwise_agree[pair] / pairwise_total[pair] if pairwise_total[pair] > 0 else 0,
                }
                for pair in sorted(pairwise_total.keys())
            },
        },
        "majority_vote_transparency": {
            "overall_rate": (
                sum(v["mentioned"] for v in majority_per_property.values()) /
                sum(v["total"] for v in majority_per_property.values())
                if sum(v["total"] for v in majority_per_property.values()) > 0 else 0
            ),
            "per_property": dict(majority_per_property),
        },
    }

    with open(args.summary, "w") as f:
        json.dump(combined, f, indent=2)

    # Print combined summary
    print(f"\n{'='*70}")
    print(f"COMBINED RQ2 RESULTS ({len(models_present)} models)")
    print(f"{'='*70}")
    print(f"Models: {', '.join(models_present)}")
    print()

    # Per-model overview
    print(f"{'Model':<20} {'Overall Rate':>15} {'Assessed':>10} {'Errors':>8}")
    print("-" * 55)
    for model in models_present:
        s = all_summaries.get(model, {})
        print(f"{model:<20} {s.get('overall_rate', 0):>14.1%} "
              f"{s.get('total_assessed', 0):>10} {s.get('total_errors', 0):>8}")

    print(f"\nInter-model agreement:")
    print(f"  Full agreement: {full_agree}/{total_comparisons} "
          f"({full_agree/total_comparisons*100:.1f}%)" if total_comparisons else "  No comparisons")
    for pair, stats in sorted(combined["inter_model_agreement"]["pairwise_agreement"].items()):
        print(f"  {pair}: {stats['rate']:.1%} ({stats['agree']}/{stats['total']})")

    print(f"\nMajority vote transparency (per property):")
    for prop in SECURITY_PROPERTIES:
        s = majority_per_property.get(prop)
        if not s:
            continue
        print(f"  {prop:<20} {s['rate']:.1%} ({s['mentioned']}/{s['total']})")

    total_m = sum(v["mentioned"] for v in majority_per_property.values())
    total_t = sum(v["total"] for v in majority_per_property.values())
    print(f"  {'OVERALL':<20} {total_m/total_t:.1%} ({total_m}/{total_t})" if total_t else "")

    print(f"\nCombined summary saved to: {args.summary}")


def main():
    parser = argparse.ArgumentParser(
        description="RQ2: LLM-based security transparency analysis using vLLM"
    )
    parser.add_argument("--input", help="Input JSONL file (independent_dataset.jsonl)")
    parser.add_argument("--model-name", choices=list(SUPPORTED_MODELS.keys()),
                        help="Short name of the model to use")
    parser.add_argument("--output", help="Output JSONL file for this model's results")
    parser.add_argument("--summary", help="Output JSON file for summary statistics")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of tools to process (0 = all)")
    parser.add_argument("--batch-size", type=int, default=8,
                        help="Number of concurrent requests to vLLM (default 8)")
    parser.add_argument("--vllm-url", default="http://localhost:8000",
                        help="vLLM server URL (default http://localhost:8000)")
    parser.add_argument("--combine", action="store_true",
                        help="Combine results from all models")
    parser.add_argument("--combine-dir", default="results/",
                        help="Directory containing per-model result files")
    parser.add_argument("--list-models", action="store_true",
                        help="List supported models and vLLM launch commands")
    args = parser.parse_args()

    if args.list_models:
        print("Supported models and vLLM launch commands:\n")
        for name, info in SUPPORTED_MODELS.items():
            print(f"  {name}: {info['display']}")
            print(f"    HuggingFace ID: {info['hf_id']}")
            print(f"    vLLM command:")
            print(f"      vllm serve {info['hf_id']} {info['vllm_args']} --port 8000")
            print()
        return

    if args.combine:
        if not args.summary:
            args.summary = str(Path(args.combine_dir) / "llm_summary_combined.json")
        combine_results(args)
        return

    if not args.input or not args.model_name or not args.output or not args.summary:
        parser.error("--input, --model-name, --output, and --summary are required "
                      "(unless using --combine or --list-models)")

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
