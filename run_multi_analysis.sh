#!/bin/bash
# Run the multi-technique analysis
# Usage: cd Paper2_Description_Security && bash run_multi_analysis.sh

set -e

# Create venv if needed
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate

# Install dependencies
pip install -q numpy scikit-learn sentence-transformers rank-bm25 gensim

# Run the analysis
python3 scripts/multi_technique_analyzer.py \
    --input data/tools_with_descriptions.jsonl \
    --output results/multi_technique_results.jsonl \
    --summary results/multi_technique_summary.json

echo ""
echo "Done! Results saved to:"
echo "  results/multi_technique_results.jsonl  (per-tool details)"
echo "  results/multi_technique_summary.json   (summary statistics)"
echo "  results/multi_technique_summary_report.txt (comparison tables)"
