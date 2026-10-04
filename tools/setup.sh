#!/usr/bin/env bash
# One-time setup after cloning: the Python environment, CICFlowMeter, the published model and, if wanted, the dataset.
#
# Run:  tools/setup.sh                                   asks whether to download the dataset, and which part
#       tools/setup.sh --dataset none|processed|model|both [--days <day> ...]    no questions
# Env:  NETWATCH_HF_ACCOUNT   the Hugging Face account that hosts the two repositories (default kaustuk000)
#       NETWATCH_REVISION     the release to fetch (default v1.0.0)
#
# Installs only; it starts nothing. The model lands in artifacts/huggingface/download/netwatch-flow-cascade/ and
# artifacts/current is pointed at it; a local training run already promoted to artifacts/current is never replaced. The
# dataset lands in artifacts/huggingface/download/netwatch-ids2018-events/ in the repository's own layout. Safe to
# re-run.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
ACCOUNT="${NETWATCH_HF_ACCOUNT:-kaustuk000}"
REVISION="${NETWATCH_REVISION:-v1.0.0}"
MODEL_REPO=netwatch-flow-cascade
DATASET_REPO=netwatch-ids2018-events
DOWNLOADS=artifacts/huggingface/download
DATASET=ask
DAYS=()

while [ $# -gt 0 ]; do
	case "$1" in
		--dataset) DATASET="$2"; shift 2 ;;
		--days) shift; while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do DAYS+=("$1"); shift; done ;;
		-h|--help) sed -n '2,12p' "$0"; exit 0 ;;
		*) echo "unknown option: $1 (see --help)"; exit 2 ;;
	esac
done
case "$DATASET" in ask|none|processed|model|both) ;; *) echo "--dataset must be none, processed, model or both"; exit 2 ;; esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1 -- $2"; exit 1; }; }
need git "https://git-scm.com"
need uv "https://docs.astral.sh/uv/getting-started/installation/"
need java "a JDK 8, which CICFlowMeter builds with"
command -v tshark >/dev/null 2>&1 || echo "note: tshark is not installed; ingest and live capture need it (apt install tshark)"

hf_py() { uv run --quiet --with huggingface_hub python "$@"; }

echo "== 1/4 Python environment"
uv sync

echo "== 2/4 CICFlowMeter"
tools/setup_cicflowmeter.sh

echo "== 3/4 model ($REVISION)"
hf_py tools/publish/download.py --repo "$ACCOUNT/$MODEL_REPO" --revision "$REVISION"   # asks for a login only if gated
mkdir -p artifacts
if [ ! -e artifacts/current ] && [ ! -L artifacts/current ]; then
	ln -s "huggingface/download/$MODEL_REPO" artifacts/current
	echo "artifacts/current -> $DOWNLOADS/$MODEL_REPO"
elif [ "$(readlink artifacts/current 2>/dev/null)" = "huggingface/download/$MODEL_REPO" ]; then
	echo "artifacts/current already points at the published model"
else
	echo "artifacts/current holds a local training run and is kept; the published model is in $DOWNLOADS/$MODEL_REPO"
fi

echo "== 4/4 dataset"
if [ "$DATASET" = ask ]; then
	read -rp "Download the dataset too? It is large and gated (accept its terms on Hugging Face; you are asked to log in). [y/N] " yes
	if [[ "$yes" =~ ^[Yy] ]]; then
		echo "  1) processed  model-agnostic tables: events, node index, flow records, side features   ~4.8 GB"
		echo "  2) model      flow embeddings and latents of this model version                     ~7.8 GB"
		echo "  3) both                                                                              ~12.7 GB"
		read -rp "Which one? [1/2/3] " pick
		case "$pick" in 1) DATASET=processed ;; 2) DATASET=model ;; 3) DATASET=both ;; *) echo "no choice made; skipping the dataset"; DATASET=none ;; esac
		if [ "$DATASET" != none ]; then
			echo "Days: Thursday-15-02-2018 Friday-16-02-2018 Friday-23-02-2018 Thursday-01-03-2018 Friday-02-03-2018"
			read -rp "Which days? (space-separated, Enter for all five) " line
			read -ra DAYS <<< "$line"
		fi
	else
		DATASET=none
	fi
fi
if [ "$DATASET" = none ]; then
	echo "dataset skipped"
else
	SETS=("$DATASET"); [ "$DATASET" = both ] && SETS=(processed model)
	hf_py tools/publish/download.py --dataset "$ACCOUNT/$DATASET_REPO" --revision "$REVISION" --sets "${SETS[@]}" \
		${DAYS[@]+--days "${DAYS[@]}"}
fi

echo
echo "Done. The model is in $DOWNLOADS/$MODEL_REPO (artifacts/current points at it unless a local run is there)."
