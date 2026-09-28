#!/usr/bin/env bash
# Train Blocks 7-10 on every ingested day, calibrate Block 10, and put the result into service.
#
# Run it detached, because a long job started with & or nohup dies with the terminal (deployment runbook, section 3):
#     tmux new -s train 'tools/train_all.sh'            # detach: Ctrl-b d      reattach: tmux attach -t train
#
# Everything a run produces goes into its own folder, and nothing already trained is overwritten:
#     ~/netwatch-data/runs/<stamp>/
#         b7/            Block 7 flow encoder, v1 checkpoint with its normalisation stats
#         embeddings/    Block 7 exports, split/<day>/          (Blocks 8 and 9 read these, not data/flow_embeddings)
#         record_encoder.pt  the flow-record encoder, trained on benign records and frozen (Block 8 reads it)
#         b8det/         Block 8 for the DETECTOR: packets + 20-packet summary, no flow records
#         detector/      the supervised detection head on b8det, one head_<day>.pt per day
#         b8/  b9/       Block 8 for the WORLD MODEL (packets + summary + flow records), and Block 9 on it
#         latents/<day>  Block 9 latents, what Block 10 reads
#         b10/           world model, calibrated thresholds stored inside best.pt
#         calibration/   the full budget curve, per-score AUCs, prefix-invariance check
#         serving.json   the models behind each world-model tag (delay, live);  parity/  the tolerance report per tag
#         logs/          one log per stage;  tb/ TensorBoard;  manifest.json  what was run, how long, where
# Every epoch's model is kept beside the best (b7/<stem>_epochNN.pt, b8det|b8|b9|b10/epoch_NN.pt; ~14 MB for a full run),
# and every block has a resume file, so an interrupted stage continues from its last finished epoch.
# Every block records its loss and score for train, validation and -- where the days have one -- test, for its best
# checkpoint: b8det/, b8/, b9/, b10/ best_metrics.csv (history.csv has every epoch); b7/<stem>_history.csv and
# b7/results.csv (held-out and cross-day scores); detector/results.csv (test recall/FPR per budget); calibration/.
# When every stage has finished, the best models are copied into artifacts/current in the repository (tools/promote.py;
# the previous set is kept as artifacts/previous) and the services are restarted on them. A stage that finished is skipped on a re-run, so an interrupted run resumes: RUN_DIR=<that folder> tools/train_all.sh
#
# Settings, as environment variables (defaults are the full run):
#     B7_EPOCHS=10 B8DET_EPOCHS=5 B8_EPOCHS=5 B9_EPOCHS=5 B10_EPOCHS=5
#                          epochs per block, the full five-day run takes ~35 h (below); EPOCHS=N sets
#                          all. Early stopping is off so each block runs every epoch; the best by validation is kept.
#     RECORD_DAY=Thursday-15-02-2018   the day the record encoder is fitted on (its benign records)
#     DAYS="..."           the days to train on (default: all five ingested days)
#     SEED=0               seed for every block
#     B7_SAMPLE=320000     Block 7 events sampled per day to FIT on (+ a quarter each for val and test); the export
#                          still embeds every event. The served checkpoint was fitted at 160000; not yet timed at 320000
#     B8_LIMIT=            Block 8 training events per stream per day; empty = every event
#     B9_LIMIT=            Block 9 training events per stream per day; empty = every event
#     B10_LIMIT=           Block 10 events per split per day; empty = every event
#     CAL_LIMIT=           calibration events per day; empty = every event
#     BUDGET=1e-4          the world model's served false-positive budget;  CALIBRATE=0.2  share of train benign added to validation
#     SERVE_BUDGET=1e-4    the detector's served false-alarm budget: each family's threshold at it is committed into its head
#     PROMOTE=1            copy the best models into artifacts/current and restart the services when it finishes
#     SMOKE=1              a minutes-long wiring check on one day with tiny caps; never promoted
#
# Two Block 8s, because the two consumers differ: the detection head must not see flow records (packets and the
# 20-packet summary only), while the world model's path through Block 9 uses the records as well.
#
# Time on this machine (RTX 3050 6 GB, 15 GB RAM), five days (35.1M events), default epochs. Measured on the run of
# 2026-09-26: Block 7 1.5 h | record encoder 5-8 min | Block 8 detector 4.4 h (53 min/epoch) | detector heads 2.4 h
# | Block 8 world model ~70 min/epoch after a first epoch of 2.9 h that also builds the day caches (~7.5 h).
# Estimated, not yet measured at full size: Block 9 ~3.3 h | latents ~0.8 h | Block 10 ~4.8 h | calibration ~0.7 h,
# and the same four again for the live tag (~9.5 h; LIVE=0 skips them)                  => about 35 h in all.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_HOME="${DATA_HOME:-$HOME/netwatch-data}"
SMOKE="${SMOKE:-0}"
ALL_DAYS="Friday-16-02-2018 Friday-02-03-2018 Friday-23-02-2018 Thursday-15-02-2018 Thursday-01-03-2018"
DAYS="${DAYS:-$ALL_DAYS}"
EPOCHS="${EPOCHS:-}"                       # set to force one epoch count on every block
B7_EPOCHS="${B7_EPOCHS:-${EPOCHS:-10}}"
B8DET_EPOCHS="${B8DET_EPOCHS:-${EPOCHS:-5}}"
B8_EPOCHS="${B8_EPOCHS:-${EPOCHS:-5}}"
B9_EPOCHS="${B9_EPOCHS:-${EPOCHS:-5}}"
B10_EPOCHS="${B10_EPOCHS:-${EPOCHS:-5}}"
RECORD_DAY="${RECORD_DAY:-Thursday-15-02-2018}"
RECORD_STEPS="${RECORD_STEPS:-1000}"             # record encoder steps (65,536 records each); 200 had not converged
SEED="${SEED:-0}"
B7_SAMPLE="${B7_SAMPLE:-320000}"
B8_LIMIT="${B8_LIMIT:-}"
B9_LIMIT="${B9_LIMIT:-}"
B10_LIMIT="${B10_LIMIT:-}"
CAL_LIMIT="${CAL_LIMIT:-}"
BUDGET="${BUDGET:-1e-4}"
SERVE_BUDGET="${SERVE_BUDGET:-1e-4}"              # the detector's served false-alarm budget (0.01%), per family
CALIBRATE="${CALIBRATE:-0.2}"
PROMOTE="${PROMOTE:-1}"
EMB_SOURCE=""                                  # empty: this run's own Block 7 export
if [ "$SMOKE" = 1 ]; then
	DAYS="Thursday-15-02-2018"; B7_EPOCHS=1; B8DET_EPOCHS=1; B8_EPOCHS=1; B9_EPOCHS=1; B10_EPOCHS=1
	B7_SAMPLE=3000; B10_LIMIT=3000; CAL_LIMIT=6000; PROMOTE=0
	# A full-day Block 7 export is required downstream (rows must line up with the day), so the smoke run checks Block
	# 7's fit and export on a small scratch export, and runs Blocks 8-10 on the existing embeddings.
	EMB_SOURCE="$REPO/data/flow_embeddings"
fi
read -r -a DAY_LIST <<< "$DAYS"
# `|| true`: under set -e a command substitution that ends false aborts the whole assignment -- which is exactly what
# happened on every non-smoke run, before the first stage.
RUN="${RUN_DIR:-$DATA_HOME/runs/$(date +%Y%m%d-%H%M)$([ "$SMOKE" = 1 ] && echo -smoke || true)}"
mkdir -p "$RUN/logs" "$RUN/tb"
cd "$REPO"
export PYTHONPATH=.

say() { echo "[$(date '+%F %T')] $*" | tee -a "$RUN/train.log"; }
done_mark() { [ -f "$RUN/.done-$1" ]; }
uvpy() { uv run python "$@"; }

# stage NAME COMMAND...: run once, log it, time it, and record it in the manifest. A finished stage is skipped.
stage() {
	local name="$1"; shift
	if done_mark "$name"; then say "skip   $name (done in an earlier run of this folder)"; return 0; fi
	say "start  $name"
	local started=$SECONDS
	if ! "$@" > "$RUN/logs/$name.log" 2>&1; then
		say "FAILED $name after $((SECONDS - started))s -- see $RUN/logs/$name.log"
		tail -20 "$RUN/logs/$name.log" | grep -viE "warn" || true
		exit 1
	fi
	echo "$((SECONDS - started))" > "$RUN/.done-$name"
	say "done   $name in $((SECONDS - started))s"
}

# ---- preflight --------------------------------------------------------------------------------------------------
say "run $RUN | days: ${DAY_LIST[*]} | epochs B7 $B7_EPOCHS B8det $B8DET_EPOCHS B8 $B8_EPOCHS B9 $B9_EPOCHS B10 $B10_EPOCHS | seed $SEED | smoke $SMOKE"
[ -z "${TMUX:-}${STY:-}" ] && say "note: not inside tmux/screen -- if this terminal closes, the run dies (see the header)"
for day in "${DAY_LIST[@]}"; do
	for f in "data/events/$day/events.parquet" "data/context_features/$day/side_features.parquet"; do
		[ -f "$f" ] || { say "missing $f -- ingest and side features must exist for every day"; exit 1; }
	done
done
uvpy -c "import torch; assert torch.cuda.is_available(), 'no GPU visible'; print(torch.cuda.get_device_name(0))" \
	2>/dev/null | tail -1 | sed 's/^/GPU: /' | tee -a "$RUN/train.log" || say "no GPU visible -- continuing on CPU"
# The live runner and the replay service hold GPU and RAM that five days of latents need. They are restarted on the new
# models at the end (or can be restarted by hand with the launcher).
if [ "$SMOKE" != 1 ]; then
	pkill -f "models.serving.live" 2>/dev/null && say "paused the live runner for training" || true
	pkill -f "models.world_model.service" 2>/dev/null && say "paused the replay service for training" || true
	pkill -f "models.serving.detect_live" 2>/dev/null && say "paused the live detector for training" || true
fi
say "limits per day: Block 8 ${B8_LIMIT:-all} | Block 9 ${B9_LIMIT:-all} | Block 10 ${B10_LIMIT:-all} | calibration ${CAL_LIMIT:-all}"
[ "$SMOKE" != 1 ] && [ -z "$B8_LIMIT$B9_LIMIT$B10_LIMIT" ] && say "expect about 35 h at the default epochs on this machine (header)"

# ---- Block 7: flow encoder, fitted on every day, exported for every day -----------------------------------------
B7_STEM="$(IFS=+; echo "${DAY_LIST[*]}")__${DAY_LIST[0]}__a_pkt__gnn__relu__s$SEED"
if [ "$SMOKE" = 1 ]; then B7_EXPORT="--export-limit 2000"; else B7_EXPORT=""; fi
stage b7 uvpy -m models.flow_encoder --side split --packet-encoder gnn --budget-ms 10 \
	--fit-day "${DAY_LIST[@]}" --cross-day "${DAY_LIST[0]}" \
	--sample "$B7_SAMPLE" --epochs "$B7_EPOCHS" --patience "$B7_EPOCHS" --model-seed "$SEED" --seed "$SEED" --readers 8 \
	--cache-root "$RUN/b7/cache" --save-scores "$RUN/b7" --results-csv "$RUN/b7/results.csv" --resume "$RUN/b7/resume.pt" \
	--export "$RUN/embeddings/split" --export-days "${DAY_LIST[@]}" $B7_EXPORT \
	--tensorboard "$RUN/tb" --run-name b7
EMB_ROOT="${EMB_SOURCE:-$RUN/embeddings}"

# ---- flow records: the CICFlowMeter record per event, and the frozen encoder Block 8 reads it through --------------
# Written beside the side features in data/context_features (derived from ingest, the same for every run); a day that
# already has its records is left alone.
MISSING=(); for day in "${DAY_LIST[@]}"; do [ -f "data/context_features/$day/flow_records.parquet" ] || MISSING+=("$day"); done
if [ ${#MISSING[@]} -gt 0 ]; then stage records uvpy -m models.context_encoder.records --days "${MISSING[@]}"; fi
if [ "$SMOKE" = 1 ]; then REC_SLICE="--events 300000"; else REC_SLICE=""; fi
stage record_encoder uvpy -m models.context_encoder.records --days "$RECORD_DAY" \
	--train-encoder "$RUN/record_encoder.pt" --steps "$RECORD_STEPS" $REC_SLICE

# ---- Block 8, twice -------------------------------------------------------------------------------------------------
B8_EXTRA=""; [ -n "$B8_LIMIT" ] && B8_EXTRA="--limit $B8_LIMIT"; [ "$SMOKE" = 1 ] && B8_EXTRA="--limit 20000"
B8_COMMON=(--arm split --days "${DAY_LIST[@]}" --embeddings-root "$EMB_ROOT" --day-cache "$RUN/daycache"
	--patience 99 --batch-size 512 --lr 1e-3 --seed "$SEED" --capacity 0.25 --lr-schedule cosine
	--tensorboard "$RUN/tb")
# For the detection head: packets and the 20-packet summary, never the flow record.
stage b8det uvpy -m models.context_encoder "${B8_COMMON[@]}" --out "$RUN/b8det" --epochs "$B8DET_EPOCHS" \
	--flow-messages --resume "$RUN/b8det/resume.pt" --run-name b8det $B8_EXTRA
if [ "$SMOKE" = 1 ]; then DET_SLICE="--events 300000 --family DoS-Slowloris"; else DET_SLICE=""; fi
mkdir -p "$RUN/detector"
stage detector uvpy -m models.detector --days "${DAY_LIST[@]}" --context-encoder "$RUN/b8det/best.pt" \
	--embeddings-root "$EMB_ROOT" --save "$RUN/detector/head.pt" --save-scores "$RUN/detector/scores.pt" \
	--out "$RUN/detector/results.csv" --seed "$SEED" $DET_SLICE
# The detector's operating point: each family gets its own threshold, the quantile of its benign calibration scores at
# SERVE_BUDGET false alarms, committed into its head as serve_threshold -- what the live detector serves.
serve_thresholds() {
	for head in "$RUN"/detector/head_*.pt; do
		day=$(basename "$head" .pt); day=${day#head_}
		uvpy -m models.evaluation.thresholds --scores "$RUN/detector/scores_$day.pt" --budgets "$SERVE_BUDGET" \
			--recall-floor 0 --write "$head" || return 1
	done
}
stage serve_threshold serve_thresholds
# For the world model: packets, the summary and the flow record, each applied when it could first exist.
stage b8 uvpy -m models.context_encoder "${B8_COMMON[@]}" --out "$RUN/b8" --epochs "$B8_EPOCHS" \
	--flow-messages --flow-records --record-encoder "$RUN/record_encoder.pt" \
	--resume "$RUN/b8/resume.pt" --run-name b8 $B8_EXTRA

# ---- Block 9: compressor, then the latents Block 10 reads ------------------------------------------------------
B9_EXTRA=""; [ -n "$B9_LIMIT" ] && B9_EXTRA="--limit $B9_LIMIT"; [ "$SMOKE" = 1 ] && B9_EXTRA="--limit 20000"
stage b9 uvpy -m models.compressor --encoder mlp --target s --context-encoder "$RUN/b8/best.pt" \
	--days "${DAY_LIST[@]}" --out "$RUN/b9" --embeddings-root "$EMB_ROOT" --day-cache "$RUN/daycache" \
	--epochs "$B9_EPOCHS" --patience "$B9_EPOCHS" --window 512 --d-z 32 --lr 1e-3 --normalise-rows 200000 \
	--seed "$SEED" --lr-schedule cosine --resume "$RUN/b9/resume.pt" --tensorboard "$RUN/tb" --run-name b9 $B9_EXTRA
if [ "$SMOKE" = 1 ]; then LATENT_SLICE="--events 60000 --family DoS-Slowloris"; else LATENT_SLICE=""; fi
stage latents uvpy -m models.compressor --encoder mlp --target s --context-encoder "$RUN/b8/best.pt" \
	--load "$RUN/b9/best.pt" --out "$RUN/b9" --export "$RUN/latents" --window 512 \
	--days "${DAY_LIST[@]}" --embeddings-root "$EMB_ROOT" --day-cache "$RUN/daycache" $LATENT_SLICE
LATENTS=(); for day in "${DAY_LIST[@]}"; do LATENTS+=("$RUN/latents/$day"); done

# ---- Block 10: world model, then its calibration -----------------------------------------------------------------
B10_EXTRA=""; [ -n "$B10_LIMIT" ] && B10_EXTRA="--limit $B10_LIMIT"
stage b10 uvpy -m models.world_model --latents "${LATENTS[@]}" --out "$RUN/b10" \
	--epochs "$B10_EPOCHS" --patience "$B10_EPOCHS" --window 512 --lr 1e-3 --rank-weight 1.0 --seed "$SEED" \
	--lr-schedule cosine --resume "$RUN/b10/resume.pt" --tensorboard "$RUN/tb" --run-name b10 $B10_EXTRA
CAL_EXTRA=""; [ -n "$CAL_LIMIT" ] && CAL_EXTRA="--limit $CAL_LIMIT"
mkdir -p "$RUN/calibration"
stage calibration uvpy -m models.world_model.calibration --load "$RUN/b10/best.pt" --latents "${LATENTS[@]}" \
	--budget "$BUDGET" --calibrate "$CALIBRATE" --cache "$RUN/calibration/scores.npz" --prefix-check 3000 \
	--window 512 $CAL_EXTRA
grep -vE "warn|Warn" "$RUN/logs/calibration.log" > "$RUN/calibration/report.txt" || true

# ---- the `live` tag: a compressor and world model trained on the detection encoder's output ---------------------------
# The world model served from the 10 ms detection stream (models.serving.detect_live --forecast) reads the context that
# stream produces -- the detection encoder's, without flow records -- so it is trained on exactly that. Same settings as
# Blocks 9 and 10 above; ~9.5 h. LIVE=0 skips them. On a run that finished without them,
#     RUN_DIR=<that run> tools/train_all.sh
# runs only these (every other stage is already done) and promotes again.
if [ "${LIVE:-1}" = 1 ]; then
	stage b9live uvpy -m models.compressor --encoder mlp --target s --context-encoder "$RUN/b8det/best.pt" \
		--days "${DAY_LIST[@]}" --out "$RUN/b9live" --embeddings-root "$EMB_ROOT" --day-cache "$RUN/daycache" \
		--epochs "$B9_EPOCHS" --patience "$B9_EPOCHS" --window 512 --d-z 32 --lr 1e-3 --normalise-rows 200000 \
		--seed "$SEED" --lr-schedule cosine --resume "$RUN/b9live/resume.pt" --tensorboard "$RUN/tb" --run-name b9live \
		$B9_EXTRA
	stage latents_live uvpy -m models.compressor --encoder mlp --target s --context-encoder "$RUN/b8det/best.pt" \
		--load "$RUN/b9live/best.pt" --out "$RUN/b9live" --export "$RUN/latents-live" --window 512 \
		--days "${DAY_LIST[@]}" --embeddings-root "$EMB_ROOT" --day-cache "$RUN/daycache" $LATENT_SLICE
	LIVE_LATENTS=(); for day in "${DAY_LIST[@]}"; do LIVE_LATENTS+=("$RUN/latents-live/$day"); done
	stage b10live uvpy -m models.world_model --latents "${LIVE_LATENTS[@]}" --out "$RUN/b10live" \
		--epochs "$B10_EPOCHS" --patience "$B10_EPOCHS" --window 512 --lr 1e-3 --rank-weight 1.0 --seed "$SEED" \
		--lr-schedule cosine --resume "$RUN/b10live/resume.pt" --tensorboard "$RUN/tb" --run-name b10live $B10_EXTRA
	mkdir -p "$RUN/calibration_live"
	stage calibration_live uvpy -m models.world_model.calibration --load "$RUN/b10live/best.pt" \
		--latents "${LIVE_LATENTS[@]}" --budget "$BUDGET" --calibrate "$CALIBRATE" \
		--cache "$RUN/calibration_live/scores.npz" --prefix-check 3000 --window 512 $CAL_EXTRA
	grep -vE "warn|Warn" "$RUN/logs/calibration_live.log" > "$RUN/calibration_live/report.txt" || true
fi

# ---- serving tags, and the tolerance test of each serving path -----------------------------------------------------
# serving.json names the models behind each world-model tag (models.serving.registry). The parity reports measure, stage
# by stage, how far each serving path's inputs are from the ones training used, on a rebuilt 600 s capture of a dataset
# day. They are reports only: nothing here retrains. (`delay` is the lag tag's old name, kept so a finished run's stage
# is not redone; the live tag's inputs are checked by tools/live/detect_check.py.)
mkdir -p "$RUN/parity"
uvpy - "$RUN" "$RUN/b7/$B7_STEM.pt" <<'PY'
import sys
from pathlib import Path
from models.serving.registry import write
run, b7 = Path(sys.argv[1]), sys.argv[2]
live = run / "b10live" / "best.pt"
write(run / "serving.json", {"block7": b7, "block8": run / "b8" / "best.pt", "block9": run / "b9" / "best.pt",
                             "block10": run / "b10" / "best.pt"},
      parity={"lag": "parity/delay.json"},
      live={"block7": b7, "block8": run / "b8det" / "best.pt", "block9": run / "b9live" / "best.pt",
            "block10": live} if live.exists() else None)
PY
PARITY_DAY="${PARITY_DAY:-Thursday-15-02-2018}"; PARITY_START="${PARITY_START:-1518707112}"
stage parity_capture uvpy -m tools.live.pcap_from_packets --day "$PARITY_DAY" --start "$PARITY_START" --seconds 600 \
	--captures UCAP172.31.69.25 capPC1-172.31.65.25 --out "$RUN/parity/capture" --files 1
for tag in self delay live; do
	stage "parity_$tag" uvpy -m models.serving.parity --registry "$RUN/serving.json" --tag "$tag" \
		--pcap "$RUN/parity/capture/replay_00000.pcap" --out "$RUN/parity/$tag.json"
done

# ---- the record of what was run -----------------------------------------------------------------------------------
rm -rf "$RUN/daycache"                           # parsed days, ~2 GB each: only needed while training
uvpy - "$RUN" "$B7_STEM" "$DAYS" "$B7_EPOCHS/$B8DET_EPOCHS/$B8_EPOCHS/$B9_EPOCHS/$B10_EPOCHS" "$SEED" "$SMOKE" "$BUDGET" "$CALIBRATE" <<'PY' 2>/dev/null
import json, subprocess, sys
from pathlib import Path
import torch
run, stem, days, epochs, seed, smoke, budget, calibrate = sys.argv[1:9]
run = Path(run)
state = torch.load(run / "b10" / "best.pt", map_location="cpu", weights_only=False)
served = state.get("serve_threshold", {})
manifest = {
    "run": str(run), "commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                              text=True).stdout.strip(),
    "days": days.split(),
    "epochs": dict(zip(("block7", "block8_detector", "block8", "block9", "block10"), map(int, epochs.split("/")))),
    "seed": int(seed), "smoke": smoke == "1",
    "stage_seconds": {p.name[len(".done-"):]: int(p.read_text() or 0) for p in sorted(run.glob(".done-*"))},
    "checkpoints": {"block7": str(run / "b7" / f"{stem}.pt"), "record_encoder": str(run / "record_encoder.pt"),
                    "block8_detector": str(run / "b8det" / "best.pt"), "detector": str(run / "detector"),
                    "block8": str(run / "b8" / "best.pt"),
                    "block9": str(run / "b9" / "best.pt"), "block10": str(run / "b10" / "best.pt"),
                    "live_block9": str(run / "b9live" / "best.pt"), "live_block10": str(run / "b10live" / "best.pt")},
    "block8_inputs": {"detector": "packets + 20-packet summary", "world_model": "packets + summary + flow records"},
    "metrics": {name: str(path) for name, path in {
        "block7_history": next(iter(run.glob("b7/*_history.csv")), None), "block7_scores": run / "b7" / "results.csv",
        "block8_detector": run / "b8det" / "best_metrics.csv", "detector": run / "detector" / "results.csv",
        "block8": run / "b8" / "best_metrics.csv", "block9": run / "b9" / "best_metrics.csv",
        "block10": run / "b10" / "best_metrics.csv", "calibration": run / "calibration" / "report.txt",
        "parity_self": run / "parity" / "self.json", "parity_delay": run / "parity" / "delay.json",
        "parity_live": run / "parity" / "live.json",
    }.items() if path is not None and Path(path).exists()},
    "latents": {d: str(run / "latents" / d) for d in days.split()},
    "calibration": {"score": state.get("score"), "direction": state.get("direction"), "budget": float(budget),
                    "calibrate_share_of_train": float(calibrate),
                    "threshold": served.get("threshold"), "test_fpr": served.get("fpr"),
                    "test_recall": served.get("recall"), "persist3_recall": served.get("persist_recall"),
                    "val_auc": state.get("calibration", {}).get("val_auc"),
                    "test_auc": state.get("calibration", {}).get("test_auc")},
}
(run / "manifest.json").write_text(json.dumps(manifest, indent=2))
print(json.dumps(manifest["calibration"]))
PY
say "manifest: $RUN/manifest.json"
say "calibration: $(grep -E 'serving|ROC-AUC' "$RUN/calibration/report.txt" | tr '\n' ' ')"

# ---- put it into service -------------------------------------------------------------------------------------------
if [ "$PROMOTE" = 1 ]; then
	uvpy tools/promote.py "$RUN" && say "artifacts/current <- $RUN (the previous set is in artifacts/previous)"
	if [ -x /mnt/c/Windows/System32/wsl.exe ]; then
		/mnt/c/Windows/System32/wsl.exe -d Ubuntu -u root -- "$DATA_HOME/start.sh" >/dev/null 2>&1 \
			&& say "services restarted on the new models: forecast APIs http://localhost:8901 (live, tag delay) and :8900 (replay)" \
			|| say "restart the services with: wsl -d Ubuntu -u root -- $DATA_HOME/start.sh"
	else
		say "restart the services with: wsl -d Ubuntu -u root -- $DATA_HOME/start.sh"
	fi
else
	say "not promoted (PROMOTE=0 or smoke); artifacts/current unchanged"
fi
say "finished"
