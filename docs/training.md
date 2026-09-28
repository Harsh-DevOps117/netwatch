# Training

How to prepare the data, train every stage with one command, follow the run, and read what it produces. For what each
stage does and why, see [architecture.md](architecture.md).

---

## 1. Prepare the data (once per day)

```bash
uv run python -m ingest.cli --days <day> --workers 1 --max-worker-mem-mb 6656   # captures -> packets, flows, labels
uv run python -m ingest.build.events <day>                                       # the event stream
uv run python -m ingest.verify <day>                                             # audit; must end in RESULT: PASS
uv run python -m models.context_encoder.features --days <day>                    # side features for the context encoder
```

`<day>` is a folder under `data/raw/`, e.g. `Friday-16-02-2018`. `--max-worker-mem-mb` must stay above the ~4.8 GB the
CICFlowMeter JVM reserves, or it will not start. Flow records (`flow_records.parquet`) are created by the training
script itself for any day that lacks them.

---

## 2. Train everything

![Training order: flow encoder; flow records and record encoder; detection encoder and detector heads; forecasting encoder, compressor, latents, world model, calibration; serving and record](diagrams/training.svg)

```bash
cd ~/netwatch && tmux new -s train 'tools/train_all.sh'
```

Run it inside `tmux` (detach with `Ctrl-b d`, reattach with `tmux attach -t train`): a job started with `&` or `nohup`
dies with the terminal. The script:

1. pauses the running forecast services (they hold GPU memory and RAM the training needs);
2. trains and exports every stage in order;
3. records every stage's time, checkpoints and metrics in `manifest.json`;
4. copies the run's best models into `artifacts/current/` in the repository (`tools/promote.py`) and restarts the
   services on them ([§5](#5-what-a-run-leaves-behind)).

### Stages

| stage | what it trains or builds | key settings | writes (in the run folder) |
|---|---|---|---|
| `b7` | flow encoder, then embeds every event | `--side split --packet-encoder gnn --budget-ms 10`, 320,000 events per day to fit on, 10 epochs | `b7/<stem>.pt`, `b7/<stem>_epochNN.pt`, `b7/<stem>_history.csv`, `b7/results.csv`, `embeddings/split/<day>/` |
| `records` | flow records for days that lack them | — | `data/context_features/<day>/flow_records.parquet` |
| `record_encoder` | the frozen encoder the context encoder reads flow records through | benign records of one day (`RECORD_DAY`), 1,000 steps | `record_encoder.pt` |
| `b8det` | detection encoder: the context encoder for the detector | `--flow-messages` (no flow records), batch 512, 5 epochs | `b8det/` |
| `detector` | one detector head per day, on `b8det`, with thresholds at 0.01%, 0.1%, 1% and 5% false alarms | — | `detector/head_<day>.pt`, `scores_<day>.pt`, `results.csv` |
| `serve_threshold` | commits each family's own threshold at `SERVE_BUDGET` into its head — what the live detector serves | `--budgets 1e-4` | `serve_threshold` inside each `detector/head_<day>.pt` |
| `b8` | forecasting encoder: the context encoder for the world model | `--flow-messages --flow-records --record-encoder`, batch 512, 5 epochs | `b8/` |
| `b9` | compressor | `--encoder mlp --target s --d-z 32 --window 512`, 5 epochs | `b9/` |
| `latents` | exports `z` for every event | — | `latents/<day>/` |
| `b10` | world model | `--window 512 --rank-weight 1.0`, 5 epochs | `b10/` |
| `calibration` | the world model's served score and threshold | `--budget 1e-4 --calibrate 0.2` | thresholds inside `b10/best.pt`; `calibration/` |
| `b9live`, `latents_live`, `b10live`, `calibration_live` | the `live` tag's compressor and world model, trained on the detection encoder (`b8det`) with the same settings as `b9` … `calibration` | the same | `b9live/`, `latents-live/<day>/`, `b10live/`, `calibration_live/` |
| `parity_*` | tolerance reports for each serving path ([serving.md](serving.md#4-serving-tags)) | a rebuilt 600 s capture | `serving.json`, `parity/` |

### Settings (environment variables)

| variable | default | meaning |
|---|---|---|
| `B7_EPOCHS`, `B8DET_EPOCHS`, `B8_EPOCHS`, `B9_EPOCHS`, `B10_EPOCHS` | 10, 5, 5, 5, 5 | epochs per stage; `EPOCHS=N` sets all |
| `B7_SAMPLE` | 320000 | flow-encoder events sampled per day to fit on (validation and test get a quarter each) |
| `DAYS` | all five ingested days | days to train on |
| `RECORD_DAY` | `Thursday-15-02-2018` | the day the record encoder is fitted on |
| `RECORD_STEPS` | 1000 | record encoder training steps |
| `B8_LIMIT`, `B9_LIMIT`, `B10_LIMIT`, `CAL_LIMIT` | empty (every event) | cap events per stream per day, for quicker runs |
| `BUDGET`, `CALIBRATE` | `1e-4`, `0.2` | the world model's false-alarm budget; share of training benign added to calibration |
| `SERVE_BUDGET` | `1e-4` | the detector's served false-alarm budget (0.01%); each family's threshold at it is committed |
| `SEED` | 0 | seed for every stage |
| `LIVE` | 1 | `LIVE=0` skips the `live` tag's compressor and world model |
| `PROMOTE` | 1 | make the run current and restart the services when it finishes |
| `SMOKE` | 0 | `SMOKE=1`: a ~30-minute wiring check on one day with small caps; never promoted |
| `RUN_DIR` | a new `~/netwatch-data/runs/<stamp>` | set it to an existing run folder to resume that run |

**Time**, five days on a laptop RTX 3050 (6 GB) with 15 GB RAM, default epochs. Measured on the run of 2026-09-26:
flow encoder 1.5 h; record encoder 5–8 min; detection encoder 4.4 h (53 min per epoch); detector heads 2.4 h;
forecasting encoder about 70 min per epoch after a first epoch of 2.9 h that also builds the per-day caches. Estimated,
not yet measured at full size: compressor 3.3 h, latents 0.8 h, world model 4.8 h, calibration 0.7 h, and the same four
again for the `live` tag (~9.5 h). About 35 hours in all.

**Memory.** Loading the largest day with flow records the first time peaks at about 12.7 GB. Later epochs read a cached
copy from disk in seconds.

---

## 3. Follow a run

```bash
RUN=$(ls -td ~/netwatch-data/runs/*/ | head -1)
tail -f ${RUN}train.log           # which stage is running, and how long each took
tail -f ${RUN}logs/<stage>.log    # progress inside a stage
```

**TensorBoard** (inside WSL; open http://localhost:6006 in the browser):

```bash
tmux new -d -s tb "cd ~/netwatch && uv run python -m tensorboard.main --logdir ${RUN}tb --port 6006 --bind_all"
```

Each stage appears as its own run (`b7`, `b8det`, `b8`, `b9`, `b10`, `b9live`, `b10live`) once its first epoch has
finished; graphs update once per epoch.

---

## 4. Resuming

A finished stage is skipped when the script is run again on the same folder, and every stage writes `resume.pt` after
each epoch, so an interrupted run continues from its last finished epoch:

```bash
RUN_DIR=~/netwatch-data/runs/<stamp> tmux new -s train 'tools/train_all.sh'
```

The same command adds stages a finished run does not have yet — for example the `live` tag's, on a run trained before
they existed — and promotes the run again.

---

## 5. What a run leaves behind

```
~/netwatch-data/runs/<stamp>/
  b7/  b8det/  b8/  b9/  b10/     best model, every epoch's model, resume file, history, best_metrics.csv
  b9live/  b10live/                the same, for the live tag's compressor and world model
  detector/                        one head per day, score distributions, results.csv
  record_encoder.pt
  embeddings/  latents/            per-event outputs of the flow encoder and the compressor
  latents-live/                    the live tag's compressor output
  calibration/  calibration_live/  each world model's threshold curve and report
  serving.json  parity/            which models each serving tag uses; tolerance reports
  logs/  tb/  train.log  manifest.json
```

### The artifacts folder

Every model the project serves or publishes lives in one git-ignored folder in the repository, `artifacts/`:

```
artifacts/
  current/          the best models of the latest finished run -- what the services read
    flow_encoder.pt  detection_encoder.pt  forecasting_encoder.pt  record_encoder.pt  compressor.pt  world_model.pt
    live_compressor.pt  live_world_model.pt     the live tag's pair, when the run has them
    detector/head_<day>.pt
    serving.json    the models behind each serving tag (paths relative to this folder)
    manifest.json   the source run, its days, epochs and calibration
    metrics/        each stage's history and best metrics, the detector's results, calibration and tolerance reports
    latents         a link to the run's latents (tens of GB, not copied)
  previous/         the set current/ replaced, kept for rollback
  huggingface/
    model/  dataset/     staged for upload (publishing.md)
    download/<repo>/     a model downloaded from Hugging Face, servable through its own serving.json
```

The training script fills `current/` when a run finishes. To promote a run by hand, or to go back to an older one:

```bash
uv run python tools/promote.py ~/netwatch-data/runs/<stamp>
```

### Checkpoints

| file | written | used for |
|---|---|---|
| `best.pt` (flow encoder: `<stem>.pt`) | when validation improves | everything downstream and serving |
| `epoch_NN.pt` (flow encoder: `<stem>_epochNN.pt`) | every epoch, never overwritten | going back to any epoch |
| `resume.pt` | every epoch, overwritten | continuing an interrupted run |

### Metrics

| file | content |
|---|---|
| `b7/<stem>_history.csv` | the flow encoder's training and validation loss per epoch |
| `b7/results.csv` | probe scores on held-out rows, per population and family |
| `<stage>/history.csv` | per epoch (context encoders: per day): training and validation loss and score |
| `<stage>/best_metrics.csv` | the best checkpoint's loss and score on training, validation and — where the days have one — test. Test is scored once, never used to choose |
| `detector/results.csv` | recall, false-positive rate and precision per family at each budget, on the test split |
| `calibration/report.txt`, `calibration_live/report.txt` | each world model's served score, threshold, and ROC-AUC on validation and test |

`manifest.json` lists every file above with its path, plus each stage's duration.

---

## 6. The detector's operating point

The served false-alarm budget is **0.01%** (`SERVE_BUDGET`). Every family gets **its own threshold**: the 99.99th
percentile of that family's score on its head's benign calibration rows (validation plus 20% of training; test rows are
never used). The training script commits it into the head as `serve_threshold`, which the live detector serves. The
run of 2026-09-26:

| head (day) | family | threshold | recall, test | false alarms, test | false-alarm rate, test | per hour of test |
|---|---|---|---|---|---|---|
| Friday-16-02-2018 | DoS-Hulk | 0.787015 | 0.9987 | 115 of 1,238,298 | 0.0093% | 41.4 |
| Friday-16-02-2018 | DoS-SlowHTTPTest | 0.266059 | 1.0000 | 106 of 1,238,298 | 0.0086% | 38.2 |
| Friday-02-03-2018 | Bot | 0.440151 | 0.9905 | 182 of 1,680,628 | 0.0108% | 52.5 |
| Friday-23-02-2018 | Brute Force -Web | 0.672325 | 0.8358 | 216 of 1,424,871 | 0.0152% | 67.0 |
| Friday-23-02-2018 | Brute Force -XSS | 0.320941 | 0.8974 | 181 of 1,424,871 | 0.0127% | 56.1 |
| Friday-23-02-2018 | SQL Injection | 0.203233 | 0.6190 | 199 of 1,424,871 | 0.0140% | 61.7 |
| Thursday-15-02-2018 | DoS-GoldenEye | 0.125330 | 0.9999 | 86 of 616,764 | 0.0139% | 23.3 |
| Thursday-15-02-2018 | DoS-Slowloris | 0.749849 | 0.8648 | 143 of 616,764 | 0.0232% | 38.7 |
| Thursday-01-03-2018 | Infiltration | 0.792620 | 0.5557 | 101 of 1,778,131 | 0.0057% | 31.0 |

Both populations pooled; the README gives the early ones alone. Infiltration's event recall at this budget is 0.56, but
its alerting hosts carry 14,549 of its 14,586 attack events.

To see the whole trade-off for one day, or to commit another budget:

```bash
uv run python -m models.evaluation.thresholds --scores <run>/detector/scores_<day>.pt            # every budget's cost
uv run python -m models.evaluation.thresholds --scores <run>/detector/scores_<day>.pt \
    --budgets 1e-4 --recall-floor 0 --write <run>/detector/head_<day>.pt                        # commit 0.01%
uv run python -m models.evaluation.thresholds --scores <run>/detector/scores_<day>.pt \
    --recall-floor 0.995 --write <run>/detector/head_<day>.pt                                   # the cheapest point keeping recall
```

A threshold belongs to one trained model: after retraining it must be committed again (the training script does it).
