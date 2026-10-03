# `tools` — scripts run by hand

Nothing here runs in deployment: serving is `models/serving`, and the reported metrics come from `models/evaluation`.

```
tools/
  train_all.sh   trains every stage in order (docs/training.md)
  promote.py     copies a finished run's best models into artifacts/current
  dataset/       preparing the raw dataset archives
  measure/       answering one question about a trained model
  publish/       staging models and data for Hugging Face
  live/          StreamMeter.java (the lag service's flow meter) and stream_check.py (its equivalence check),
                 detect_check.py (the live detector against training), pcap_from_packets.py (captures rebuilt from a day)
  setup.sh                once after cloning: uv sync, CICFlowMeter, the published model (artifacts/current points at it),
                          and the dataset if wanted (asks which set and days, or --dataset none|processed|model|both)
  setup_cicflowmeter.sh   fetches (git submodule, pinned), patches and builds tools/CICFlowMeter; setup.sh runs it
  run_windows.ps1         starts live capture, detection, the lag forecast and the dashboard on Windows
  ../start-netwatch.ps1    one-command Windows bootstrap and interactive CLI (no dashboard/frontend)
  ../start-netwatch.sh     Linux/macOS bootstrap and interactive CLI (no dashboard/frontend)
  repo/          repository checks
```

On Windows, the one-command CLI setup/start is:

```powershell
.\start-netwatch.cmd                       # or: powershell -ExecutionPolicy Bypass -File .\start-netwatch.ps1
.\start-netwatch.cmd -Interface 'Ethernet' # select a different capture interface
.\start-netwatch.cmd -SkipSetup            # subsequent starts without dependency sync
.\start-netwatch.cmd -Device cpu          # explicit CPU override (default is CUDA)
```

It installs missing tools using winget, syncs the Python environment, builds CICFlowMeter,
downloads the published model only if `artifacts/current` is absent, builds the Go CLI,
starts capture plus both model services, then opens the interactive `netwatch>` prompt.
It does not download the training dataset or start the frontend or dashboard. Wireshark's
installer must be completed interactively so that Npcap is installed for live capture.
The CLI can be left with `exit`; the model services continue in the background.

Model serving defaults to CUDA. `uv sync --frozen` installs CUDA-enabled PyTorch
on Windows and Linux from the official PyTorch CUDA 13.0 index. An NVIDIA GPU
and compatible driver are required. Startup checks a real CUDA operation and
prints `Detection: Running in CUDA` and `World model: Running in CUDA` in the
service logs; the CLI's `model` output also reports the actual service device.
An unavailable GPU produces a clear error; select CPU explicitly when needed.

On Linux (Debian/Ubuntu, Fedora/RHEL, or Arch) and macOS, use the Unix launcher
as a normal user, not with `sudo`:

```bash
bash ./start-netwatch.sh                         # chooses the default-route interface
bash ./start-netwatch.sh --interface eth0        # explicit interface (see: tshark -D)
bash ./start-netwatch.sh --skip-setup            # later starts without dependency sync
bash ./start-netwatch.sh --device cpu            # CPU machines and macOS
```

It installs missing system tools through apt, dnf, pacman, or Homebrew, installs
JDK 8 and uv if needed, then performs the same model/CICFlowMeter/CLI setup as
the Windows launcher. Its service logs and PID files are in `artifacts/runtime/`.
Packet capture requires permission to use `dumpcap`; on Linux, configure the
Wireshark capture group/capabilities and re-login if necessary. On macOS,
install Wireshark's ChmodBPF helper if capture devices are unavailable. The
launcher reports capture-permission failures rather than running the whole
model pipeline as root.

The older setup/dashboard workflow remains available. After installing uv, Java 8,
Wireshark and Npcap, run `tools/setup.sh --dataset none` with Git Bash. From PowerShell:

```powershell
.\tools\run_windows.ps1                 # starts all four services, reusing existing processes
.\tools\run_windows.ps1 -Status         # checks capture, detection and forecasting
.\tools\run_windows.ps1 -Restart        # apply updated service/dashboard code after calibration completes
```

The dashboard is at `http://127.0.0.1:8787`. The default interface is the active default-route adapter (LAN when it carries the route, otherwise Wi-Fi). Capture and both model services pin that adapter when started. After switching adapters, rerun the launcher to restart this checkout's managed services together. The System tab shows both the pinned capture interface and current active route, and warns if they differ. Per-interface capture and four-hour threshold-calibration files stay separate; existing Wi-Fi calibration files are retained.
use `-Interface 'Ethernet'` to select another adapter. The published v1.0.0 model
uses the lag forecast, which requires more than four minutes of capture to warm
up. Detection starts immediately. Logs and the capture ring are kept under
`artifacts/runtime/`.

## `dataset/`

| file | role |
|---|---|
| `extract_zip.py` | extracts a large archive without filling memory, and can be stopped and resumed: each file is written to `<name>.part`, its CRC-32 checked while writing, and renamed only when complete |
| `verify_extract.py` | reads every extracted file and compares it with the CRC-32 in the archive, naming any file that is truncated, missing or altered |

Needed when adding dataset days.

## `measure/`

| file | question |
|---|---|
| `baseline.py` | how does a logistic-regression baseline compare, on the same rows? |
| `campaign_coverage.py` | at a given threshold, are whole campaigns missed, or only scattered flows inside campaigns that are caught? |
| `lead_ceiling_days.py` | how much warning does each day contain before any model — from the ground truth alone |
| `supervised_economics.py` | the detector in operational terms: alerts and incidents per hour |
| `forecast_lead.py` | are a trained world model's predicted links still in the future when a service with a given lag serves them? |
| `world_model_accuracy.py` | the world model's accuracy on its two training tasks: ranking top-1 / hit@3 / MRR among the quiz's candidates, next-event AUC |
| `forecast_beam.py` | keeping the top 1-3 hosts at every rollout step: is the attacker's real next victim on the list, and are the path probabilities calibrated? |
| `forecast_candidates.py` | the attacker's next new victim ranked by the world model over the served pool, all hosts, a retrieved pool and an address prior, against recency and popularity |
| `average_checkpoints.py` | one world model averaged over several saved epochs of a run, to compare with the single best epoch |

`baseline.py` must receive the same `--events` and `--family` as whatever it is compared with, or the positive rate
differs and not even PR-AUC is comparable. To choose the detector's operating point, use
`python -m models.evaluation.thresholds`.

## `publish/`

| file | role |
|---|---|
| `huggingface.py` | stages `artifacts/huggingface/model/` and `artifacts/huggingface/dataset/` from `artifacts/current` (or `--bundle <run>`), with the cards Hugging Face shows, and prints the upload command; staging is separate from uploading so the contents can be checked first |
| `to_safetensors.py` | converts a checkpoint to safetensors plus a JSON config after checking every tensor is bit-identical; `--to-pt` converts back. Called by `huggingface.py --what model` |
| `download.py` | downloads a published model into `artifacts/huggingface/download/<repo>/` and rebuilds it as servable `.pt` files with a `serving.json`; with `--dataset`, the chosen sets (`--sets processed model`) and days (`--days`) of the dataset |

```bash
uv run python tools/publish/huggingface.py --what model   --user <account> --detector-day <day> --dry-run
uv run python tools/publish/huggingface.py --what dataset --user <account>
uv run --with huggingface_hub python tools/publish/download.py --repo kaustuk000/netwatch-flow-cascade
```

Full instructions: [docs/publishing.md](../docs/publishing.md). **The dataset is not MIT**: CSE-CIC-IDS2018 has its own
terms, and the event tables, embeddings and latents are derived from it, so the dataset card is gated.

## `repo/`

| file | role |
|---|---|
| `verify_contracts.py` | checks that the modules, functions and settings the pipeline relies on exist; run by CI on every push |
| `verify_docs.py` | checks that every published document's links, repository paths, `python -m` commands and their options exist |
| `render_field_reference.py` | regenerates field tables for internal reference documents; does nothing when they are absent |

Every script takes `--help` and runs through the project environment, for example
`uv run python -m tools.repo.verify_contracts`.
