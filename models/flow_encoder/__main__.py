"""Block 7: train the per-flow autoencoder on benign flows, score a held-out day, optionally export embeddings."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

# cuBLAS reads this when CUDA initialises, so it must be set before torch is
# imported. Without it the packet branch is not bit-reproducible.
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch

from ingest.build.events import DEFAULT_K_PACKETS
from ingest.sources.flows import BENIGN_LABEL
from models.flow_encoder.encoder import PACKET_ENCODERS, VARIANT, FlowAutoencoder
from models.flow_encoder.export import export_latents
from models.flow_encoder.metrics import auroc, average_precision_tied, probe
from models.training import Telemetry, add_training_arguments
from models.flow_encoder.train import embed, train_autoencoder
from models.data.inputs import cached_inputs, normalise, read_events
from models.data.prefix import COMPLETED, DEFAULT_BUDGET_MS, EARLY, SIDES, prepare
from models.data.splits import SPLIT_NAMES, observed_windows, segment_split

BENIGN = BENIGN_LABEL["Label"]


def _sample(rows: np.ndarray, n: int, rng: np.random.Generator) -> np.ndarray:
    """Uniform sample without replacement.

    Input:  candidate rows, sample size, generator
    Output: sorted sampled rows
    """
    return np.sort(rng.choice(rows, size=min(n, len(rows)), replace=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--fit-day", nargs="+", default=["Friday-16-02-2018"],
        help="one or more days to fit on; leave-one-day-out is --fit-day A B --cross-day C",
    )
    parser.add_argument("--cross-day", default="Friday-02-03-2018", help="the held-out day to score")
    parser.add_argument(
        "--side", choices=SIDES, default="responder",
        help="responder: the response side only (anomaly arm); initiator: the request side only (Block 8 side "
             "arm); split: both sides kept apart (classifier and Block 8 input); both: one arrival chain, for the "
             "direction-aware reader",
    )
    parser.add_argument(
        "--packet-encoder", choices=PACKET_ENCODERS, default="gnn",
        help="gnn, or dir_gnn: the direction-aware reader of the anomaly arm (use with --side both)",
    )
    parser.add_argument("--budget-ms", type=float, default=DEFAULT_BUDGET_MS, help="observation budget")
    parser.add_argument("--events-root", type=Path, default=Path("data/events"))
    parser.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    parser.add_argument(
        "--sample", type=int, default=400_000,
        help="events drawn from each fit day's train split and from the cross day; val and test get a quarter each",
    )
    parser.add_argument(
        "--cross-attacks-all", action="store_true",
        help="score every attack event of the cross day plus a benign sample of --sample rows",
    )
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument(
        "--patience", type=int, default=5,
        help="stop when benign validation error has not improved for this many epochs; 0 disables",
    )
    parser.add_argument("--batch-size", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=0, help="seed for the event sample")
    parser.add_argument(
        "--model-seed", type=int, default=None, help="seed for weights and batch order; defaults to --seed",
    )
    parser.add_argument(
        "--cache-root", type=Path, default=None,
        help="directory holding built tensors; reused when the sampled event ids match",
    )
    parser.add_argument("--results-csv", type=Path, default=None, help="append the results table here")
    parser.add_argument(
        "--save-scores", type=Path, default=None,
        help="write each population's scores, embeddings, labels and event ids, and the model, here",
    )
    parser.add_argument(
        "--load-from", type=Path, default=None,
        help="a --save-scores directory: load the model saved there for this configuration instead of training",
    )
    parser.add_argument(
        "--export", type=Path, default=None,
        help="after training, stream whole days through the encoder and write <day>/flow_embeddings.parquet "
             "plus its manifest here: Block 7's handoff to Block 8",
    )
    parser.add_argument("--export-days", nargs="+", default=None, help="days to export (default: every fit day)")
    parser.add_argument("--export-limit", type=int, default=None, help="stop the export after this many events")
    add_training_arguments(parser, default_epochs=30)
    parser.add_argument("--readers", type=int, default=4, help="captures read concurrently")
    parser.add_argument("--workers", type=int, default=0, help="DataLoader worker processes")
    args = parser.parse_args(argv)
    if args.side == "split" and args.packet_encoder != "gnn":
        parser.error("--side split is built for --packet-encoder gnn only")
    torch.use_deterministic_algorithms(True, warn_only=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    rng = np.random.default_rng(args.seed)
    model_seed = args.seed if args.model_seed is None else args.model_seed

    print(f"fit {','.join(args.fit_day)} | cross-day {args.cross_day} | side {args.side} | {args.packet_encoder} "
          f"| budget {args.budget_ms:g} ms | {device}", flush=True)
    cache = (lambda day: args.cache_root / day if args.cache_root else None)
    days, splits, labels_per_day = [], [], []
    for day in args.fit_day:
        day_events = args.events_root / day
        timeline = read_events(day_events, columns=["t", "label"])
        windows = observed_windows(timeline, day)
        split = segment_split(timeline["t"].to_numpy(), windows)
        print(f"{day}: segmented split over {len(windows)} observed attack window(s)", flush=True)
        print(pd.crosstab(timeline["label"], split).rename(columns=SPLIT_NAMES).to_string(), flush=True)
        day_labels = timeline["label"].to_numpy()
        del timeline
        # Each fit day contributes the same sample, so no day dominates by being busy.
        picked = np.sort(np.concatenate([
            _sample(np.flatnonzero(split == s), n, rng)
            for s, n in ((0, args.sample), (1, args.sample // 4), (2, args.sample // 4))
        ]))
        days.append(cached_inputs(
            read_events(day_events, rows=picked), args.processed_root / day, DEFAULT_K_PACKETS, cache(day), args.readers,
        ))
        splits.append(split[picked])
        labels_per_day.append(day_labels[picked])
    fit = days[0] if len(days) == 1 else {key: np.concatenate([d[key] for d in days]) for key in days[0]}
    del days
    fit_split = np.concatenate(splits)
    fit_labels = np.concatenate(labels_per_day)
    cross_events = args.events_root / args.cross_day
    n_cross = pq.ParquetFile(cross_events / "events.parquet").metadata.num_rows
    cross_labels = read_events(cross_events, columns=["label"])["label"].to_numpy()
    if args.cross_attacks_all:
        # Keep every attack and subsample the benign majority, recording the rate so
        # precision can be corrected back to the day's true prevalence.
        is_attack = cross_labels != BENIGN
        benign_rows = np.flatnonzero(~is_attack)
        cross_pick = np.sort(np.concatenate([np.flatnonzero(is_attack), _sample(benign_rows, args.sample, rng)]))
        benign_rate = min(args.sample, len(benign_rows)) / len(benign_rows)
        del is_attack
    else:
        cross_pick = _sample(np.arange(n_cross), args.sample, rng)
        benign_rate = len(cross_pick) / n_cross
    cross_label = cross_labels[cross_pick].astype(str)
    del cross_labels
    cross = cached_inputs(
        read_events(cross_events, rows=cross_pick), args.processed_root / args.cross_day,
        DEFAULT_K_PACKETS, cache(args.cross_day), args.readers,
    )

    budget = args.budget_ms / 1000
    # One at a time, so the raw fit arrays are released before the cross day is prepared.
    fit = prepare(fit, budget, args.side)
    cross = prepare(cross, budget, args.side)
    for name, data in (("fit", fit), ("cross", cross)):
        counts = pd.Series(data["population"]).value_counts()
        print(f"{name} populations: " + ", ".join(f"{k} {v:,}" for k, v in counts.items())
              + f" | packets seen p50 {np.median(data['packets_seen']):.0f} | a_f {data['a'].shape[1]} columns", flush=True)

    train_rows = np.flatnonzero((fit_split == 0) & ~fit["attack"])
    val_rows = np.flatnonzero((fit_split == 1) & ~fit["attack"])
    # Test rows only: early stopping selects the model on validation, so scoring it too
    # would report a number its own rows helped choose.
    held = np.flatnonzero(fit_split == 2)
    probe_rows = np.flatnonzero(fit_split == 0)
    fit, stats = normalise(fit, rows=train_rows)
    cross, _ = normalise(cross, stats)
    cross_rows = np.arange(len(cross["attack"]))
    print(f"loaded fit {len(fit_split):,} ({len(train_rows):,} benign train, "
          f"{int(fit['attack'][held].sum()):,} attack held out) | "
          f"cross {len(cross_rows):,} ({int(cross['attack'].sum()):,} attack)", flush=True)

    torch.manual_seed(model_seed)
    model = FlowAutoencoder(VARIANT, k=DEFAULT_K_PACKETS, predict=True, packet_encoder=args.packet_encoder,
                            a_width=fit["a"].shape[1], split=args.side == "split").to(device)
    # "relu" stays in the name so models saved before the activation was fixed still load.
    stem = f"{'+'.join(args.fit_day)}__{args.cross_day}__{VARIANT}__{args.packet_encoder}__relu__s{model_seed}"
    if args.load_from:
        saved = torch.load(args.load_from / f"{stem}.pt", map_location=device, weights_only=False)
        # The tag was "block7-encoder-v1" before the stages were named; accept both so an existing checkpoint loads.
        if isinstance(saved, dict) and saved.get("format") in ("flow-encoder-v1", "block7-encoder-v1"):
            model.load_state_dict(saved["model"])
            # Re-scale with the stats the weights were fitted behind, not this invocation's sample.
            stats = saved["stats"]
            fit, _ = normalise(fit, stats)
            cross, _ = normalise(cross, stats)
            print(f"  loaded {args.load_from / f'{stem}.pt'} with its normalisation stats, training skipped",
                  flush=True)
        else:
            model.load_state_dict(saved)
            print(f"  loaded {args.load_from / f'{stem}.pt'} (pre-v1: NO saved stats, so the input scale is "
                  f"recomputed from this run's --sample/--seed and may differ from the fit)", flush=True)
        history = []
    else:
        board = Telemetry(args.tensorboard, args.run_name)
        history = train_autoencoder(
            model, fit, train_rows, val_rows, epochs=args.epochs, batch_size=args.batch_size,
            device=device, seed=model_seed, workers=args.workers, patience=args.patience,
            schedule=args.lr_schedule, board=board, resume=args.resume,
        )
        board.close()
    h_fit, err_fit = embed(model, fit, np.arange(len(fit_split)), device=device, workers=args.workers)
    h_cross, err_cross = embed(model, cross, cross_rows, device=device, workers=args.workers)

    for day in (args.export_days or args.fit_day) if args.export else ():
        print(f"exporting {day} latents to {args.export / day}", flush=True)
        started = time.perf_counter()
        manifest = export_latents(
            model, stats, day=day, events_root=args.events_root, processed_root=args.processed_root,
            out_dir=args.export / day, k=DEFAULT_K_PACKETS, budget_ms=args.budget_ms, side=args.side, device=device,
            readers=args.readers, limit=args.export_limit, model_seed=model_seed,
        )
        print(f"  wrote {manifest['n_events']:,} rows, dim {manifest['embedding_dim']}, "
              f"in {time.perf_counter() - started:.0f} s", flush=True)

    a_col = model.targets.index("a")
    results = []
    # The two observation populations are never pooled, or the completed half inflates a
    # number presented as early warning.
    for population in (EARLY, COMPLETED):
        in_fit, in_cross = fit["population"] == population, cross["population"] == population
        held_p = held[in_fit[held]]
        probe_p = probe_rows[in_fit[probe_rows]]
        cross_p = cross_rows[in_cross[cross_rows]]
        fit_benign = train_rows[in_fit[train_rows]]
        if not (len(held_p) and len(cross_p) and len(fit_benign)):
            print(f"  {population}: empty, skipped", flush=True)
            continue

        held_labels = fit_labels[held_p]
        cross_truth = cross["attack"][cross_p]
        if args.save_scores:
            args.save_scores.mkdir(parents=True, exist_ok=True)
            # The input normalisation stats travel WITH the weights. They were fitted on this run's train_rows, which
            # depend on --fit-day, --sample and --seed, so weights reloaded beside different stats silently produce
            # differently scaled embeddings -- and every block downstream reads those embeddings.
            torch.save({"format": "flow-encoder-v1", "model": model.state_dict(), "stats": stats,
                        "side": args.side, "packet_encoder": args.packet_encoder, "budget_ms": args.budget_ms,
                        "fit_days": list(args.fit_day), "sample": args.sample, "model_seed": model_seed},
                       args.save_scores / f"{stem}.pt")

        within, within_scores = probe(h_fit[probe_p], fit["attack"][probe_p], h_fit[held_p], fit["attack"][held_p],
                                      device=device, return_scores=True)
        # Per family on the fit days' test rows, for the classifier: AUROC and PR-AUC against benign, and
        # recall at a 1% benign false-positive rate read off these rows.
        held_benign = held_labels == BENIGN
        family = {}
        for name in sorted(set(held_labels) - {BENIGN}):
            is_family = held_labels == name
            keep = is_family | held_benign
            family[f"probe_auroc_within_{name}"] = auroc(within_scores[keep], is_family[keep])
            family[f"probe_ap_within_{name}"] = average_precision_tied(within_scores[keep], is_family[keep])
            cut = np.quantile(within_scores[held_benign], 0.99) if held_benign.any() else np.inf
            family[f"probe_recall_fpr1_within_{name}"] = float((within_scores[is_family] > cut).mean())
            family[f"n_within_{name}"] = int(is_family.sum())
        results.append({
            "fit_days": "+".join(args.fit_day), "cross_day": args.cross_day,
            "side": args.side, "packet_encoder": args.packet_encoder, "budget_ms": args.budget_ms,
            "model_seed": model_seed, "population": population, "epochs_run": len(history),
            "load_from": str(args.load_from or ""), "train_rows": len(train_rows),
            "n_held": len(held_p), "n_cross": len(cross_p), "benign_rate": benign_rate,
            # benign_rate corrects precision only under stratified sampling; uniform samples are unbiased.
            "cross_sampling": "stratified" if args.cross_attacks_all else "uniform",
            "probe_within_fpr": within["fpr"], "probe_within_auroc": within["auroc"],
            "probe_within_ap_tied": within["ap_tied"], "probe_within_recall": within["recall"],
            **family,
        })
        print("  " + "  ".join(f"{k} {v:.4f}" if isinstance(v, float) else f"{k} {v}" for k, v in results[-1].items()), flush=True)

    table = pd.DataFrame(results)
    if args.results_csv:
        # Runs differ in their columns -- each day names its own families -- so append by union.
        args.results_csv.parent.mkdir(parents=True, exist_ok=True)
        if args.results_csv.exists():
            table = pd.concat([pd.read_csv(args.results_csv), table], ignore_index=True)
        table.to_csv(args.results_csv, index=False)
        print(f"\nresults appended to {args.results_csv}", flush=True)
    print("\n" + table.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
