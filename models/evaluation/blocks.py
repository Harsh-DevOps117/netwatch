"""Per-stage evaluation: judge each block on its own objective, not only by what comes out of the end.

An end-to-end number says the cascade works or does not. It does not say **which stage** moved when it changes, and in
a frozen cascade that matters more than usual: a stage is fitted once and every later stage inherits whatever it
produced. A drop in detection recall can come from the flow encoder reconstructing worse, the context encoder losing
link structure, or the compressor throwing away the part of the context that mattered, and the end-to-end metric cannot
tell those apart.

Each stage is therefore scored on the objective it was actually trained against, plus the one property the next stage
depends on:

| stage | trained against | also reported |
|---|---|---|
| flow encoder | reconstructing a benign flow | how separable benign and attack are in its embedding |
| context encoder | link prediction on benign events | how much of the context is neighbourhood rather than the event |
| compressor | rebuilding the context vector | how much of the context variance 32 dimensions retain |
| detector | naming the family | ranking quality, calibration, and the alert economics |

Reconstruction error is reported on **benign rows**, because that is what the stage was fitted on; a rising benign
error means the stage has drifted from what it modelled, which is the failure that silently degrades everything after
it.
"""
from __future__ import annotations

import torch


def reconstruction_quality(error: torch.Tensor, attack: torch.Tensor) -> dict:
    """How well a stage rebuilds what it was given, and whether attacks stand out in that error.

    Input:  per-event reconstruction error, per-event attack flag
    Output: dict with benign and attack error, their ratio, and the separation

    The ratio is the useful number: a stage fitted on benign rows should rebuild benign traffic better than attacks, so
    a ratio at or below 1 means the error carries no signal, whatever its absolute value.
    """
    error = torch.as_tensor(error, dtype=torch.float64).flatten()
    attack = torch.as_tensor(attack, dtype=torch.bool).flatten()
    benign = ~attack
    if not benign.any() or not attack.any():
        return {"benign_error": float(error[benign].mean()) if benign.any() else float("nan"),
                "attack_error": float(error[attack].mean()) if attack.any() else float("nan"),
                "ratio": float("nan"), "separation": float("nan")}
    b, a = error[benign], error[attack]
    spread = torch.sqrt(0.5 * (b.var() + a.var())).clamp(min=1e-12)
    return {"benign_error": float(b.mean()), "attack_error": float(a.mean()),
            "ratio": float(a.mean() / b.mean().clamp(min=1e-12)),
            # Standardised mean difference: how far apart the two error distributions are in their own units.
            "separation": float((a.mean() - b.mean()) / spread)}


def representation_quality(h: torch.Tensor, attack: torch.Tensor, sample: int = 200_000,
                           seed: int = 0) -> dict:
    """How much the next stage has to work with: spread, collapse, and linear separability.

    Input:  the stage's output (N, W), per-event attack flag, rows to sample, seed
    Output: dict with the width, the effective rank, and a single-direction separability

    **Effective rank** is the one to watch. A stage can have a healthy loss while collapsing its output into a handful
    of directions, at which point the next stage is fitted on far less information than its width suggests. Computed as
    the exponential of the entropy of the normalised singular values: a width-32 output using every direction equally
    scores 32, one that has collapsed to a line scores 1.

    Separability is deliberately the crudest possible probe -- the standardised mean difference along the single best
    direction -- because anything stronger measures the probe rather than the representation.
    """
    h = torch.as_tensor(h, dtype=torch.float32)
    attack = torch.as_tensor(attack, dtype=torch.bool).flatten()
    if len(h) > sample:
        pick = torch.randperm(len(h), generator=torch.Generator().manual_seed(seed))[:sample]
        h, attack = h[pick], attack[pick]
    centred = (h - h.mean(0)).double()
    values = torch.linalg.svdvals(centred)
    share = (values / values.sum().clamp(min=1e-12)).clamp(min=1e-12)
    effective_rank = float(torch.exp(-(share * share.log()).sum()))
    out = {"width": int(h.shape[1]), "effective_rank": effective_rank,
           "rank_fraction": effective_rank / max(h.shape[1], 1)}
    if attack.any() and (~attack).any():
        a, b = centred[attack], centred[~attack]
        direction = (a.mean(0) - b.mean(0))
        norm = direction.norm().clamp(min=1e-12)
        projected_a, projected_b = a @ (direction / norm), b @ (direction / norm)
        spread = torch.sqrt(0.5 * (projected_a.var() + projected_b.var())).clamp(min=1e-12)
        out["separability"] = float((projected_a.mean() - projected_b.mean()).abs() / spread)
    else:
        out["separability"] = float("nan")
    return out


def demo() -> None:
    """Self-check on constructed cases, so each number's direction is pinned."""
    torch.manual_seed(0)
    n = 4_000
    attack = torch.zeros(n, dtype=torch.bool)
    attack[:200] = True

    # a stage fitted on benign rows rebuilds them better: ratio above 1, separation positive
    error = torch.rand(n) * 0.1
    error[attack] += 1.0
    good = reconstruction_quality(error, attack)
    assert good["ratio"] > 1 and good["separation"] > 0, good
    # error carrying no signal: ratio about 1, separation about 0
    flat = reconstruction_quality(torch.rand(n), attack)
    assert 0.8 < flat["ratio"] < 1.2 and abs(flat["separation"]) < 0.3, flat
    # one class absent is reported, not divided by zero
    lonely = reconstruction_quality(torch.rand(n), torch.zeros(n, dtype=torch.bool))
    assert lonely["ratio"] != lonely["ratio"], lonely          # nan

    # a representation using every direction scores near its width; a collapsed one scores near 1
    full = representation_quality(torch.randn(n, 16), attack)
    assert full["effective_rank"] > 12, full
    line = torch.randn(n, 1) @ torch.randn(1, 16)
    collapsed = representation_quality(line, attack)
    assert collapsed["effective_rank"] < 1.5, collapsed
    assert collapsed["rank_fraction"] < full["rank_fraction"]

    # separability responds to a planted difference
    planted = torch.randn(n, 8)
    planted[attack] += 5.0
    assert representation_quality(planted, attack)["separability"] > 2
    assert representation_quality(torch.randn(n, 8), attack)["separability"] < 1
    print("demo ok")



def score_flow_encoder(day: str, embeddings_root: "Path | str" = "data/flow_embeddings",
                       events_root: "Path | str" = "data/events", side: str = "split") -> dict:
    """The flow encoder's own numbers for one day, read from its export.

    Input:  day, the embeddings root, the events root, which side was exported
    Output: dict of stage metrics, or a reason it could not be scored
    """
    from pathlib import Path

    import pyarrow.parquet as pq

    export = Path(embeddings_root) / side / day / "flow_embeddings.parquet"
    if not export.is_file():
        return {"stage": "flow_encoder", "day": day, "skipped": f"no export at {export}"}
    table = pq.read_table(export, columns=["h", "recon_error"] if "recon_error" in
                          pq.read_schema(export).names else ["h"])
    # The export is one row per event in event order, including events without packets, so the labels are read
    # unfiltered. Aligning them any other way silently pairs an embedding with another event's label.
    events = pq.read_table(Path(events_root) / day / "events.parquet", columns=["label"]).to_pandas()
    from ingest.sources.flows import BENIGN_LABEL
    attack = torch.as_tensor(events["label"].to_numpy(str) != BENIGN_LABEL["Label"])
    h = table["h"].combine_chunks()
    h = torch.as_tensor(h.flatten().to_numpy().reshape(len(h), -1).copy())
    if len(h) != len(attack):
        return {"stage": "flow_encoder", "day": day,
                "skipped": f"export has {len(h):,} rows, the event stream has {len(attack):,}; "
                           f"they must line up row for row"}
    out = {"stage": "flow_encoder", "day": day, "events": len(h), **representation_quality(h, attack)}
    if "recon_error" in table.column_names:
        column = table["recon_error"].combine_chunks()
        error = torch.as_tensor(column.flatten().to_numpy().reshape(len(column), -1).copy())
        # The flow encoder rebuilds several targets and reports one error per target, unstandardised. The export's
        # manifest warns against combining them without standardising first, so each is reported on its own.
        import json
        manifest = export.with_name("flow_embeddings_manifest.json")
        names = (json.loads(manifest.read_text()).get("recon_targets")
                 if manifest.is_file() else None) or [str(i) for i in range(error.shape[1])]
        if error.shape[1] == 1:
            out.update(reconstruction_quality(error[:, 0], attack))
        else:
            for index, name in enumerate(names[: error.shape[1]]):
                for key, value in reconstruction_quality(error[:, index], attack).items():
                    out[f"{name}_{key}"] = value
    return out


def score_compressor(latents_dir: "Path | str") -> dict:
    """The compressor's own numbers, read from one day of its latents export.

    Input:  a directory holding event_latents.parquet
    Output: dict of stage metrics, or a reason it could not be scored
    """
    from pathlib import Path

    import pyarrow.parquet as pq

    export = Path(latents_dir) / "event_latents.parquet"
    if not export.is_file():
        return {"stage": "compressor", "skipped": f"no export at {export}"}
    table = pq.read_table(export, columns=["z", "recon_error", "attack"])
    z = table["z"].combine_chunks()
    z = torch.as_tensor(z.flatten().to_numpy().reshape(len(z), -1).copy())
    attack = torch.as_tensor(table["attack"].to_numpy(zero_copy_only=False).copy())
    error = torch.as_tensor(table["recon_error"].to_numpy(zero_copy_only=False).copy())
    return {"stage": "compressor", "day": Path(latents_dir).name, "events": len(z),
            **representation_quality(z, attack), **reconstruction_quality(error, attack)}


def main(argv: "list[str] | None" = None) -> int:
    """Report every stage that has an artefact on disk, one row each."""
    import argparse
    from pathlib import Path

    import pandas as pd

    parser = argparse.ArgumentParser(description="Per-stage evaluation: judge each block on its own objective.")
    parser.add_argument("--days", nargs="*", default=None, help="default: every ingested day")
    parser.add_argument("--embeddings-root", type=Path, default=Path("data/flow_embeddings"))
    parser.add_argument("--events-root", type=Path, default=Path("data/events"))
    parser.add_argument("--latents", type=Path, nargs="*", default=None,
                        help="one or more day directories holding event_latents.parquet")
    parser.add_argument("--side", default="split")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args(argv)
    if args.demo:
        demo()
        return 0

    from models.data.splits import available_days

    rows = [score_flow_encoder(day, args.embeddings_root, args.events_root, args.side)
            for day in (args.days or available_days(args.events_root))]
    rows += [score_compressor(path) for path in (args.latents or [])]
    table = pd.DataFrame(rows)
    pd.set_option("display.width", 220)
    print("\nPER-STAGE EVALUATION — each block against its own objective\n")
    print(table.to_string(index=False, float_format=lambda v: f"{v:,.4g}"))
    print("\n  effective_rank: directions actually used out of `width`. A collapsed representation starves the next"
          "\n                  stage however healthy its loss looks."
          "\n  ratio:          attack error over benign error. At or below 1 the reconstruction carries no signal.")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        table.to_csv(args.out, index=False)
        print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
