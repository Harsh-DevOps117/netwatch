"""At the 99%-recall threshold, are whole campaigns missed, or only scattered flows inside campaigns already caught?

Run: uv run python tools/measure/campaign_coverage.py --day Friday-02-03-2018 --family Bot --events 3000000 \
         --context-encoder data/model_cache/context/f_norec_s0/best.pt

The detection arm offers two very different operating points: ~100% of attack EVENTS for 275-374 false alarms
(385-523/hour, too noisy for a person), or 99% for 0-2 false alarms (under 3/hour, comfortably operator-grade). The
choice turns on what the missing 1% is. A campaign produces many flows, so missing 1% of events plausibly means missing
0% of campaigns - but that is an assumption, and this measures it.

A campaign here is a maximal run of attack events on one attacking host separated by at least `--quiet` non-attack
events, which is the stricter definition the onset audit showed is needed: the default K=1 definition counts a two-second
resumption after a benign blip as a new campaign, and on Bot that inflates 11 real campaigns into 1,565.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from models.flow_encoder.metrics import pr_threshold
from models.detector.features import load_features
from models.detector.model import class_scores, family_codes, train_head


def campaigns(host: np.ndarray, attack: np.ndarray, quiet: int) -> np.ndarray:
    """Label each attack event with its campaign id; -1 for non-attack events.

    Input:  host per event, attack flag per event, how many non-attack events on the host end a campaign
    Output: (N,) int64 campaign id, -1 where the event is not an attack

    Walking in host-major, stream order: an attack opens a new campaign when at least `quiet` non-attack events on that
    host have passed since the previous attack, or when the host has not attacked before.
    """
    order = np.lexsort((np.arange(len(host)), host))
    out = np.full(len(host), -1, np.int64)
    nxt, since, current, prev_host = 0, 0, -1, None
    for i in order:
        if host[i] != prev_host:
            prev_host, since, current = host[i], quiet, -1
        if attack[i]:
            if current < 0 or since >= quiet:
                current, nxt = nxt, nxt + 1
            out[i], since = current, 0
        else:
            since += 1
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--day", default="Friday-02-03-2018")
    parser.add_argument("--family", default="Bot")
    parser.add_argument("--events", type=int, default=3_000_000)
    parser.add_argument("--context-encoder", type=Path, default=None)
    parser.add_argument("--quiet", type=int, default=20, help="non-attack events on a host that end a campaign")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/results/campaign_coverage.csv"))
    args = parser.parse_args(argv)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    data, name = load_features(args.day, args.context_encoder, device, args.events, args.family)
    x = data["h"]
    code, families = family_codes(data["label"])
    target = families.index(args.family) + 1
    split = data["split"]
    attack = data["label"] == args.family
    host = data["sender"].astype(np.int64)

    rng = np.random.default_rng(args.seed)
    train_rows = np.flatnonzero(split == 0)
    rng.shuffle(train_rows)
    cut = int(0.8 * len(train_rows))
    fit_rows = train_rows[:cut]
    calib = np.zeros(len(attack), bool)
    calib[np.r_[train_rows[cut:], np.flatnonzero(split == 1)]] = True
    test = split == 2

    head, mean, std = train_head(x[fit_rows], code[fit_rows], len(families) + 1, device=device, seed=args.seed)
    score = class_scores(head, mean, std, x, device=device)[:, target]

    ids = campaigns(host, attack, args.quiet)
    rows = []
    for label, threshold in (("0.1% budget", float(np.quantile(score[calib & ~attack], 0.999))),
                             ("1% budget", float(np.quantile(score[calib & ~attack], 0.99))),
                             ("99% recall", pr_threshold(score[calib], attack[calib], min_precision=None)[0])):
        # the 99%-recall threshold: the highest cut whose recall on calibration rows is still at least 0.99
        if label == "99% recall":
            order = np.argsort(-score[calib])
            s_sorted = score[calib][order]
            hit = np.cumsum(attack[calib][order]) / max(attack[calib].sum(), 1)
            at = int(np.searchsorted(hit, 0.99))
            threshold = float(s_sorted[min(at, len(s_sorted) - 1)])
        alert = (score >= threshold) & test
        tp, fp = int((alert & attack).sum()), int((alert & ~attack).sum())
        positives = int((test & attack).sum())
        test_ids = np.unique(ids[test & attack])
        covered = np.unique(ids[alert & attack])
        missed = np.setdiff1d(test_ids, covered)
        sizes = np.array([int((ids == c).sum()) for c in missed]) if len(missed) else np.array([], int)
        rows.append({"operating_point": label, "threshold": threshold,
                     "event_recall": tp / max(positives, 1), "false_alarms": fp,
                     "campaigns_in_test": len(test_ids), "campaigns_covered": len(covered),
                     "campaigns_missed": len(missed),
                     "campaign_recall": len(covered) / max(len(test_ids), 1),
                     "missed_campaign_sizes": ";".join(map(str, sizes[:20]))})
    table = pd.DataFrame(rows)
    table.insert(0, "day", args.day)
    table.insert(1, "family", args.family)
    table["quiet"] = args.quiet
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(args.out, index=False)
    pd.set_option("display.width", 220)
    print(f"{args.day} / {args.family} | campaigns need {args.quiet} quiet events to end | "
          f"{int((test & attack).sum()):,} attack events in test\n")
    print(table.drop(columns=["day", "family", "quiet"]).to_string(index=False, float_format=lambda v: f"{v:,.4f}"))
    print("\n-> if campaigns_missed is 0 at 99% recall, the cheap operating point costs nothing that matters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
