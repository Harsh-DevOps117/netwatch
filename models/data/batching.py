"""Batching: the event tensors as a PyTorch dataset, the samplers over it and the hop to the compute device."""

from __future__ import annotations

import numpy as np
import torch
from torch.utils.data import BatchSampler, DataLoader, Dataset, RandomSampler, SequentialSampler

from models.data.inputs import FUTURE_FIELDS

TENSOR_FIELDS = ("a", "pkt", "dt", "n_pkt")


class FlowDataset(Dataset):
    """Serve model inputs as tensors, a whole batch per fetch.

    Input:  normalised arrays from models.data.inputs, optional subset of their rows
    Output: dataset of len(rows) items; a fetch returns x, a, pkt, dt, n_pkt plus
            attack and the row each item came from

    __getitems__ takes the batch's indices in one call, so a batch costs one
    numpy gather instead of one Python call per flow.
    """

    def __init__(self, data: dict, rows: np.ndarray | None = None):
        self.data = data
        self.rows = np.arange(len(data["attack"])) if rows is None else np.asarray(rows)

    def __len__(self) -> int:
        return len(self.rows)

    def batch(self, indices) -> dict:
        """Fetch these dataset positions as one batch.

        Input:  dataset positions
        Output: dict of tensors x, a, pkt, dt, n_pkt, attack, row
        """
        rows = self.rows[indices]
        names = [n for n in (*TENSOR_FIELDS, *FUTURE_FIELDS) if n in self.data]
        batch = {name: torch.from_numpy(np.asarray(self.data[name][rows])) for name in names}
        batch["attack"] = torch.from_numpy(np.asarray(self.data["attack"][rows]))
        batch["row"] = torch.from_numpy(rows)
        return batch

    def __getitem__(self, index: int) -> dict:
        return self.batch([index])

    __getitems__ = batch

def flow_loader(
    dataset: FlowDataset, *, batch_size: int = 1024, shuffle: bool = False,
    workers: int = 0, seed: int = 0, pin: bool = False,
) -> DataLoader:
    """Iterate a FlowDataset in batches.

    Input:  dataset, batch size, shuffle, worker processes, seed, pinned memory
    Output: DataLoader yielding the dataset's own batch dicts, in row order when
            not shuffled
    """
    if shuffle:
        sampler = RandomSampler(dataset, generator=torch.Generator().manual_seed(seed))
    else:
        sampler = SequentialSampler(dataset)
    return DataLoader(
        dataset,
        batch_sampler=BatchSampler(sampler, batch_size, drop_last=False),
        collate_fn=_identity,
        num_workers=workers,
        pin_memory=pin,
        persistent_workers=workers > 0,
    )


def _identity(batch: dict) -> dict:
    """Keep the batch the dataset already assembled.

    Input:  batch dict
    Output: the same dict
    """
    return batch


def to_device(batch: dict, device: str) -> dict:
    """Move a batch to the compute device.

    Input:  batch dict, device
    Output: dict of tensors on that device
    """
    return {name: value.to(device, non_blocking=True) for name, value in batch.items()}
