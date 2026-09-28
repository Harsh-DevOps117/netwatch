"""Block 7 model: packet-subgraph GNN fused with the flow's aggregates, with its reconstruction decoders."""

from __future__ import annotations

import math

import torch
import torch.nn.functional as F
from torch import nn
from torch_geometric.nn import GINEConv, HeteroConv, SAGEConv
from torch_geometric.utils import scatter

from ingest.build.events import AGG_COLUMNS, DEFAULT_K_PACKETS
from models.data.inputs import PACKET_FEATURES

CONTAIN = ("flow", "contain", "packet")
LINK = ("packet", "link", "packet")

# Edge kinds when directions are kept apart: next packet of the same side, and the reply --
# the next packet, when the side changes.
SPLIT_KINDS = ("same_side", "reply")

# Direction-aware arrival chain: each link i -> i+1 is either within one side or a change of
# direction, and the gap it carries means something different in each case.
DIR_KINDS = ("same_side", "flip")
DIRECTION = PACKET_FEATURES.index("direction")

PACKET_ENCODERS = ("gnn", "dir_gnn")

# The only input variant: a_f and the packet subgraph as seen by t_obs. x_f does not exist online.
VARIANT = "a_pkt"


def split_links(n_pkt: torch.Tensor, pkt: torch.Tensor, dt: torch.Tensor, owner: torch.Tensor,
                slot: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Packet edges that keep the two directions apart.

    Input:  packets per flow (B,), packet features (B, K, F), gaps (B, K), owner and slot of
            every packet node from packet_graph
    Output: link (2, E) node pairs, kind (E,) 0 = next packet of the same side, 1 = reply,
            seconds (E,) between the two packets

    Direction is read as the sign of the direction column: before normalisation it is 0 or
    1, after it the responder rows sit above the column mean and the initiator rows below.
    """
    k = dt.shape[1]
    valid = torch.arange(k, device=dt.device) < n_pkt[:, None]
    responder = pkt[..., DIRECTION] > 0
    node = torch.full(valid.shape, -1, dtype=torch.long, device=dt.device)
    node[owner, slot] = torch.arange(len(owner), device=dt.device)
    pairs, kinds = [], []
    for mask in (valid & ~responder, valid & responder):
        flow, at = mask.nonzero(as_tuple=True)          # row-major: by flow, slots ascending
        same = flow[1:] == flow[:-1]
        pairs.append(torch.stack([node[flow[:-1][same], at[:-1][same]], node[flow[1:][same], at[1:][same]]]))
        kinds.append(torch.zeros(int(same.sum()), dtype=torch.long, device=dt.device))
    turn = valid[:, 1:] & (responder[:, 1:] != responder[:, :-1])
    flow, at = turn.nonzero(as_tuple=True)
    pairs.append(torch.stack([node[flow, at], node[flow, at + 1]]))
    kinds.append(torch.ones(len(flow), dtype=torch.long, device=dt.device))
    link, kind = torch.cat(pairs, 1), torch.cat(kinds)
    offset = torch.cumsum(dt, 1)
    seconds = offset[owner[link[1]], slot[link[1]]] - offset[owner[link[0]], slot[link[0]]]
    return link, kind, seconds.clamp(min=0)


def slog(x: torch.Tensor) -> torch.Tensor:
    """Signed log, for a feature that spans orders of magnitude either side of zero.

    Input:  any tensor
    Output: sign(x) * log(1 + |x|), same shape
    """
    return torch.sign(x) * torch.log1p(x.abs())


def mlp(d_in: int, d_out: int, hidden: int = 128) -> nn.Sequential:
    """The encoder head and decoder shape.

    Input:  input width, output width, hidden width
    Output: nn.Sequential Linear -> ReLU -> Linear
    """
    return nn.Sequential(nn.Linear(d_in, hidden), nn.ReLU(), nn.Linear(hidden, d_out))


def direction_flips(pkt: torch.Tensor, owner: torch.Tensor, slot: torch.Tensor, link: torch.Tensor) -> torch.Tensor:
    """Whether each arrival-order link changes direction.

    Input:  packet features (B, K, F), owner and slot of every packet node, link (2, E) from packet_graph
    Output: (E,) bool, True where the two packets were sent by different sides
    """
    responder = pkt[..., DIRECTION] > 0
    return responder[owner[link[0]], slot[link[0]]] != responder[owner[link[1]], slot[link[1]]]


class TimeEncoder(nn.Module):
    """Bochner encoding of a within-flow packet gap, Phi(log(1 + dt)) with learnable frequencies.

    Input:  gaps in seconds, shape (E,)
    Output: (E, d) encoding
    """

    def __init__(self, d: int = 16):
        super().__init__()
        self.omega = nn.Parameter(torch.logspace(-1, 1, d // 2))

    def forward(self, dt: torch.Tensor) -> torch.Tensor:
        phase = torch.log1p(dt).unsqueeze(-1) * self.omega
        return torch.cat([phase.cos(), phase.sin()], -1) / math.sqrt(len(self.omega))


def packet_graph(n_pkt: torch.Tensor, k: int) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Packet nodes and link edges of every flow subgraph in a batch.

    Input:  packets per flow (B,), K
    Output: owner (P,) flow of each packet node, slot (P,) its position in that flow,
            link (2, E) packet node pairs i -> i+1 inside one flow
    """
    valid = torch.arange(k, device=n_pkt.device) < n_pkt[:, None]
    owner, slot = valid.nonzero(as_tuple=True)
    node = torch.full(valid.shape, -1, dtype=torch.long, device=n_pkt.device)
    node[owner, slot] = torch.arange(len(owner), device=n_pkt.device)
    flow, earlier = valid[:, 1:].nonzero(as_tuple=True)
    link = torch.stack([node[flow, earlier], node[flow, earlier + 1]])
    return owner, slot, link


class FlowEncoder(nn.Module):
    """Map one flow to h_f = MLP([a_f || z_pkt]).

    Input:  hidden width d, embedding width d_h, time width d_t, GNN layers, packet reader
            ("gnn", or "dir_gnn": direction-aware), aggregate width, split (directions kept apart)
    Output: module; forward(batch) returns (B, d_h)
    """

    def __init__(self, d: int = 64, d_h: int = 32, d_t: int = 16, layers: int = 2,
                 packet_encoder: str = "gnn", a_width: int = len(AGG_COLUMNS), split: bool = False):
        super().__init__()
        if packet_encoder not in PACKET_ENCODERS:
            raise ValueError(f"packet_encoder must be one of {PACKET_ENCODERS}")
        if split and packet_encoder != "gnn":
            raise ValueError("directions kept apart are built for the gnn packet reader only")
        self.packet_encoder, self.split = packet_encoder, split
        self.side = nn.Embedding(2, d) if split or packet_encoder == "dir_gnn" else None
        edge_extra = 0
        if split:
            edge_extra = len(SPLIT_KINDS)
        elif packet_encoder == "dir_gnn":
            # Order has to survive: more hops along the chain, and a recurrent reader below.
            layers = max(layers, 4)
            self.reader = nn.GRU(d, d, batch_first=True)
            edge_extra = d_t + len(DIR_KINDS)
        self.packet_in = nn.Linear(len(PACKET_FEATURES), d)
        self.time = TimeEncoder(d_t)
        # The direction-aware reader gets the packet's arrival offset as a node position.
        self.position = nn.Linear(d_t, d) if packet_encoder == "dir_gnn" else None
        self.flow_in = nn.Linear(a_width, d)
        self.convs = nn.ModuleList(
            HeteroConv({
                LINK: GINEConv(nn.Sequential(nn.Linear(d, d), nn.ReLU(), nn.Linear(d, d)), edge_dim=d_t + edge_extra),
                CONTAIN: SAGEConv((d, d), d),
            }, aggr="sum")
            for _ in range(layers)
        )
        self.head = mlp(a_width + (3 if packet_encoder == "dir_gnn" else 2) * d, d_h)

    def forward(self, batch: dict) -> torch.Tensor:
        return self.head(torch.cat([batch["a"], self._packets(batch, batch["a"])], 1))

    def _packets(self, batch: dict, flow: torch.Tensor) -> torch.Tensor:
        n_flows, k = batch["dt"].shape
        owner, slot, link = packet_graph(batch["n_pkt"], k)
        h = {"packet": self.packet_in(batch["pkt"][owner, slot])}
        if self.position is not None:
            offset = torch.cumsum(batch["dt"], 1)[owner, slot]
            h["packet"] = h["packet"] + self.position(self.time(offset))
        if self.split:
            # Directions kept apart: a chain per side plus reply edges, each edge marked with its
            # kind, and each packet with its side.
            link, kind, seconds = split_links(batch["n_pkt"], batch["pkt"], batch["dt"], owner, slot)
            gap = torch.cat([self.time(seconds), F.one_hot(kind, len(SPLIT_KINDS)).to(seconds.dtype)], 1)
            h["packet"] = h["packet"] + self.side((batch["pkt"][owner, slot, DIRECTION] > 0).long())
        elif self.packet_encoder == "dir_gnn":
            # Arrival order kept. A link's gap goes in the slot for its kind -- the reaction gap after a
            # change of direction, the same-side gap otherwise -- and the kind itself is marked.
            flip = direction_flips(batch["pkt"], owner, slot, link)
            enc = self.time(batch["dt"][owner[link[1]], slot[link[1]]])
            same, turn = (~flip).unsqueeze(1).to(enc.dtype), flip.unsqueeze(1).to(enc.dtype)
            gap = torch.cat([enc * same, enc * turn, F.one_hot(flip.long(), len(DIR_KINDS)).to(enc.dtype)], 1)
            h["packet"] = h["packet"] + self.side((batch["pkt"][owner, slot, DIRECTION] > 0).long())
        else:
            gap = self.time(batch["dt"][owner[link[1]], slot[link[1]]])
        h["flow"] = self.flow_in(flow)
        edges = {LINK: link, CONTAIN: torch.stack([owner, torch.arange(len(owner), device=owner.device)])}
        for conv in self.convs:
            out = conv(h, edges, edge_attr_dict={LINK: gap})
            h = {**h, "packet": F.relu(h["packet"] + out["packet"])}
        z = h["packet"]
        parts = [
            scatter(z, owner, 0, dim_size=n_flows, reduce="mean"),
            scatter(z, owner, 0, dim_size=n_flows, reduce="max"),
        ]
        if self.packet_encoder == "dir_gnn":
            # Mean and max forget order; a GRU over the packets in arrival order keeps it.
            dense = z.new_zeros(n_flows, k, z.shape[1])
            dense[owner, slot] = z
            lengths = batch["n_pkt"].long().clamp(min=1).cpu()
            packed = nn.utils.rnn.pack_padded_sequence(dense, lengths, batch_first=True, enforce_sorted=False)
            _, last = self.reader(packed)
            parts.append(last[-1] * (batch["n_pkt"] > 0).unsqueeze(1).to(z.dtype))
        return torch.cat(parts, 1)


class FlowAutoencoder(nn.Module):
    """FlowEncoder plus decoders reconstructing the flow's own normalised inputs.

    Input:  variant (only "a_pkt"), K, embedding width d_h, predict (also forecast the completed flow's
            aggregates, a_future), aggregate width, FlowEncoder keyword arguments
    Output: module; forward(batch) returns (h (B, d_h), error per target (B, len(targets)))
    """

    def __init__(self, variant: str = VARIANT, k: int = DEFAULT_K_PACKETS, d_h: int = 32,
                 predict: bool = False, a_width: int = len(AGG_COLUMNS), **encoder_kw):
        super().__init__()
        if variant != VARIANT:
            raise ValueError(f"the only variant is {VARIANT}")
        self.encoder = FlowEncoder(d_h=d_h, a_width=a_width, **encoder_kw)
        widths = {"a": a_width, "pkt": k * (len(PACKET_FEATURES) + 2)}
        if predict:
            # Generation reconstructs what was seen; prediction forecasts what the flow becomes.
            widths["a_future"] = len(AGG_COLUMNS)
        self.targets = list(widths)
        self.decoders = nn.ModuleDict({n: mlp(d_h, w) for n, w in widths.items()})

    def forward(self, batch: dict) -> tuple[torch.Tensor, torch.Tensor]:
        h = self.encoder(batch)
        errors = [F.mse_loss(self.decoders[n](h), _target(batch, n), reduction="none").mean(1) for n in self.targets]
        return h, torch.stack(errors, dim=1)


def _target(batch: dict, name: str) -> torch.Tensor:
    """Reconstruction target for one input group.

    Input:  batch, group name a, pkt or a_future
    Output: (B, width) tensor; pkt is packet features, log(1 + dt) and a presence bit per slot
    """
    if name != "pkt":
        return batch[name]
    k = batch["dt"].shape[1]
    present = (torch.arange(k, device=batch["dt"].device) < batch["n_pkt"][:, None]).float()
    return torch.cat([batch["pkt"], torch.log1p(batch["dt"])[..., None], present[..., None]], 2).flatten(1)
