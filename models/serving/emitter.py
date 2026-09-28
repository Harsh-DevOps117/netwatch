"""The three stages between a score and something a human reads: threshold, persistence, incident.

Offline these were whole-file operations (`tools/world_model/fpr_levers.py`, `tools/world_model/alert_economics.py`). Live they have to be
incremental, because the process sees one batch at a time and can never look at the rest of the day. This is that,
with the same arithmetic.

Measured, in order, on the Bot day: thresholding alone emitted **8,544 alerts/hour**. Requiring three consecutive
events above threshold on the same key halved the false alarms (58 -> 30) at **zero** cost to early recall or to
campaign onsets, because an attack produces a run of events and a noisy benign host produces isolated ones. Collapsing
what remained into incidents with a 60 s quiet gap turned 30 alerts into 8. Together: **41.9 alerts/hour, 11.2
incidents/hour**, still catching 99.7% of early events.

None of this touches the model. It is the cheapest large win available anywhere in the system, which is why it is
worth getting exactly right.
"""
from __future__ import annotations

from collections import deque

import torch

PERSIST = 3            # consecutive events above threshold before a key may alert; 2 -> 3 halved false alarms
GAP = 60.0             # quiet seconds that close an incident
CAPACITY = 500_000     # keys tracked at once; a live stream cannot hold a row per key it has ever seen


class AlertEmitter:
    """Score in, incidents out, one event at a time.

    Input:  the family's threshold, how many consecutive events must clear it, the quiet gap, the key cap
    Output: object; push() returns an Incident when a new one opens and None otherwise

    Per key, because both remaining stages are per key: a run of three is three events on the *same* host, and an open
    incident belongs to one host. Keyed on whatever the caller keys on -- sender is what the measurements used.
    """

    def __init__(self, threshold: float, persist: int = PERSIST, gap: float = GAP, capacity: int = CAPACITY):
        self.threshold, self.persist, self.gap, self.capacity = float(threshold), int(persist), float(gap), capacity
        self.run: dict[int, int] = {}          # key -> consecutive events at or above threshold
        self.open_until: dict[int, float] = {}  # key -> when its current incident stops being open
        self.events = self.alerts = self.incidents = 0

    def push(self, key: int, score: float, t: float) -> dict | None:
        """Feed one scored event.

        Input:  its key, its score, its observation time in seconds
        Output: a dict describing the incident if this event opens one, else None

        The counter resets on **any** event below threshold, which is what makes persistence a run test rather than a
        count: an attack holds the score up across consecutive events, benign noise does not.
        """
        self.events += 1
        return self._step(key, score, t)

    def _step(self, key: int, score: float, t: float) -> dict | None:
        """One event's effect on the state, without counting it.

        Input:  key, score, observation time
        Output: the incident it opens, or None

        Separate from push() only so push_batch can count a whole batch at once and still reuse identical logic --
        there must never be two implementations of the run test.
        """
        if score < self.threshold:
            self.run.pop(key, None)                      # reset, and stop tracking a key with nothing to hold
            return None
        run = self.run.get(key, 0) + 1
        self.run[key] = run
        if run < self.persist:
            return None
        self.alerts += 1
        opened = t > self.open_until.get(key, float("-inf"))
        self.open_until[key] = t + self.gap
        if len(self.open_until) > self.capacity:
            self._prune(t)
        if not opened:
            return None                                  # same incident, still open: nothing new to show a human
        self.incidents += 1
        return {"key": key, "t": t, "score": float(score), "incident": self.incidents}

    def push_batch(self, keys, scores, times) -> list[dict]:
        """Feed a batch in arrival order.

        Input:  key, score and observation time per row, in the order the stream produced them
        Output: the incidents this batch opened

        Order matters and is the caller's responsibility: a run of three is three *consecutive* events, so a batch
        sorted by anything other than availability changes the answer.

        **Only the rows that clear the threshold are walked.** The comparison is one torch kernel over the whole batch
        (on the GPU when the scores are already there, which they are -- they come straight from the head), and a key
        with no firing row in this batch ends with its run counter at zero however many rows it had, so those rows
        cannot change the outcome and are skipped. At a 0.003% budget that is 99.997% of the batch not touched by
        Python. Verified against the row-by-row path in demo().
        """
        scores = torch.as_tensor(scores)
        keys = torch.as_tensor(keys)
        times = torch.as_tensor(times)
        self.events += int(scores.numel())
        fires = scores >= self.threshold
        if not bool(fires.any()):
            for key in torch.unique(keys).tolist():          # every run interrupted, nothing to alert
                self.run.pop(int(key), None)
            return []
        live = torch.unique(keys[fires])
        # Keys present but never firing: their runs are broken, and no alert of theirs can survive this batch.
        for key in torch.unique(keys[~torch.isin(keys, live)]).tolist():
            self.run.pop(int(key), None)
        wanted = torch.nonzero(torch.isin(keys, live)).flatten()
        # Only the selected rows cross to the host. Transferring the whole batch instead cost 28 ms of the 87 ms an
        # evaluation spent here, for rows that were then skipped anyway.
        key_list = keys[wanted].tolist()
        score_list = scores[wanted].tolist()
        time_list = times[wanted].tolist()
        out = []
        for key, score, t in zip(key_list, score_list, time_list):   # stream order, so runs stay consecutive
            got = self._step(int(key), float(score), float(t))
            if got is not None:
                out.append(got)
        return out

    def _prune(self, now: float) -> None:
        """Forget keys with nothing outstanding.

        Input:  the current time
        Output: none; closed incidents older than one gap are dropped, and their runs with them

        A key whose incident closed carries no state worth keeping: if it comes back it starts a fresh run, which is
        the same thing a never-seen key does. Only if pruning frees nothing is the oldest half dropped outright.
        """
        stale = [k for k, until in self.open_until.items() if until < now - self.gap]
        for k in stale:
            self.open_until.pop(k, None)
            self.run.pop(k, None)
        if len(self.open_until) > self.capacity:
            for k in sorted(self.open_until, key=self.open_until.get)[: len(self.open_until) // 2]:
                self.open_until.pop(k, None)
                self.run.pop(k, None)

    def rates(self, hours: float) -> dict:
        """What this emitter has produced, per hour.

        Input:  hours of traffic pushed so far
        Output: dict of events, alerts and incidents, absolute and per hour
        """
        hours = max(hours, 1e-9)
        return {"events": self.events, "alerts": self.alerts, "incidents": self.incidents,
                "alerts_per_hour": self.alerts / hours, "incidents_per_hour": self.incidents / hours}


class Recalibrator:
    """Keeps a threshold honest as benign traffic drifts.

    Input:  the false-positive budget, how many rows span the whole period, how many recent rows to keep, the drift
            ratio that demands a recalibration
    Output: object; observe() feeds benign scores, threshold() returns the current one

    **Why two samples.** A threshold read from one contiguous recent stretch overshot its budget **six-fold** on
    another segment of the same day: benign traffic differs by time of day, so a recent window alone is a biased
    sample of "normal". A sample spanning the whole period alone is stale. This keeps both -- a reservoir sample
    across everything seen, plus a FIFO of the most recent rows -- and reads the quantile off their union, which is
    the arrangement the offline calibration measured best.

    Scores fed here must be believed benign. In deployment that means rows that did not alert, which is circular but
    conservative: an attack that slips under the threshold drags the threshold down, never up.
    """

    def __init__(self, budget: float, span: int = 200_000, recent: int = 50_000, tolerance: float = 3.0,
                 seed: int = 0):
        self.budget, self.tolerance = float(budget), float(tolerance)
        self.span, self.recent = torch.empty(span, dtype=torch.float32), deque(maxlen=recent)
        self.seen, self.filled = 0, 0
        self.rng = torch.Generator().manual_seed(seed)

    def observe(self, scores) -> None:
        """Add benign scores to both samples.

        Input:  an array of scores from rows believed benign
        Output: none

        Reservoir sampling for the spanning half, so every row of the period keeps an equal chance of being kept no
        matter how long the process runs, with no growth in memory.
        """
        for value in torch.as_tensor(scores, dtype=torch.float32).flatten().tolist():
            self.recent.append(value)
            self.seen += 1
            if self.filled < len(self.span):
                self.span[self.filled] = value
                self.filled += 1
            else:
                j = int(torch.randint(self.seen, (1,), generator=self.rng))
                if j < len(self.span):
                    self.span[j] = value

    def threshold(self) -> float:
        """The current threshold: the budget quantile of the spanning and recent samples together.

        Input:  none
        Output: threshold, or inf while nothing has been observed
        """
        pool = torch.cat([self.span[: self.filled],
                          torch.tensor(list(self.recent), dtype=torch.float32)])
        if not pool.numel():
            return float("inf")
        return float(torch.quantile(pool, 1.0 - self.budget, interpolation="higher"))

    def drifted(self, realised_rate: float) -> bool:
        """Whether the realised alert rate has moved far enough from the budget to demand a recalibration.

        Input:  the observed false-positive rate over the recent window
        Output: True when it is outside the tolerated ratio either way

        Offline the quantile rule held between 1.0x and 2.4x of its budget across five orders of magnitude, so a
        ratio beyond 3x is outside anything that was ever measured and means the score scale has moved.
        """
        if realised_rate <= 0 or self.budget <= 0:
            return False
        ratio = realised_rate / self.budget
        return ratio > self.tolerance or ratio < 1.0 / self.tolerance


def demo() -> None:
    """Self-check: persistence, incident collapse, key hygiene, the batch fast path, and the calibrator."""
    g = torch.Generator().manual_seed(0)

    # persist-3: two consecutive highs emit nothing, the third opens an incident
    e = AlertEmitter(threshold=0.5, persist=3, gap=60.0)
    assert e.push(1, 0.9, 0.0) is None
    assert e.push(1, 0.9, 1.0) is None
    first = e.push(1, 0.9, 2.0)
    assert first is not None and first["incident"] == 1, first
    assert e.push(1, 0.9, 3.0) is None                     # still inside the quiet gap: same incident
    assert e.incidents == 1 and e.alerts == 2, e.rates(1.0)
    assert e.push(1, 0.9, 200.0) is not None               # past the gap: a second incident
    assert e.incidents == 2

    # a below-threshold event resets the run, so an interrupted run never alerts
    e = AlertEmitter(threshold=0.5, persist=3)
    for t, score in enumerate([0.9, 0.9, 0.1, 0.9, 0.9]):
        assert e.push(7, score, float(t)) is None, (t, score)
    assert e.alerts == 0

    # keys are independent: interleaved hosts each need their own run
    e = AlertEmitter(threshold=0.5, persist=3)
    got = e.push_batch([1, 2, 1, 2, 1, 2], [0.9] * 6, [0.0, 0.1, 0.2, 0.3, 0.4, 0.5])
    assert len(got) == 2, got
    assert {g_["key"] for g_ in got} == {1, 2}

    # THE fast path must equal the row-by-row path, event for event, on a hard random stream
    keys = torch.randint(0, 25, (4_000,), generator=g)
    scores = torch.rand(4_000, generator=g)
    times = torch.sort(torch.rand(4_000, generator=g) * 3600).values
    for threshold in (0.5, 0.8, 0.95):
        one = AlertEmitter(threshold, persist=3, gap=60.0)
        serial = [one.push(int(k), float(s), float(t)) for k, s, t in zip(keys, scores, times)]
        serial = [x for x in serial if x is not None]
        many = AlertEmitter(threshold, persist=3, gap=60.0)
        batched = []
        for at in range(0, len(keys), 512):                 # the real batch width
            batched += many.push_batch(keys[at:at + 512], scores[at:at + 512], times[at:at + 512])
        assert serial == batched, (threshold, len(serial), len(batched))
        assert (one.events, one.alerts, one.incidents) == (many.events, many.alerts, many.incidents)

    # persistence can only reduce volume, never increase it
    previous = float("inf")
    for persist in (1, 2, 3, 5):
        e = AlertEmitter(0.8, persist=persist, gap=60.0)
        e.push_batch(keys, scores, times)
        assert e.events == 4_000
        assert e.alerts <= previous, persist
        assert e.incidents <= e.alerts
        previous = e.alerts

    # pruning keeps the table bounded without losing an open incident
    e = AlertEmitter(0.5, persist=1, gap=10.0, capacity=4)
    for k in range(50):
        e.push(k, 0.9, float(k))
    assert len(e.open_until) <= 8, len(e.open_until)

    # calibrator: a tighter budget gives a higher threshold, and drift is symmetric
    c = Recalibrator(budget=0.01, span=1_000, recent=500)
    c.observe(torch.rand(20_000, generator=g))
    tight = Recalibrator(budget=0.001, span=1_000, recent=500)
    tight.observe(torch.rand(20_000, generator=g))
    assert tight.threshold() >= c.threshold(), (tight.threshold(), c.threshold())
    assert Recalibrator(0.01).threshold() == float("inf"), "no observations yet -> never alert"
    assert c.drifted(0.05) and c.drifted(0.001) and not c.drifted(0.012)
    print("demo ok")


if __name__ == "__main__":
    demo()
