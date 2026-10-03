"""Persist the operator's served-threshold choice without touching checkpoints."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path


class ThresholdMode:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.mode = "checkpoint"
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            if saved.get("mode") in ("checkpoint", "live"):
                self.mode = saved["mode"]
        except (FileNotFoundError, ValueError, OSError, AttributeError):
            pass

    def requested(self) -> str:
        with self.lock:
            return self.mode

    def status(self, live_ready: bool) -> dict:
        requested = self.requested()
        return {"requested": requested,
                "effective": "live" if requested == "live" and live_ready else "checkpoint",
                "live_ready": bool(live_ready)}

    def set(self, mode: str, live_ready: bool) -> dict:
        if mode not in ("checkpoint", "live"):
            raise ValueError("mode must be checkpoint or live")
        if mode == "live" and not live_ready:
            raise ValueError("four-hour live threshold window is not ready")
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + ".tmp")
            temporary.write_text(json.dumps({"mode": mode}) + "\n", encoding="utf-8")
            os.replace(temporary, self.path)
            self.mode = mode
        return self.status(live_ready)
