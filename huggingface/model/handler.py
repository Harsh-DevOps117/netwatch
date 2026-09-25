"""Hugging Face Inference Endpoints entry point.

The platform imports `EndpointHandler` from this file, constructs it once with the repository path, and calls it per
request. Everything the model needs is in the repository; nothing is fetched at request time.

Request:  {"inputs": [[...132 floats...], ...]}            a batch of pre-extracted features
          {"inputs": {"features": [[...]]}}                 equivalent
          {"inputs": "info"}                                what this checkpoint is
Response: [{"predicted": ..., "family": ..., "family_probability": ..., "probabilities": {...}, "alert": ...}, ...]
"""
from __future__ import annotations

from inference import Detector


class EndpointHandler:
    """Loads the detector once, scores each request.

    Input:  the repository path the platform passes in
    Output: callable handler
    """

    def __init__(self, path: str = ""):
        self.detector = Detector(path or ".")

    def __call__(self, data: dict) -> list[dict]:
        """Score one request.

        Input:  the platform's payload dict
        Output: one result per event, or a single-item list carrying the model description

        Errors are returned rather than raised, so a malformed request produces a readable message instead of a 500
        with no explanation.
        """
        payload = data.get("inputs", data)
        if payload == "info" or (isinstance(payload, dict) and payload.get("info")):
            return [self.detector.info()]
        if isinstance(payload, dict):
            payload = payload.get("features", payload.get("inputs"))
        if payload is None:
            return [{"error": "send {'inputs': [[...132 floats...]]} or {'inputs': 'info'}"}]
        try:
            return self.detector.decide(payload)
        except (ValueError, TypeError) as error:
            return [{"error": str(error)}]
