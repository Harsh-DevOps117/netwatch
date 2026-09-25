"""Why the system said what it said.

The problem statement asks for explainability, and the context encoder already computes the thing that answers it: an
attention distribution over each event's neighbourhood. It was being discarded (`need_weights=False`). This package
turns it on, reads it out, and pairs it with an attribution over the detector's own input so an analyst gets both
halves of an answer: *which other traffic* made this event look wrong, and *which part of the representation* the
decision actually used.
"""
