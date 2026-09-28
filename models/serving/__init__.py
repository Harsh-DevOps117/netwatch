"""Serving-side code: the parts that run against live traffic rather than a finished file.

Nothing here is trained. These are the pieces a live process needs that the offline pipeline gets for free from having
the whole day in memory: the graph built incrementally (graph.py) and the decision made incrementally (emitter.py).
"""
