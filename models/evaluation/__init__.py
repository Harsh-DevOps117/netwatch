"""The complete evaluation: every reported metric, computed in one place from the serving artefacts.

Before this, metrics lived across a dozen experiment scripts, each answering one question on one slice, and
`tools/collect_final.py` only knew how to gather the seven final experiments by number. Nothing produced the whole
picture for a given trained model -- which is what has to be shown, and what has to be re-shown after the full run.
"""
