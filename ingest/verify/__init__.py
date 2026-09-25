"""Post-ingest audits. Run as `python -m ingest.verify <day>`; exits non-zero on any failure."""
from ingest.verify.checks import verify_day

__all__ = ["verify_day"]
