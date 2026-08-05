"""sink taxonomy — pattern table for classifying Q4 callees as dangerous sinks."""
from .taxonomy import SINK_TAXONOMY, classify_sink, match_sinks

__all__ = ["SINK_TAXONOMY", "classify_sink", "match_sinks"]
