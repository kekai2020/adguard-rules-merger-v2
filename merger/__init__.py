"""AdGuard Rules Merger v2 — accuracy-first rule merging and deduplication."""

from .core import RuleEngine, DomainTrie, DedupReport
from .models import Rule
from .parser import RuleParser
from .reporter import MergeReporter

__version__ = "2.0.0"
__all__ = [
    "RuleEngine", "DomainTrie", "DedupReport",
    "Rule", "RuleParser", "MergeReporter",
]
