"""V2 Data models for AdGuard rules — accuracy-first design.

Key design decisions:
  1. __eq__ / __hash__ are CONSISTENT: both use (normalized_domain, rule_type, wildcard).
     This means *.a.com and a.com are NOT equal — they are semantically different rules.
  2. Each Rule tracks ALL sources it appeared in (set[str]), not just one.
  3. Rule.output_raw returns the canonical AdGuard format for output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Set


@dataclass
class Rule:
    """A single AdGuard filter rule with full provenance.

    Attributes:
        raw:           Original line from source (kept for fidelity).
        domain:        Extracted domain string (may include *. prefix).
        rule_type:     'block' | 'allow' | 'comment'
        wildcard:      True if domain starts with *.
        sources:       Set of source URLs this rule appeared in.
        _norm:         Cached normalized_domain (computed once).
    """

    raw: str
    domain: str
    rule_type: str          # 'block', 'allow', 'comment'
    wildcard: bool
    sources: Set[str] = field(default_factory=set)
    _norm: str = field(init=False, repr=False, compare=False, default="")

    # ── post-init ──────────────────────────────────────────────

    def __post_init__(self) -> None:
        if isinstance(self.sources, str):
            self.sources = {self.sources}
        self._norm = self._normalize(self.domain)

    # ── normalization ──────────────────────────────────────────

    @staticmethod
    def _normalize(domain: str) -> str:
        """Lowercase, strip wildcard prefix, strip trailing dot."""
        d = domain.lower().strip()
        if d.startswith("*."):
            d = d[2:]
        if d.endswith("."):
            d = d[:-1]
        return d

    @property
    def normalized_domain(self) -> str:
        return self._norm

    # ── canonical output ───────────────────────────────────────

    @property
    def output_raw(self) -> str:
        """Canonical AdGuard format for output file."""
        if self.rule_type == "comment":
            return self.raw
        if self.rule_type == "allow":
            return f"@@||{self.domain}^"
        # block
        return f"||{self.domain}^"

    # ── domain relationship helpers ────────────────────────────

    def is_subdomain_of(self, parent: Rule) -> bool:
        """True if self's domain is a strict subdomain of parent's wildcard."""
        if not parent.wildcard:
            return False
        if self.rule_type != parent.rule_type:
            return False
        return (self._norm != parent._norm and
                self._norm.endswith("." + parent._norm))

    def covers_as_wildcard(self, child: Rule) -> bool:
        """True if self (wildcard) covers child (non-wildcard) as subdomain."""
        if not self.wildcard:
            return False
        if self.rule_type != child.rule_type:
            return False
        return (child._norm != self._norm and
                child._norm.endswith("." + self._norm))

    # ── equality / hashing ─────────────────────────────────────
    # __eq__ and __hash__ MUST be consistent.
    # Key: (normalized_domain, rule_type, wildcard)
    # This means *.a.com ≠ a.com — they are different rules.

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        return (self._norm == other._norm and
                self.rule_type == other.rule_type and
                self.wildcard == other.wildcard)

    def __hash__(self) -> int:
        return hash((self._norm, self.rule_type, self.wildcard))

    # ── string representation ──────────────────────────────────

    def __str__(self) -> str:
        return self.output_raw

    def __repr__(self) -> str:
        src = ",".join(sorted(self.sources)[:2])
        if len(self.sources) > 2:
            src += ",..."
        return f"Rule({self.rule_type} {self.domain!r} [{src}])"
