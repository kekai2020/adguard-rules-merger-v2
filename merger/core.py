"""V2 Core engine for merging AdGuard rules — accuracy-first design.

Dedup algorithm (3 phases):
  Phase 1 — Exact dedup:
      Key = (normalized_domain, rule_type, wildcard).
      On collision, merge source sets.  Keep one Rule with combined sources.
      *.a.com and a.com are NOT the same key — both survive.

  Phase 2 — Wildcard coverage:
      Build a DomainTrie from all wildcard domains.
      Remove non-wildcard rules whose normalized_domain is a strict
      subdomain of a wildcard.  (*.a.com removes ads.a.com but NOT a.com.)

  Phase 3 — Allow-overrides-block (optional):
      If the same normalized_domain has both block and allow rules,
      keep the allow rule (AdGuard semantics: allow wins).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from .models import Rule
from .parser import RuleParser

logger = logging.getLogger(__name__)


# ── Domain Trie ────────────────────────────────────────────────


class DomainTrie:
    """Trie for wildcard coverage detection.

    Stored with TLD-first ordering:
        *.example.com  →  root['com']['example']['__wc__'] = True

    Coverage rule:
        sub.example.com  →  covered  (parent has wildcard)
        example.com      →  NOT covered  (wildcard = subdomains only)
    """

    __slots__ = ("root",)

    def __init__(self) -> None:
        self.root: Dict[str, Any] = {}

    def add(self, domain: str) -> None:
        """Insert a wildcard domain (without *. prefix)."""
        node = self.root
        for part in reversed(domain.lower().split(".")):
            node = node.setdefault(part, {})
        node["__wc__"] = True

    def is_covered(self, domain: str) -> bool:
        """Check if *domain* is a strict subdomain of any wildcard."""
        node = self.root
        for part in reversed(domain.lower().split(".")):
            if "__wc__" in node:
                return True
            if part not in node:
                return False
            node = node[part]
        return False


# ── Dedup Report ───────────────────────────────────────────────


class DedupReport:
    """Tracks what was removed and why."""

    __slots__ = (
        "exact_merged",      # sources merged into surviving rule
        "wildcard_removed",  # removed by wildcard coverage
        "conflict_resolved", # block/allow conflicts resolved
    )

    def __init__(self) -> None:
        self.exact_merged: int = 0
        self.wildcard_removed: int = 0
        self.conflict_resolved: int = 0

    @property
    def total_removed(self) -> int:
        return self.exact_merged + self.wildcard_removed + self.conflict_resolved

    def summary(self) -> str:
        return (
            f"exact_merged={self.exact_merged} "
            f"wildcard_removed={self.wildcard_removed} "
            f"conflict_resolved={self.conflict_resolved} "
            f"total={self.total_removed}"
        )


# ── Rule Engine ────────────────────────────────────────────────


class RuleEngine:
    """Fetch, parse, deduplicate, and merge AdGuard filter rules."""

    def __init__(
        self,
        timeout: int = 60,
        max_workers: int = 10,
        allow_overrides_block: bool = True,
    ) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self.allow_overrides_block = allow_overrides_block
        self.parser = RuleParser()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "AdGuard-Rules-Merger/2.0"

    # ── fetch ──────────────────────────────────────────────────

    def fetch_source(self, source: str) -> str:
        """Fetch from URL or local file."""
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"Invalid source: {source!r}")
        source = source.strip()
        p = Path(source)
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8")
        resp = self.session.get(source, timeout=self.timeout)
        resp.raise_for_status()
        return resp.text

    def _fetch_and_parse(self, url: str) -> Tuple[List[Rule], bool]:
        try:
            text = self.fetch_source(url)
            rules = self.parser.parse_text(text, source=url)
            logger.info("Parsed %d rules from %s", len(rules), url)
            return rules, True
        except Exception as exc:
            logger.warning("Failed %s: %s", url, exc)
            return [], False

    def fetch_and_parse_all(self, urls: List[str]) -> Tuple[List[Rule], int]:
        """Concurrent fetch + parse.  Returns (all_rules, success_count)."""
        all_rules: List[Rule] = []
        ok = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futs = {pool.submit(self._fetch_and_parse, u): u for u in urls}
            for fut in as_completed(futs):
                try:
                    rules, success = fut.result()
                    all_rules.extend(rules)
                    if success:
                        ok += 1
                except Exception as exc:
                    logger.warning("Unexpected: %s", exc)
        return all_rules, ok

    # ── dedup ──────────────────────────────────────────────────

    def deduplicate(
        self, rules: List[Rule]
    ) -> Tuple[List[Rule], DedupReport]:
        """3-phase dedup.  Returns (deduped_rules, report)."""
        report = DedupReport()
        if not rules:
            return [], report

        # separate by type
        blocks:   List[Rule] = []
        allows:   List[Rule] = []
        comments: List[Rule] = []
        for r in rules:
            if r.rule_type == "block":
                blocks.append(r)
            elif r.rule_type == "allow":
                allows.append(r)
            else:
                comments.append(r)

        dedup_blocks, rep_b   = self._dedup_type(blocks)
        dedup_allows, rep_a   = self._dedup_type(allows)
        dedup_comments, rep_c = self._dedup_comments(comments)

        report.exact_merged     += rep_b.exact_merged + rep_a.exact_merged + rep_c.exact_merged
        report.wildcard_removed += rep_b.wildcard_removed + rep_a.wildcard_removed

        merged = dedup_blocks + dedup_allows + dedup_comments

        # Phase 3: allow-overrides-block
        if self.allow_overrides_block:
            merged, rep_conf = self._resolve_conflicts(merged)
            report.conflict_resolved = rep_conf

        return merged, report

    def _dedup_type(
        self, rules: List[Rule]
    ) -> Tuple[List[Rule], DedupReport]:
        """Phase 1 + Phase 2 for a single rule type."""
        report = DedupReport()
        if not rules:
            return [], report

        # Phase 1: exact dedup with source merging
        unique: Dict[Tuple[str, str, bool], Rule] = {}
        wild_domains: Set[str] = set()

        for r in rules:
            key = (r._norm, r.rule_type, r.wildcard)
            existing = unique.get(key)
            if existing is None:
                unique[key] = r
                if r.wildcard:
                    wild_domains.add(r._norm)
            else:
                # merge sources into surviving rule
                before = len(existing.sources)
                existing.sources |= r.sources
                report.exact_merged += 1

        if not wild_domains:
            return list(unique.values()), report

        # Phase 2: wildcard coverage
        trie = DomainTrie()
        for d in wild_domains:
            trie.add(d)

        final: List[Rule] = []
        for r in unique.values():
            if r.wildcard:
                final.append(r)
            elif trie.is_covered(r._norm):
                report.wildcard_removed += 1
            else:
                final.append(r)

        return final, report

    @staticmethod
    def _dedup_comments(
        comments: List[Rule],
    ) -> Tuple[List[Rule], DedupReport]:
        report = DedupReport()
        seen: Set[str] = set()
        out: List[Rule] = []
        for c in comments:
            if c.raw in seen:
                report.exact_merged += 1
                continue
            seen.add(c.raw)
            out.append(c)
        return out, report

    @staticmethod
    def _resolve_conflicts(
        rules: List[Rule],
    ) -> Tuple[List[Rule], int]:
        """Phase 3: if same domain has both block and allow → keep allow."""
        by_key: Dict[Tuple[str, str], List[Rule]] = defaultdict(list)
        for r in rules:
            by_key[(r._norm, r.rule_type)].append(r)

        # find domains with both block and allow
        all_norms = {k[0] for k in by_key}
        block_norms = {k[0] for k in by_key if k[1] == "block"}
        allow_norms = {k[0] for k in by_key if k[1] == "allow"}
        conflict_norms = block_norms & allow_norms

        if not conflict_norms:
            return rules, 0

        out: List[Rule] = []
        resolved = 0
        for r in rules:
            if r._norm in conflict_norms:
                if r.rule_type == "allow":
                    # merge block sources into allow rule
                    block_rules = by_key.get((r._norm, "block"), [])
                    for br in block_rules:
                        r.sources |= br.sources
                    out.append(r)
                else:
                    resolved += 1
            else:
                out.append(r)

        return out, resolved

    # ── merge (high-level) ─────────────────────────────────────

    def merge(
        self,
        sources: List[str],
        *,
        return_stats: bool = False,
        detect_conflicts: bool = False,
    ) -> Any:
        """Full merge pipeline.  Returns list[Rule] or dict with stats."""
        if not isinstance(sources, list):
            raise TypeError(f"Expected list, got {type(sources).__name__}")

        logger.info("Merging %d sources", len(sources))
        t0 = time.time()

        all_rules, ok = self.fetch_and_parse_all(sources)
        logger.info("Raw rules: %d (from %d/%d sources)", len(all_rules), ok, len(sources))

        deduped, report = self.deduplicate(all_rules)

        block_n  = sum(1 for r in deduped if r.rule_type == "block")
        allow_n  = sum(1 for r in deduped if r.rule_type == "allow")
        comment_n = sum(1 for r in deduped if r.rule_type == "comment")
        elapsed = time.time() - t0
        dedup_rate = (1 - len(deduped) / len(all_rules)) * 100 if all_rules else 0

        logger.info("Deduped: %d (%.1f%% rate) in %.2fs", len(deduped), dedup_rate, elapsed)
        logger.info("Dedup detail: %s", report.summary())

        if not return_stats and not detect_conflicts:
            return deduped

        stats: Dict[str, Any] = {
            "total_before":      len(all_rules),
            "total_after":       len(deduped),
            "dedup_rate":        dedup_rate,
            "block_count":       block_n,
            "allow_count":       allow_n,
            "comment_count":     comment_n,
            "elapsed_time":      elapsed,
            "sources_ok":        ok,
            "sources_total":     len(sources),
            "exact_merged":      report.exact_merged,
            "wildcard_removed":  report.wildcard_removed,
            "conflict_resolved": report.conflict_resolved,
        }

        result: Dict[str, Any] = {"rules": deduped, "stats": stats}

        if detect_conflicts:
            result["conflicts"] = self.detect_conflicts(deduped)
            stats["conflict_count"] = len(result["conflicts"])

        return result

    # ── conflict detection ─────────────────────────────────────

    @staticmethod
    def detect_conflicts(rules: List[Rule]) -> List[Dict[str, Any]]:
        """Find domains that have both block and allow rules."""
        block_map: Dict[str, List[Rule]] = defaultdict(list)
        allow_map: Dict[str, List[Rule]] = defaultdict(list)
        for r in rules:
            if r.rule_type == "block":
                block_map[r._norm].append(r)
            elif r.rule_type == "allow":
                allow_map[r._norm].append(r)

        conflicts = []
        for norm in set(block_map) & set(allow_map):
            conflicts.append({
                "domain": norm,
                "block_rules": block_map[norm],
                "allow_rules": allow_map[norm],
            })
        return conflicts
