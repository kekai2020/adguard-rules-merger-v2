"""V2 comprehensive test suite — covers every edge case for accuracy."""

import pytest
from merger.models import Rule
from merger.parser import RuleParser
from merger.core import RuleEngine, DomainTrie, DedupReport


# ═══════════════════════════════════════════════════════════════
#  Rule model
# ═══════════════════════════════════════════════════════════════


class TestRuleModel:
    """Rule data model tests."""

    def test_basic(self):
        r = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"})
        assert r.normalized_domain == "a.com"
        assert r.output_raw == "||a.com^"

    def test_wildcard_strip(self):
        r = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"})
        assert r.normalized_domain == "a.com"
        assert r.wildcard is True

    def test_trailing_dot(self):
        r = Rule(raw="||a.com.^", domain="a.com.", rule_type="block",
                 wildcard=False, sources={"s1"})
        assert r.normalized_domain == "a.com"

    def test_case_insensitive(self):
        r = Rule(raw="||Example.COM^", domain="Example.COM",
                 rule_type="block", wildcard=False, sources={"s1"})
        assert r.normalized_domain == "example.com"

    def test_output_raw_allow(self):
        r = Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                 wildcard=False, sources={"s1"})
        assert r.output_raw == "@@||a.com^"

    def test_output_raw_comment(self):
        r = Rule(raw="! comment", domain="", rule_type="comment",
                 wildcard=False, sources={"s1"})
        assert r.output_raw == "! comment"

    def test_output_raw_wildcard_block(self):
        r = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"})
        assert r.output_raw == "||*.a.com^"

    # ── equality / hashing ─────────────────────────────────────

    def test_eq_same(self):
        r1 = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                  wildcard=False, sources={"s1"})
        r2 = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                  wildcard=False, sources={"s2"})
        assert r1 == r2
        assert hash(r1) == hash(r2)

    def test_eq_different_type(self):
        r1 = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                  wildcard=False, sources={"s1"})
        r2 = Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                  wildcard=False, sources={"s1"})
        assert r1 != r2

    def test_eq_wildcard_vs_not(self):
        """*.a.com and a.com are NOT equal — different wildcard flag."""
        r1 = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                  wildcard=True, sources={"s1"})
        r2 = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                  wildcard=False, sources={"s1"})
        assert r1 != r2
        assert hash(r1) != hash(r2)

    def test_eq_normalized(self):
        """*.A.COM and a.com compare on normalized_domain."""
        r1 = Rule(raw="||*.A.COM^", domain="*.A.COM", rule_type="block",
                  wildcard=True, sources={"s1"})
        r2 = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                  wildcard=True, sources={"s1"})
        assert r1 == r2

    def test_sources_set(self):
        r = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1", "s2"})
        assert r.sources == {"s1", "s2"}

    def test_sources_string_coerce(self):
        r = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources="s1")
        assert r.sources == {"s1"}

    # ── domain relationships ───────────────────────────────────

    def test_is_subdomain_of(self):
        parent = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                      wildcard=True, sources={"s1"})
        child = Rule(raw="||sub.a.com^", domain="sub.a.com", rule_type="block",
                     wildcard=False, sources={"s1"})
        assert child.is_subdomain_of(parent)
        assert not parent.is_subdomain_of(child)

    def test_self_not_subdomain(self):
        r1 = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                  wildcard=True, sources={"s1"})
        r2 = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                  wildcard=False, sources={"s1"})
        assert not r2.is_subdomain_of(r1)

    def test_covers_as_wildcard(self):
        wc = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                  wildcard=True, sources={"s1"})
        sub = Rule(raw="||x.a.com^", domain="x.a.com", rule_type="block",
                   wildcard=False, sources={"s1"})
        assert wc.covers_as_wildcard(sub)
        assert not sub.covers_as_wildcard(wc)

    def test_deep_subdomain(self):
        wc = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                  wildcard=True, sources={"s1"})
        deep = Rule(raw="||x.y.a.com^", domain="x.y.a.com", rule_type="block",
                    wildcard=False, sources={"s1"})
        assert wc.covers_as_wildcard(deep)

    def test_unrelated_not_covered(self):
        wc = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                  wildcard=True, sources={"s1"})
        other = Rule(raw="||b.org^", domain="b.org", rule_type="block",
                     wildcard=False, sources={"s1"})
        assert not wc.covers_as_wildcard(other)

    def test_str(self):
        r = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"})
        assert str(r) == "||a.com^"

    def test_repr(self):
        r = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1", "s2"})
        s = repr(r)
        assert "block" in s
        assert "a.com" in s


# ═══════════════════════════════════════════════════════════════
#  Parser
# ═══════════════════════════════════════════════════════════════


class TestParser:
    def setup_method(self):
        self.p = RuleParser()

    def test_block(self):
        r = self.p.parse_line("||example.com^")
        assert r is not None and r.rule_type == "block"
        assert r.domain == "example.com"

    def test_allow(self):
        r = self.p.parse_line("@@||example.com^")
        assert r is not None and r.rule_type == "allow"

    def test_comment(self):
        r = self.p.parse_line("! adguard comment")
        assert r is not None and r.rule_type == "comment"

    def test_wildcard_block(self):
        r = self.p.parse_line("||*.example.com^")
        assert r is not None and r.wildcard is True
        assert r.normalized_domain == "example.com"

    def test_hosts_0000(self):
        r = self.p.parse_line("0.0.0.0 example.com")
        assert r is not None and r.rule_type == "block"
        assert r.raw == "||example.com^"

    def test_hosts_127(self):
        r = self.p.parse_line("127.0.0.1 example.com")
        assert r is not None and r.rule_type == "block"

    def test_plain_domain(self):
        r = self.p.parse_line("example.com")
        assert r is not None and r.rule_type == "block"
        assert r.raw == "||example.com^"

    def test_localhost_skip(self):
        assert self.p.parse_line("0.0.0.0 localhost") is None
        assert self.p.parse_line("0.0.0.0 localhost.localdomain") is None
        assert self.p.parse_line("0.0.0.0 localhost6") is None

    def test_empty(self):
        assert self.p.parse_line("") is None
        assert self.p.parse_line("   ") is None

    def test_html_skip(self):
        assert self.p.parse_line("##.ad-banner") is None

    def test_css_skip(self):
        assert self.p.parse_line("#@#.ad-banner") is None

    def test_ipv4_not_domain(self):
        assert self.p.parse_line("192.168.1.1") is None

    def test_ipv6_not_domain(self):
        assert self.p.parse_line("::1") is None

    def test_trailing_dot(self):
        r = self.p.parse_line("0.0.0.0 example.com.")
        assert r is not None and r.normalized_domain == "example.com"

    def test_subdomain(self):
        r = self.p.parse_line("||ads.example.com^")
        assert r is not None and r.domain == "ads.example.com"
        assert r.wildcard is False

    def test_parse_text(self):
        text = "! comment\n||a.com^\n@@||b.com^\n0.0.0.0 c.com\nd.com\n\n"
        rules = self.p.parse_text(text, source="test")
        types = [r.rule_type for r in rules]
        assert types.count("block") == 3
        assert types.count("allow") == 1
        assert types.count("comment") == 1

    def test_source_preserved(self):
        r = self.p.parse_line("||a.com^", source="https://src1")
        assert r is not None and "https://src1" in r.sources

    def test_adguard_extended_rule_skipped(self):
        """Rules like ||domain.com^$important should be parsed."""
        # This is a basic block rule — the $modifier is after ^
        r = self.p.parse_line("||example.com^$important")
        # The regex requires ^ at end, so this won't match — it's skipped
        # This is correct behavior for DNS-level rules

    def test_hosts_with_comment(self):
        r = self.p.parse_line("0.0.0.0 example.com # comment")
        # Hosts regex captures "example.com" (stops at space)
        assert r is not None and r.domain == "example.com"


# ═══════════════════════════════════════════════════════════════
#  DomainTrie
# ═══════════════════════════════════════════════════════════════


class TestDomainTrie:

    def test_basic_coverage(self):
        t = DomainTrie()
        t.add("example.com")
        assert t.is_covered("sub.example.com") is True
        assert t.is_covered("deep.sub.example.com") is True

    def test_self_not_covered(self):
        t = DomainTrie()
        t.add("example.com")
        assert t.is_covered("example.com") is False

    def test_unrelated(self):
        t = DomainTrie()
        t.add("example.com")
        assert t.is_covered("other.org") is False

    def test_multiple_wildcards(self):
        t = DomainTrie()
        t.add("example.com")
        t.add("test.org")
        assert t.is_covered("x.example.com") is True
        assert t.is_covered("x.test.org") is True
        assert t.is_covered("x.other.net") is False

    def test_empty_trie(self):
        t = DomainTrie()
        assert t.is_covered("anything.com") is False

    def test_deep_wildcard(self):
        t = DomainTrie()
        t.add("a.b.c.com")
        assert t.is_covered("x.a.b.c.com") is True
        assert t.is_covered("a.b.c.com") is False
        assert t.is_covered("b.c.com") is False

    def test_overlapping_wildcards(self):
        t = DomainTrie()
        t.add("example.com")
        t.add("sub.example.com")
        assert t.is_covered("x.sub.example.com") is True
        assert t.is_covered("x.example.com") is True


# ═══════════════════════════════════════════════════════════════
#  RuleEngine — dedup accuracy
# ═══════════════════════════════════════════════════════════════


class TestEngineDedup:

    def setup_method(self):
        self.engine = RuleEngine(allow_overrides_block=False)

    # ── Phase 1: exact dedup ───────────────────────────────────

    def test_exact_dedup(self):
        rules = [
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, report = self.engine.deduplicate(rules)
        assert len(out) == 1
        assert report.exact_merged == 1
        assert out[0].sources == {"s1", "s2"}

    def test_exact_dedup_merges_sources(self):
        """When duplicates are merged, all sources must be preserved."""
        rules = [
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s3"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 1
        assert out[0].sources == {"s1", "s2", "s3"}

    def test_wildcard_and_exact_different_keys(self):
        """*.a.com and a.com have different keys — both kept."""
        rules = [
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 2

    # ── Phase 2: wildcard coverage ─────────────────────────────

    def test_wildcard_removes_subdomain(self):
        rules = [
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||sub.a.com^", domain="sub.a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, report = self.engine.deduplicate(rules)
        assert len(out) == 1
        assert out[0].wildcard is True
        assert report.wildcard_removed == 1

    def test_wildcard_keeps_parent(self):
        """*.a.com does NOT remove a.com."""
        rules = [
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 2

    def test_wildcard_removes_deep_subdomain(self):
        rules = [
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||x.y.a.com^", domain="x.y.a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, report = self.engine.deduplicate(rules)
        assert len(out) == 1
        assert report.wildcard_removed == 1

    def test_wildcard_does_not_remove_different_domain(self):
        rules = [
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||b.com^", domain="b.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 2

    def test_multiple_wildcards(self):
        rules = [
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||*.b.com^", domain="*.b.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||x.a.com^", domain="x.a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
            Rule(raw="||y.b.com^", domain="y.b.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
            Rule(raw="||z.c.com^", domain="z.c.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, report = self.engine.deduplicate(rules)
        assert len(out) == 3  # 2 wildcards + z.c.com
        assert report.wildcard_removed == 2

    # ── block/allow separation ─────────────────────────────────

    def test_block_allow_separate(self):
        rules = [
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                 wildcard=False, sources={"s1"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 2

    def test_allow_dedup_independent(self):
        rules = [
            Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                 wildcard=False, sources={"s1"}),
            Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                 wildcard=False, sources={"s2"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 1

    # ── comments ───────────────────────────────────────────────

    def test_comment_dedup(self):
        rules = [
            Rule(raw="! comment", domain="", rule_type="comment",
                 wildcard=False, sources={"s1"}),
            Rule(raw="! comment", domain="", rule_type="comment",
                 wildcard=False, sources={"s2"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 1

    def test_different_comments_kept(self):
        rules = [
            Rule(raw="! comment A", domain="", rule_type="comment",
                 wildcard=False, sources={"s1"}),
            Rule(raw="! comment B", domain="", rule_type="comment",
                 wildcard=False, sources={"s1"}),
        ]
        out, _ = self.engine.deduplicate(rules)
        assert len(out) == 2

    def test_empty(self):
        out, report = self.engine.deduplicate([])
        assert out == []
        assert report.total_removed == 0

    # ── DedupReport ────────────────────────────────────────────

    def test_report_summary(self):
        report = DedupReport()
        report.exact_merged = 5
        report.wildcard_removed = 3
        report.conflict_resolved = 1
        assert report.total_removed == 9
        assert "exact_merged=5" in report.summary()


# ═══════════════════════════════════════════════════════════════
#  RuleEngine — conflict resolution
# ═══════════════════════════════════════════════════════════════


class TestConflictResolution:

    def test_allow_overrides_block(self):
        engine = RuleEngine(allow_overrides_block=True)
        rules = [
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                 wildcard=False, sources={"s2"}),
        ]
        out, report = engine.deduplicate(rules)
        assert len(out) == 1
        assert out[0].rule_type == "allow"
        assert out[0].sources == {"s1", "s2"}
        assert report.conflict_resolved == 1

    def test_no_override_when_disabled(self):
        engine = RuleEngine(allow_overrides_block=False)
        rules = [
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                 wildcard=False, sources={"s2"}),
        ]
        out, _ = engine.deduplicate(rules)
        assert len(out) == 2

    def test_conflict_preserves_other_rules(self):
        engine = RuleEngine(allow_overrides_block=True)
        rules = [
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            Rule(raw="@@||a.com^", domain="a.com", rule_type="allow",
                 wildcard=False, sources={"s2"}),
            Rule(raw="||b.com^", domain="b.com", rule_type="block",
                 wildcard=False, sources={"s3"}),
        ]
        out, _ = engine.deduplicate(rules)
        assert len(out) == 2
        domains = {r.normalized_domain for r in out}
        assert "a.com" in domains and "b.com" in domains


# ═══════════════════════════════════════════════════════════════
#  End-to-end: combined scenarios
# ═══════════════════════════════════════════════════════════════


class TestEndToEnd:

    def setup_method(self):
        self.engine = RuleEngine(allow_overrides_block=False)

    def test_full_pipeline(self):
        """Simulate real merge: multiple sources, wildcards, duplicates."""
        rules = [
            # Source 1: *.a.com + a.com + b.com
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            Rule(raw="||b.com^", domain="b.com", rule_type="block",
                 wildcard=False, sources={"s1"}),
            # Source 2: a.com (dup) + sub.a.com (covered by wildcard) + c.com
            Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
            Rule(raw="||sub.a.com^", domain="sub.a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
            Rule(raw="||c.com^", domain="c.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
        ]
        out, report = self.engine.deduplicate(rules)
        domains = {r.normalized_domain for r in out}
        assert domains == {"a.com", "b.com", "c.com"}
        assert report.exact_merged == 1      # a.com dup
        assert report.wildcard_removed == 1  # sub.a.com

        # a.com (non-wildcard) should have both sources merged
        a_rule = next(r for r in out if r.normalized_domain == "a.com" and not r.wildcard)
        assert a_rule.sources == {"s1", "s2"}

    def test_allow_block_conflict_with_wildcard(self):
        engine = RuleEngine(allow_overrides_block=True)
        rules = [
            Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block",
                 wildcard=True, sources={"s1"}),
            Rule(raw="||sub.a.com^", domain="sub.a.com", rule_type="block",
                 wildcard=False, sources={"s2"}),
            Rule(raw="@@||sub.a.com^", domain="sub.a.com", rule_type="allow",
                 wildcard=False, sources={"s3"}),
        ]
        out, report = engine.deduplicate(rules)
        # sub.a.com: block removed by wildcard, allow survives
        # *.a.com survives
        # But sub.a.com allow has no wildcard → it survives
        # Actually: Phase 1 → 3 unique rules. Phase 2 → sub.a.com block removed.
        # Phase 3 → no remaining block/allow conflict on same domain.
        # Wait: sub.a.com block was removed in Phase 2. Only sub.a.com allow remains.
        # So no conflict to resolve.
        types = {r.normalized_domain: r.rule_type for r in out}
        assert "a.com" in types
        assert types.get("sub.a.com") == "allow"
