#!/usr/bin/env python3
"""V2 CLI for merging AdGuard rules.

Usage:
  python merge_rules.py --config config/sources.yaml
  python merge_rules.py -s URL1 URL2 -o output.txt --report --verify
  python merge_rules.py --config config/sources.yaml --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from merger import RuleEngine, MergeReporter
from config_loader import load_sources_config, load_sources_with_names


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )


def write_output(rules, path: Path, stats: dict | None = None) -> None:
    """Write merged rules to file with metadata header."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("! Merged AdGuard Filter Rules\n")
        f.write(f"! Generated: {datetime.now(timezone.utc).isoformat()}\n")
        if stats:
            f.write(f"! Sources: {stats.get('sources_ok', 0)}/{stats.get('sources_total', 0)}\n")
            f.write(f"! Total rules: {len(rules)}\n")
            f.write(f"! Dedup rate: {stats.get('dedup_rate', 0):.1f}%\n")
            f.write(f"! Dedup detail: exact_merged={stats.get('exact_merged', 0)}"
                    f" wildcard_removed={stats.get('wildcard_removed', 0)}"
                    f" conflict_resolved={stats.get('conflict_resolved', 0)}\n")
        f.write("!\n")
        for rule in rules:
            f.write(f"{rule}\n")


def verify_output(sources: list[str], rules: list, timeout: int, workers: int) -> bool:
    """Quick inline verification."""
    from validate_output import validate_merged_output
    return validate_merged_output(sources, merged_rules=rules, timeout=timeout, workers=workers)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="V2: Merge AdGuard filter rules with guaranteed accuracy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-s", "--sources", nargs="+", help="Source URLs")
    src.add_argument("-c", "--config", help="YAML config path")

    ap.add_argument("-o", "--output", default="merged_rules.txt", help="Output path")
    ap.add_argument("-r", "--report", action="store_true", help="Generate report")
    ap.add_argument("--report-format", choices=["markdown", "text", "json"], default="markdown")
    ap.add_argument("--detect-conflicts", action="store_true", help="Detect block/allow conflicts")
    ap.add_argument("--no-allow-override", action="store_true",
                    help="Disable allow-overrides-block resolution")
    ap.add_argument("--verify", action="store_true", help="Verify output against sources")
    ap.add_argument("--dry-run", action="store_true", help="Fetch + dedup but don't write")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--max-workers", type=int, default=10)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--version", action="version", version="%(prog)s 2.0.0")

    args = ap.parse_args()
    setup_logging(args.verbose, args.quiet)
    log = logging.getLogger("merge")

    # load sources
    if args.config:
        try:
            sources = load_sources_config(args.config)
            log.info("Loaded %d sources from %s", len(sources), args.config)
        except Exception as e:
            log.error("Config error: %s", e)
            sys.exit(1)
    else:
        sources = args.sources

    if not sources:
        log.error("No sources!")
        sys.exit(1)

    log.info("AdGuard Rules Merger v2.0 — %d sources", len(sources))

    try:
        engine = RuleEngine(
            timeout=args.timeout,
            max_workers=args.max_workers,
            allow_overrides_block=not args.no_allow_override,
        )

        result = engine.merge(
            sources,
            return_stats=True,
            detect_conflicts=args.detect_conflicts,
        )
        rules = result["rules"]
        stats = result["stats"]

        log.info("Merged %d → %d rules (dedup %.1f%%, %.2fs)",
                 stats["total_before"], len(rules), stats["dedup_rate"], stats["elapsed_time"])

        if args.detect_conflicts:
            for c in result.get("conflicts", []):
                log.warning("Conflict: %s", c["domain"])

        if args.dry_run:
            log.info("Dry-run mode — skipping file write")
        else:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            write_output(rules, out, stats)
            log.info("Written to %s", out)

        if args.report:
            reporter = MergeReporter(rules, stats)
            ext = {"markdown": "md", "text": "txt", "json": "json"}[args.report_format]
            rp = Path(args.output).with_suffix(f".report.{ext}")
            reporter.save(str(rp), fmt=args.report_format)
            log.info("Report: %s", rp)

        if args.verify:
            log.info("Verifying output...")
            ok = verify_output(sources, rules, args.timeout, args.max_workers)
            if not ok:
                log.error("Verification FAILED")
                sys.exit(2)
            log.info("Verification PASSED")

        if not args.quiet:
            print(f"\n📊 V2 Merge Results:")
            print(f"   Rules: {len(rules):,} (from {stats['total_before']:,})")
            print(f"   Block: {stats['block_count']:,}  Allow: {stats['allow_count']:,}  Comment: {stats['comment_count']:,}")
            print(f"   Dedup: {stats['dedup_rate']:.1f}%  "
                  f"(exact={stats['exact_merged']:,} wildcard={stats['wildcard_removed']:,} conflict={stats['conflict_resolved']:,})")
            print(f"   Time: {stats['elapsed_time']:.2f}s")
            if not args.dry_run:
                print(f"   Output: {Path(args.output).absolute()}")

    except KeyboardInterrupt:
        log.info("Cancelled")
        sys.exit(1)
    except Exception as e:
        log.error("Failed: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
