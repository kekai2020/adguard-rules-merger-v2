"""V2 Configuration loader with validation and source metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def _load_yaml(config_path: str) -> Dict[str, Any]:
    p = Path(config_path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_sources_config(config_path: str = "config/sources.yaml") -> List[str]:
    """Return list of enabled source URLs."""
    cfg = _load_yaml(config_path)
    out = []
    for s in cfg.get("sources", []):
        if s.get("enabled", True):
            out.append(s["url"])
    return out


def load_sources_with_names(
    config_path: str = "config/sources.yaml",
) -> List[Dict[str, str]]:
    """Return list of {'name': ..., 'url': ..., 'category': ...}."""
    cfg = _load_yaml(config_path)
    out = []
    for s in cfg.get("sources", []):
        if s.get("enabled", True):
            out.append({
                "name":     s.get("name", "unknown"),
                "url":      s["url"],
                "category": s.get("category", ""),
            })
    return out


def load_test_sources(config_path: str = "config/sources.yaml") -> List[str]:
    cfg = _load_yaml(config_path)
    return [
        s["url"]
        for s in cfg.get("test_sources", [])
        if s.get("enabled", True)
    ]


def validate_config(config_path: str = "config/sources.yaml") -> List[str]:
    """Validate config and return list of issues."""
    issues: List[str] = []
    try:
        cfg = _load_yaml(config_path)
    except Exception as e:
        return [f"Cannot load config: {e}"]

    if "sources" not in cfg:
        issues.append("No 'sources' key found")
        return issues

    urls_seen = set()
    for i, s in enumerate(cfg["sources"]):
        prefix = f"sources[{i}]"
        if "url" not in s:
            issues.append(f"{prefix}: missing 'url'")
            continue
        url = s["url"]
        if url in urls_seen:
            issues.append(f"{prefix}: duplicate URL {url}")
        urls_seen.add(url)
        if not s.get("name"):
            issues.append(f"{prefix}: missing 'name'")

    return issues


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "config/sources.yaml"
    issues = validate_config(path)
    if issues:
        print("Issues found:")
        for i in issues:
            print(f"  - {i}")
    else:
        sources = load_sources_with_names(path)
        print(f"Valid config with {len(sources)} enabled sources:")
        for s in sources:
            print(f"  [{s['category'] or '-'}] {s['name']}")
