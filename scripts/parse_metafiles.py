#!/usr/bin/env python3
"""Parse already-collected robots/sitemap assets without making network requests."""
import argparse
import json
import os
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_ITEMS = 1000


def parse_robots(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*(Disallow|Allow)\s*:\s*(\S+)", line, re.I)
        if m and m.group(2):
            out.append((m.group(2), "robots:" + m.group(1).lower()))
    return out


def parse_sitemap(text):
    out = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] == "loc" and node.text and node.text.strip():
            out.append((node.text.strip(), "sitemap:loc"))
    return out


def main():
    ap = argparse.ArgumentParser(description="Build candidate paths from collected metafiles")
    ap.add_argument("target")
    args = ap.parse_args()
    base = os.path.join(ROOT, "targets", args.target)
    manifest_path = os.path.join(base, "captures", "manifest.json")
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    candidates = []
    sitemap_urls = []
    for asset in manifest.get("assets", []):
        if asset.get("asset_kind") != "metafile" or not asset.get("raw_ref"):
            continue
        path = os.path.join(ROOT, asset["raw_ref"])
        if not os.path.exists(path):
            continue
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", "replace")
        source = asset.get("source_url", "")
        if urlparse(source).path.lower().endswith("robots.txt"):
            candidates.extend(parse_robots(text))
        elif urlparse(source).path.lower().endswith("sitemap.xml") or "sitemap" in text[:300].lower():
            found = parse_sitemap(text)
            candidates.extend(found)
            sitemap_urls.extend(u for u, _ in found if u.lower().endswith((".xml", "/sitemap")))
    # Nested sitemap URLs are observations only when their assets were not collected.
    collected_urls = {a.get("source_url") for a in manifest.get("assets", [])}
    for url in sitemap_urls:
        if url not in collected_urls:
            candidates.append((url, "sitemap:uncollected-nested"))
    unique = []
    seen = set()
    for value, source in candidates:
        key = (value, source)
        if key not in seen and len(unique) < MAX_ITEMS:
            seen.add(key)
            unique.append(key)
    out_dir = os.path.join(base, "captures", "observation")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "candidate-paths.txt")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Observation only; no URL was fetched by this parser.\n")
        for value, source in unique:
            f.write(f"{source}\t{value}\n")
    print(f"[*] candidate paths: {len(unique)} -> {os.path.relpath(out_path, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
