#!/usr/bin/env python3
"""Synthetic, CPU-bound performance corpus for the §7 evaluation.

Deterministic (fixed seed) and local-only: no network is involved, so what the
benchmarks measure is the parser and the scheduler, not HTTP round-trips.

Three size classes (~10 KB, ~100 KB, ~1 MB). A configurable fraction of the
elements are hostile (script tags, event handlers, javascript: links, CSS
expressions, blocked domains) so the rewriter also exercises its action paths.
The benign templates use only tags/attributes allowed by the `balanced` profile.

    python3 scripts/gen_corpus.py --out corpus_perf
    python3 scripts/gen_corpus.py --out /tmp/smoke --scale 0.02     # quick smoke test
"""
import argparse
import json
import pathlib
import random

SIZE_CLASSES = {"small": 10 * 1024, "medium": 100 * 1024, "large": 1024 * 1024}
DEFAULT_COUNTS = {"small": 2000, "medium": 400, "large": 60}

BENIGN = [
    '<h1>Section {i}</h1>',
    '<h2>Subsection {i}</h2>',
    '<p>Lorem ipsum dolor sit amet, <b>consectetur</b> adipiscing elit, '
    '<i>sed do eiusmod</i> tempor incididunt ut labore et dolore {i}.</p>',
    '<div class="box" style="color: #333333; margin: 4px"><p>Paragraph with '
    '<a href="https://example.org/page/{i}" title="Link {i}">a link</a> inside.</p></div>',
    '<span style="font-weight: bold; font-size: 12px">Inline text {i}</span>',
    '<ul><li>One {i}</li><li>Two</li><li>Three</li></ul>',
]

HOSTILE = [
    '<script>alert({i})</script>',
    '<p onclick="steal({i})">Click me</p>',
    '<a href="javascript:alert({i})">x</a>',
    '<div style="width: expression(alert({i})); color: red">styled</div>',
    '<a href="https://malware.com/dl/{i}">download</a>',
    '<img src="data:text/html,<script>1</script>" alt="x">',
]


def build_page(rng: random.Random, target_bytes: int, hostile_fraction: float = 0.1) -> str:
    """Builds an HTML fragment of roughly `target_bytes` bytes."""
    parts, size, i = ["<div>\n"], 0, 0
    while size < target_bytes:
        pool = HOSTILE if rng.random() < hostile_fraction else BENIGN
        chunk = rng.choice(pool).format(i=i) + "\n"
        parts.append(chunk)
        size += len(chunk)
        i += 1
    parts.append("</div>\n")
    return "".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="corpus_perf", help="output directory (default: corpus_perf)")
    ap.add_argument("--scale", type=float, default=1.0, help="multiplier on the file counts")
    ap.add_argument("--hostile-fraction", type=float, default=0.1)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    rng = random.Random(args.seed)
    manifest = {"seed": args.seed, "hostile_fraction": args.hostile_fraction, "classes": {}}

    for cls, target in SIZE_CLASSES.items():
        n = max(1, round(DEFAULT_COUNTS[cls] * args.scale))
        d = out / cls
        d.mkdir(parents=True, exist_ok=True)
        total = 0
        for k in range(n):
            data = build_page(rng, target, args.hostile_fraction).encode()
            (d / f"page_{k:05d}.html").write_bytes(data)
            total += len(data)
        manifest["classes"][cls] = {"files": n, "target_bytes": target, "total_bytes": total}
        print(f"{cls:>6}: {n:5d} files, {total / 1e6:8.1f} MB  -> {d}")

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()