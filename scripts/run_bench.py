#!/usr/bin/env python3
"""Benchmark harness for the §7 evaluation. Writes results/results.csv + results/meta.json.

Experiments (select with --experiments):
  scale   worker sweep (1,2,4,...) over each size class        -> speed-up, throughput, latency vs size
  memory  single files of growing size, one worker              -> peak RSS vs input size
  fetch   sub-resource fetching off / unique URLs / shared URLs -> cost of fetching, cache behaviour

Peak RSS and CPU time come from wait4() on the child, so they are per-run and portable
across macOS and Linux. ALWAYS benchmark the release binary:

    cargo build --release
    python3 scripts/gen_corpus.py --out corpus_perf
    python3 scripts/run_bench.py --corpus corpus_perf
"""
import argparse
import csv
import http.server
import json
import os
import pathlib
import platform
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from gen_corpus import SIZE_CLASSES, build_page  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIELDS = ["experiment", "label", "workers", "n_files", "input_bytes", "rep",
          "wall_s", "cpu_s", "user_s", "sys_s", "maxrss_mb", "exit_code"]


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def make_png() -> bytes:
    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff"))
            + chunk(b"IEND", b""))


def measure(cmd):
    """Runs cmd once. Returns (wall_s, user_s, sys_s, peak_rss_mb, exit_code)."""
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _, status, ru = os.wait4(p.pid, 0)
    wall = time.perf_counter() - t0
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
    p.returncode = code
    div = 1024 * 1024 if platform.system() == "Darwin" else 1024  # ru_maxrss: bytes on macOS, KiB on Linux
    return wall, ru.ru_utime, ru.ru_stime, ru.ru_maxrss / div, code


class Recorder:
    def __init__(self, path: pathlib.Path):
        self.f = open(path, "w", newline="")
        self.w = csv.DictWriter(self.f, FIELDS)
        self.w.writeheader()

    def run(self, experiment, label, workers, n_files, input_bytes, rep, cmd):
        wall, user, sys_, rss, code = measure(cmd)
        cpu = user + sys_
        if code not in (0, 1):  # 1 = "something was refused", legitimate; anything else is a real failure
            raise SystemExit(f"cli failed with exit code {code}: {' '.join(map(str, cmd))}")
        self.w.writerow(dict(experiment=experiment, label=label, workers=workers, n_files=n_files,
                             input_bytes=input_bytes, rep=rep, wall_s=f"{wall:.6f}",
                             cpu_s=f"{cpu:.6f}", user_s=f"{user:.6f}", sys_s=f"{sys_:.6f}",
                             maxrss_mb=f"{rss:.2f}", exit_code=code))
        self.f.flush()
        log(f"  {experiment}/{label} w={workers} rep={rep}: {wall:7.3f}s  cpu={cpu:7.3f}s "
            f"(user {user:.3f} / sys {sys_:.3f})  rss={rss:7.1f}MB")


def dir_stats(d: pathlib.Path):
    sizes = [p.stat().st_size for p in d.iterdir() if p.is_file()]
    return len(sizes), sum(sizes)


def worker_list(cpus: int):
    ws = {1}
    w = 2
    while w < cpus:
        ws.add(w)
        w *= 2
    ws.update({cpus, cpus * 2})
    return sorted(ws)


# --------------------------------------------------------------------------- experiments
def exp_scale(rec, cli, corpus, workers, reps):
    log("== scale: worker sweep per size class")
    for cls in SIZE_CLASSES:
        d = corpus / cls
        if not d.is_dir():
            log(f"  skipping {cls}: {d} not found")
            continue
        n, total = dir_stats(d)
        measure([cli, "-d", d, "-w", "1", "-q", "--max-fetch-depth", "0"])  # warm the page cache
        for rep in range(reps):  # reps outermost: slow drift (thermal, background) is spread across worker counts
            for w in workers:
                rec.run("scale", cls, w, n, total, rep,
                        [cli, "-d", d, "-w", str(w), "-q", "--max-fetch-depth", "0"])


def exp_memory(rec, cli, sizes_mb, reps):
    log("== memory: peak RSS vs single-file input size (1 worker)")
    rng = random.Random(7)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ws_mem_"))
    try:
        cases = [("baseline", 2_000)] + [(f"{mb}MB", int(mb * 1_000_000)) for mb in sizes_mb]
        for label, target in cases:
            f = tmp / f"{label}.html"
            f.write_bytes(build_page(rng, target).encode())
            size = f.stat().st_size
            measure([cli, "-f", f, "-w", "1", "-q", "--max-fetch-depth", "0"])
            for rep in range(reps):
                rec.run("memory", label, 1, 1, size, rep,
                        [cli, "-f", f, "-w", "1", "-q", "--max-fetch-depth", "0"])
            f.unlink()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class _AssetHandler(http.server.BaseHTTPRequestHandler):
    png = make_png()
    delay = 0.0
    served = 0                      # responses fully written; lets us check the fetches really happened
    _lock = threading.Lock()

    def do_GET(self):
        if self.delay:
            time.sleep(self.delay)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(self.png)))
            self.end_headers()
            self.wfile.write(self.png)
        except (BrokenPipeError, ConnectionResetError):
            return                  # the client hung up mid-response; not an error for the benchmark
        with _AssetHandler._lock:
            _AssetHandler.served += 1

    def log_message(self, *a):
        pass


class _QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass                        # silence per-connection tracebacks (see do_GET)


def exp_fetch(rec, cli, reps, workers, pages, imgs, delay_ms):
    log("== fetch: sub-resource fetching off / unique URLs / shared URLs")
    _AssetHandler.delay = delay_ms / 1000.0
    srv = _QuietServer(("127.0.0.1", 0), _AssetHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ws_fetch_"))
    try:
        for variant in ("unique", "shared"):
            d = tmp / variant
            d.mkdir()
            for p in range(pages):
                imgs_html = "".join(
                    f'<img src="{base}/{"a" if variant == "shared" else f"p{p}_"}{k}.png" alt="i">'
                    for k in range(imgs))
                (d / f"page_{p:04d}.html").write_text(f"<div><p>page {p}</p>{imgs_html}</div>")
        common = ["-w", str(workers), "-q", "--block-internal-ips", "false"]
        variants = [("no-fetch", "unique", ["--max-fetch-depth", "0"]),
                    ("fetch-unique", "unique", ["--max-fetch-depth", "3"]),
                    ("fetch-shared", "shared", ["--max-fetch-depth", "3"])]
        for label, sub, extra in variants:
            d = tmp / sub
            n, total = dir_stats(d)
            before = _AssetHandler.served
            for rep in range(reps):
                rec.run("fetch", label, workers, n, total, rep, [cli, "-d", d] + common + extra)
            per_run = (_AssetHandler.served - before) / reps
            log(f"  -> {label}: {per_run:.0f} asset requests served per run "
                f"({pages} pages x {imgs} images = {pages * imgs} references)")
    finally:
        srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", default=str(ROOT / "target" / "release" / "cli"))
    ap.add_argument("--corpus", default="corpus_perf")
    ap.add_argument("--out", default="results")
    ap.add_argument("--experiments", default="scale,memory,fetch")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--workers", help="comma-separated worker counts (default: 1,2,4,..,cpus,2*cpus)")
    ap.add_argument("--memory-sizes-mb", default="1,5,10,25,50,100")
    ap.add_argument("--fetch-pages", type=int, default=300)
    ap.add_argument("--fetch-imgs", type=int, default=10, help="sub-resources per page (max_requests_per_job is 50)")
    ap.add_argument("--fetch-delay-ms", type=float, default=5.0, help="simulated origin latency")
    args = ap.parse_args()

    cli = pathlib.Path(args.cli)
    if not cli.exists():
        sys.exit(f"CLI binary not found: {cli}\nBuild it first: cargo build --release")
    if "debug" in cli.parts:
        log("WARNING: benchmarking a debug build; numbers are meaningless. Use --release.")

    cpus = os.cpu_count() or 4
    workers = [int(x) for x in args.workers.split(",")] if args.workers else worker_list(cpus)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    def sh(*cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT).stdout.strip()
        except OSError:
            return "n/a"
    (out / "meta.json").write_text(json.dumps({
        "platform": platform.platform(), "machine": platform.machine(), "cpu_count": cpus,
        "python": platform.python_version(), "rustc": sh("rustc", "--version"),
        "git_commit": sh("git", "rev-parse", "--short", "HEAD"), "cli": str(cli),
        "workers": workers, "reps": args.reps, "experiments": args.experiments,
        "fetch_delay_ms": args.fetch_delay_ms,
    }, indent=2))

    rec = Recorder(out / "results.csv")
    exps = set(args.experiments.split(","))
    if "scale" in exps:
        exp_scale(rec, str(cli), pathlib.Path(args.corpus), workers, args.reps)
    if "memory" in exps:
        exp_memory(rec, str(cli), [float(x) for x in args.memory_sizes_mb.split(",")], args.reps)
    if "fetch" in exps:
        exp_fetch(rec, str(cli), args.reps, cpus, args.fetch_pages, args.fetch_imgs, args.fetch_delay_ms)
    log(f"done -> {out / 'results.csv'}")


if __name__ == "__main__":
    main()