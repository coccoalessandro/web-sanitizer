#!/usr/bin/env python3
"""Turns results/results.csv into the plots and the summary table for the report.

    python3 scripts/plot_results.py --results results

Produces in <results>/plots/: speedup.png, latency_vs_size.png, memory.png, fetch.png
and <results>/summary.csv (medians over repetitions, ready to paste into the report).
"""
import argparse
import json
import pathlib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

ORDER = ["small", "medium", "large"]


def aggregate(df, cpus=None):
    g = df.groupby(["experiment", "label", "workers"], sort=False)
    a = g.agg(n_files=("n_files", "first"), input_bytes=("input_bytes", "first"),
              wall=("wall_s", "median"), wall_min=("wall_s", "min"), wall_max=("wall_s", "max"),
              cpu=("cpu_s", "median"), rss=("maxrss_mb", "median"), reps=("rep", "count")).reset_index()
    if {"user_s", "sys_s"} <= set(df.columns):  # absent in CSVs produced by the first version of run_bench.py
        extra = g.agg(user=("user_s", "median"), sys=("sys_s", "median")).reset_index()
        a = a.merge(extra, on=["experiment", "label", "workers"])
    a["inputs_per_s"] = a["n_files"] / a["wall"]
    a["mb_per_s"] = a["input_bytes"] / 1e6 / a["wall"]
    a["latency_ms"] = a["wall"] / a["n_files"] * 1000
    # Fraction of the available execution units actually busy. With more workers than cores
    # the denominator is capped at the core count: otherwise 16 workers on 8 cores could never
    # exceed 50% and the metric would look like idleness when it is just oversubscription.
    eff = a["workers"].clip(upper=cpus) if cpus else a["workers"]
    a["cpu_util"] = a["cpu"] / (a["wall"] * eff)
    return a


def plot_scale(a, out):
    s = a[a.experiment == "scale"]
    if s.empty:
        return
    fig, ax = plt.subplots(1, 3, figsize=(15, 4.2))
    for cls in [c for c in ORDER if c in set(s.label)]:
        d = s[s.label == cls].sort_values("workers")
        base = d[d.workers == d.workers.min()].wall.iloc[0]
        speed = base / d.wall
        ax[0].plot(d.workers, speed, "o-", label=cls)
        ax[1].plot(d.workers, d.mb_per_s, "o-", label=cls)
        ax[2].plot(d.workers, d.cpu_util * 100, "o-", label=cls)
    wmax = s.workers.max()
    ax[0].plot([1, wmax], [1, wmax], "k--", lw=1, label="ideal")
    ax[0].set(xlabel="worker threads", ylabel="speed-up vs 1 worker", title="Speed-up")
    ax[1].set(xlabel="worker threads", ylabel="input MB / second", title="Throughput", ylim=(0, None))
    ax[2].set(xlabel="worker threads", ylabel="CPU busy (% of min(workers, cores))",
              title="Core utilisation", ylim=(0, 105))
    for x in ax:
        x.grid(alpha=.3)
        x.legend()
    fig.tight_layout()
    fig.savefig(out / "speedup.png", dpi=150)
    plt.close(fig)


def plot_latency(a, out):
    s = a[(a.experiment == "scale") & (a.workers == a[a.experiment == "scale"].workers.min())]
    if s.empty:
        return
    s = s.assign(avg_kb=s.input_bytes / s.n_files / 1024).sort_values("avg_kb")
    fig, ax = plt.subplots(1, 2, figsize=(10, 4.2))
    ax[0].loglog(s.avg_kb, s.latency_ms, "o-")
    ax[0].set(xlabel="input size (KB)", ylabel="per-input latency (ms, 1 worker)", title="Latency vs size")
    ax[1].semilogx(s.avg_kb, s.mb_per_s, "o-")
    ax[1].set(xlabel="input size (KB)", ylabel="MB / s (1 worker)", title="Throughput vs size", ylim=(0, None))
    for x in ax:
        x.grid(alpha=.3, which="both")
    fig.tight_layout()
    fig.savefig(out / "latency_vs_size.png", dpi=150)
    plt.close(fig)


def plot_memory(a, out):
    m = a[(a.experiment == "memory") & (a.label != "baseline")].copy()
    if m.empty:
        return
    base_rows = a[(a.experiment == "memory") & (a.label == "baseline")]
    base = base_rows.rss.iloc[0] if not base_rows.empty else 0.0
    m["mb_in"] = m.input_bytes / 1e6
    m = m.sort_values("mb_in")
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.plot(m.mb_in, m.rss, "o-", label="peak RSS")
    ax.plot(m.mb_in, m.mb_in, "k--", lw=1, label="input size (y = x)")
    if base:
        ax.axhline(base, color="gray", ls=":", label=f"empty-run baseline ({base:.0f} MB)")
    ax.set(xlabel="input file size (MB)", ylabel="peak RSS (MB)", title="Peak memory vs input size (1 worker)")
    ax.grid(alpha=.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "memory.png", dpi=150)
    plt.close(fig)


def plot_fetch(a, out):
    f = a[a.experiment == "fetch"]
    if f.empty:
        return
    f = f.set_index("label").loc[[x for x in ["no-fetch", "fetch-unique", "fetch-shared"] if x in set(f.label)]]
    err = [f.wall - f.wall_min, f.wall_max - f.wall]
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    ax.bar(f.index, f.wall, yerr=err, capsize=4, color=["#4c72b0", "#dd8452", "#55a868"][:len(f)])
    ax.set(ylabel="wall time (s)", title="Sub-resource fetching: cost and cache behaviour")
    ax.grid(alpha=.3, axis="y")
    fig.tight_layout()
    fig.savefig(out / "fetch.png", dpi=150)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default="results")
    args = ap.parse_args()
    res = pathlib.Path(args.results)
    df = pd.read_csv(res / "results.csv")
    meta_path = res / "meta.json"
    cpus = json.loads(meta_path.read_text()).get("cpu_count") if meta_path.exists() else None
    a = aggregate(df, cpus)
    out = res / "plots"
    out.mkdir(exist_ok=True)
    plot_scale(a, out)
    plot_latency(a, out)
    plot_memory(a, out)
    plot_fetch(a, out)
    a.round(4).to_csv(res / "summary.csv", index=False)
    with pd.option_context("display.width", 200, "display.max_columns", None):
        print(a.round(3).to_string(index=False))
    print(f"\nplots -> {out}\nsummary -> {res / 'summary.csv'}")


if __name__ == "__main__":
    main()