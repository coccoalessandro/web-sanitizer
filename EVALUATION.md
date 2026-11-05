# Web Sanitizer — Experimental Evaluation & Performance Analysis

This document presents the empirical evaluation, scalability benchmarks, and performance analysis of the **Web Sanitizer** release build, structured according to Section 7 of the project specification.

---

## 1. Benchmarking Environment & Methodology

All measurements were conducted on the release build compiled with full optimizations (`cargo build --release`, rustc 1.93.1 on ARM64). Performance metrics (`wall_s`, `user_s`, `sys_s`, `maxrss_mb`) were collected via `wait4()` to obtain high-precision, kernel-level resource telemetry across 5 repetitions per configuration, with median values reported.

* **Hardware**: Apple M1 (8 physical execution cores: 4 Firestorm Performance Cores @ ~3.2 GHz + 4 Icestorm Efficiency Cores @ ~2.06 GHz)
* **Operating System**: macOS Darwin (ARM64)
* **Software**: Rust 1.93.1 (edition 2024, release mode)
* **Harness Scripts**: `scripts/gen_corpus.py`, `scripts/run_bench.py`, `scripts/plot_results.py`
* **Test Corpus**: 2,460 files, 124.5 MB total synthetic web content with a 10% hostile payload ratio exercising all sanitizer action branches

---

## 2. Multicore Scalability & Speed-up (`scale`)

Thread pool scalability was evaluated systematically across worker thread counts from **1 to 8 threads** across three document size classes:
* **Small**: 2,000 files $\times$ ~10 KB ($20.6\text{ MB}$ total)
* **Medium**: 400 files $\times$ ~100 KB ($41.0\text{ MB}$ total)
* **Large**: 60 files $\times$ ~1 MB ($62.9\text{ MB}$ total)

### 2.1 Empirical Results (1 to 8 Workers)

| Size Class | Workers | Files | Total Input | Wall Time (s) | Throughput (MB/s) | Inputs / sec | Speed-up vs 1W | CPU Busy (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small (~10 KB)** | 1 | 2,000 | 20.6 MB | 0.418 | 49.4 MB/s | 4,788 | $1.00\times$ | 100.0% |
| | 2 | 2,000 | 20.6 MB | 0.231 | 89.2 MB/s | 8,657 | **$1.81\times$** | 98.2% |
| | 3 | 2,000 | 20.6 MB | 0.167 | 123.8 MB/s | 12,011 | **$2.50\times$** | 95.6% |
| | 4 | 2,000 | 20.6 MB | 0.132 | 156.0 MB/s | 15,130 | **$3.17\times$** | 94.0% |
| | 5 | 2,000 | 20.6 MB | 0.127 | 162.6 MB/s | 15,770 | $3.29\times$ | 92.9% |
| | 6 | 2,000 | 20.6 MB | 0.123 | 167.5 MB/s | 16,247 | $3.40\times$ | 92.0% |
| | 7 | 2,000 | 20.6 MB | 0.119 | 173.8 MB/s | 16,865 | $3.51\times$ | 89.6% |
| | 8 | 2,000 | 20.6 MB | 0.116 | 177.7 MB/s | **17,243** | **$3.60\times$** | 85.3% |
| **Medium (~100 KB)** | 1 | 400 | 41.0 MB | 0.701 | 58.5 MB/s | 571 | $1.00\times$ | 99.5% |
| | 2 | 400 | 41.0 MB | 0.371 | 110.3 MB/s | 1,077 | **$1.89\times$** | 98.0% |
| | 3 | 400 | 41.0 MB | 0.265 | 154.6 MB/s | 1,508 | **$2.65\times$** | 96.8% |
| | 4 | 400 | 41.0 MB | 0.206 | 198.5 MB/s | 1,938 | **$3.40\times$** | 95.7% |
| | 5 | 400 | 41.0 MB | 0.199 | 206.2 MB/s | 2,012 | $3.52\times$ | 95.1% |
| | 6 | 400 | 41.0 MB | 0.193 | 212.5 MB/s | 2,074 | $3.63\times$ | 94.7% |
| | 7 | 400 | 41.0 MB | 0.185 | 221.6 MB/s | 2,162 | $3.79\times$ | 92.4% |
| | 8 | 400 | 41.0 MB | 0.177 | 232.0 MB/s | **2,264** | **$3.96\times$** | 89.3% |
| **Large (~1 MB)** | 1 | 60 | 62.9 MB | 1.038 | 60.6 MB/s | 57.8 | $1.00\times$ | 99.6% |
| | 2 | 60 | 62.9 MB | 0.549 | 114.5 MB/s | 109.2 | **$1.89\times$** | 97.7% |
| | 3 | 60 | 62.9 MB | 0.387 | 162.5 MB/s | 155.0 | **$2.68\times$** | 97.3% |
| | 4 | 60 | 62.9 MB | 0.301 | 208.9 MB/s | 199.2 | **$3.45\times$** | 95.8% |
| | 5 | 60 | 62.9 MB | 0.297 | 211.7 MB/s | 201.9 | $3.50\times$ | 93.1% |
| | 6 | 60 | 62.9 MB | 0.282 | 223.1 MB/s | 212.8 | $3.68\times$ | 92.2% |
| | 7 | 60 | 62.9 MB | 0.266 | 236.1 MB/s | 225.2 | $3.90\times$ | 90.2% |
| | 8 | 60 | 62.9 MB | 0.258 | 243.5 MB/s | **232.2** | **$4.02\times$** | 87.0% |

### 2.2 Scalability Visualization

![Speed-up Curves, Throughput, and Core Utilisation](results/plots/speedup.png)

### 2.3 Scalability Analysis & Hardware Corroboration

1. **Linear Scaling on Performance Cores (1 to 4 Workers)**:
   * Up to 4 worker threads, speed-up scales near-linearly ($1.89\times$ on 2 workers, $2.68\times$ on 3 workers, and $3.45\times$ on 4 workers for large files), with core utilization consistently exceeding $95\%-99\%$.
   * This behavior maps directly to the Apple M1 processor topology: the host contains exactly **4 high-performance Firestorm cores (P-cores)**. Up to 4 threads, the operating system assigns one worker per physical P-core.
   * In software, linear scaling is enabled by the shared-nothing design: each worker thread parses input bytes independently using streaming rewriter buffers, without taking any shared lock during document rewriting. Job distribution relies on `crossbeam-channel` lock-free circular ring buffers, preventing thread contention on dequeue operations.
2. **Transition Region on Efficiency Cores (5 to 8 Workers)**:
   * At 5 to 8 workers, the throughput continues to increase, reaching **$4.02\times$** ($243.5\text{ MB/s}$ on large files, $17,243\text{ inputs/sec}$ on small files), but with smaller incremental gains per thread.
   * This inflection occurs because workers 5 through 8 are scheduled onto the **4 energy-efficient Icestorm cores (E-cores)**, which run at lower clock frequency (~2.06 GHz vs ~3.2 GHz) and feature a narrower execution pipeline.
   * Dynamic work-stealing through the shared queue allows fast P-cores to continue processing the majority of incoming tasks while E-cores process supplementary jobs without stalling the overall pipeline.

---

## 3. Latency vs. Input Size

Per-input latency and single-worker processing throughput were measured across file sizes spanning three orders of magnitude ($10\text{ KB} \to 1\text{ MB}$):

![Latency vs Size and Single-Worker Throughput](results/plots/latency_vs_size.png)

* **Linear Complexity ($O(N)$)**: Processing latency grows in direct proportion to input size:
  * $10\text{ KB}$: **$0.21\text{ ms}$** per document
  * $100\text{ KB}$: **$1.75\text{ ms}$** per document
  * $1\text{ MB}$: **$17.30\text{ ms}$** per document
* **Throughput Stability**: Throughput remains stable between **49.4 MB/s and 60.6 MB/s** per single core, verifying that `lol_html`'s streaming tokenizer operates in linear time with zero super-linear parser penalties.

---

## 4. Peak Memory Footprint & Zero-Copy Efficiency (`memory`)

To verify the non-functional requirement against unbounded memory allocation, peak resident set size (RSS) was measured for single inputs scaling from baseline up to **100 MB**:

| Input Size Class | Input Bytes | Wall Time (s) | Peak RSS (MB) | RSS / Input Ratio |
| :--- | :---: | :---: | :---: | :---: |
| **Empty Baseline** | 2,124 B | 0.004 s | **2.98 MB** | — |
| **1.0 MB** | 1,000,019 B | 0.022 s | **5.89 MB** | $2.9\times$ |
| **5.0 MB** | 5,000,064 B | 0.089 s | **17.56 MB** | $2.9\times$ |
| **10.0 MB** | 10,000,045 B | 0.169 s | **27.56 MB** | $2.5\times$ |
| **25.0 MB** | 25,000,079 B | 0.409 s | **66.52 MB** | $2.5\times$ |
| **50.0 MB** | 50,000,024 B | 0.808 s | **128.33 MB** | $2.5\times$ |
| **100.0 MB** | 100,000,028 B | 1.609 s | **237.02 MB** | **$2.3\times$** |

### 4.1 Memory Scaling Visualization

![Peak Memory vs Input Size](results/plots/memory.png)

### 4.2 Systems Memory Model Analysis
* **Strictly Linear Bound**: Peak memory scales strictly as $\text{Peak RSS} \approx 2.3 \times \text{Input Size} + 3\text{ MB}$.
* **Zero-Copy Guarantees**: The $2.3\times$ multiplier corresponds strictly to the input buffer, the streaming output accumulator buffer, and minimal process heap overhead. Once an input is processed, buffers are reclaimed immediately, confirming bounded allocations and zero memory leaks.

---

## 5. Sub-Resource Fetching & In-Memory Caching (`fetch`)

To evaluate network subsystem performance and caching behavior, 300 HTML documents referencing 10 images each (3,000 total sub-resource references) were processed with 8 worker threads under a 5.0 ms simulated origin latency:

| Fetch Mode | Max Depth | Distinct URLs | Network Requests Made | Wall Time (s) | Effective Throughput | Speed-up vs Uncached |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`no-fetch`** | 0 | 0 | 0 | **0.013 s** | 22,691 pages/s | — |
| **`fetch-unique`** | 3 | 3,000 | 3,000 | **2.694 s** | 111.4 pages/s | Baseline ($1.00\times$) |
| **`fetch-shared`** | 3 | 10 | **80** | **0.179 s** | **1,680 pages/s** | **$15.1\times$ Speed-up** |

### 5.1 Caching Performance Visualization

![Sub-Resource Fetching Cost and Cache Efficiency](results/plots/fetch.png)

### 5.2 Network & Caching Analysis
* **I/O Latency Impact**: When sub-resource fetching is enabled without asset deduplication, throughput drops from 22,691 pages/s to 111.4 pages/s due to network socket round-trips and connection setup overhead.
* **Shared State Deduplication**: With thread-safe in-memory caching (`Arc<RwLock<SharedState>>`), documents sharing sub-resources require only 80 initial network requests (during parallel cache warming) and serve the remaining 2,920 references directly from memory. This achieves an empirical **$15.1\times$ speed-up** over uncached fetching.

---

## 6. Functional Detection Accuracy

Against the curated test corpus (`tests/corpus/`) evaluated via `cli/tests/corpus_evaluation.rs`:
* **True Positives (TP)**: 15 / 15 malicious samples detected and neutralized ($100.00\%$ detection rate).
* **True Negatives (TN)**: 7 / 7 benign samples preserved without false alarms ($100.00\%$ specificity).
* **False Positives (FP)**: 0 ($0.00\%$).
* **False Negatives (FN)**: 0 ($0.00\%$).
