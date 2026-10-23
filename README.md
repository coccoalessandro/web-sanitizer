# Web Sanitizer

A defensive web content sanitiser written in Rust: a reusable library crate (`engine`) and a
command-line front-end (`cli`). It parses untrusted HTML and embedded assets, neutralises
malicious constructs according to a declarative policy, and emits a machine-readable JSON
audit report for every input.

Defends against XSS, dangerous URI schemes, IDN homographs and Unicode Host-Split confusion,
active documents (JavaScript in PDF/SVG), image and XML bombs, MIME confusion and SSRF.

## Requirements

- Rust **1.88** or newer (edition 2024)
- Python 3.9+ with `pandas` and `matplotlib`, only for the benchmark scripts

## Build and test

```bash
cargo build --workspace
cargo test --workspace
```

The corpus evaluation (detection rate and false-positive rate against
`tests/corpus/ground_truth.json`) prints its summary table with:

```bash
cargo test -p cli --test corpus_evaluation -- --nocapture
```

## Usage

```bash
# Sanitise local files with the default Balanced profile
cargo run --bin cli -- -f path/to/page.html

# Sanitise a whole directory tree, write cleaned outputs and per-input reports
cargo run --bin cli -- -d path/to/dir -o out/ --report-file report.json

# Remote URLs with the Strict profile, verbose per-action audit
cargo run --bin cli -- -u https://example.com -p strict -v

# Custom policy from a JSON file (takes precedence over --profile)
cargo run --bin cli -- -f page.html -c config.json
```

Main options (`cargo run --bin cli -- --help` for the full list):

| Option | Meaning |
|---|---|
| `-f`, `-d`, `-u` | input files, directories (recursive), URLs; repeatable |
| `-p strict\|balanced\|relaxed` | built-in security profile (default: balanced) |
| `-c <file>` | JSON policy file |
| `-o <dir>` | write cleaned outputs and per-input `.report.json` |
| `--report-file <file>` | aggregated JSON report for the whole batch |
| `-w <n>` | worker threads (default: available parallelism) |
| `-q` / `-v` / `--json-only` | output verbosity |

Every policy field can also be overridden from the command line
(e.g. `--max-fetch-depth 0`, `--block-internal-ips false`).

Refused inputs are never written to the output directory: a `.refused.txt` notice and the
JSON report are written instead.

**Exit codes:** `0` all inputs processed and none refused; `1` at least one input was refused
or failed; `2` invalid command line.

Library demo:

```bash
cargo run -p engine --example demo
```

## Evaluation

### Security scenarios (evil-origin)

The course-provided `evil-origin` Docker image serves the attack scenarios on port 3100
(see the testing guide). Since the server runs on `localhost`, the internal-IP SSRF guard
must be disabled for this run; SSRF blocking is covered by the unit tests in
`engine/src/network.rs` and `engine/src/pipeline.rs`.

```bash
docker load -i evil-origin.tar
docker run -d -p 3100:3100 --name evil-origin evil-origin
cargo run --bin cli -- -u http://localhost:3100/html/script-tag [-u ...] \
    --block-internal-ips false -o out/ --report-file report.json -v
```

### Performance benchmarks

Synthetic, deterministic corpus (generated, not versioned) and benchmark harness in `scripts/`:

```bash
cargo build --release
python3 scripts/gen_corpus.py --out corpus_perf
python3 scripts/run_bench.py --corpus corpus_perf      # -> results/results.csv, results/meta.json
python3 scripts/plot_results.py --results results      # -> results/plots/*.png, results/summary.csv
```

Experiments: worker-count sweep per input size class (speed-up, throughput, latency), peak RSS
vs input size, and sub-resource fetching against a local asset server. Always benchmark the
release build.

## Workspace layout

```
web-sanitizer/
├── engine/                     # Reusable sanitisation library
│   ├── src/
│   │   ├── lib.rs              # Crate root and HTML rule tests
│   │   ├── policy.rs           # Declarative policies and built-in profiles
│   │   ├── parser.rs           # Streaming HTML rewriting (lol_html)
│   │   ├── url_sanitizer.rs    # URL schemes, block-lists, IDN, Host-Split
│   │   ├── css.rs              # Inline style and <style> sanitisation
│   │   ├── active_content.rs   # PDF/SVG active content, image and XML bombs
│   │   ├── network.rs          # Sub-resource fetching, SSRF and MIME defences
│   │   ├── pipeline.rs         # Worker pool, channels, shared state
│   │   └── report.rs           # Audit report types
│   └── examples/demo.rs        # Minimal library usage example
├── cli/
│   ├── src/main.rs             # Argument parsing, batch execution, outputs
│   └── tests/                  # CLI integration tests and corpus evaluation
├── tests/corpus/               # Benign and malicious samples + ground_truth.json
├── scripts/                    # Benchmark corpus generator, harness, plots
└── config.json                 # Example policy file
```