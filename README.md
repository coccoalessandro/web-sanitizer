# Web Sanitizer

A defensive web content sanitization engine and CLI written in Rust. It intercepts, parses, and cleans untrusted HTML and embedded assets before they reach the client, protecting against XSS, SSRF, MIME confusion, IDN homographs, and resource exhaustion.

## Quick Start

### Build
```bash
cargo build --workspace
```

### Run CLI
```bash
# Sanitize a local HTML file using the default Balanced profile
cargo run --bin cli -- --files path/to/page.html

# Sanitize remote URLs using the Strict security profile
cargo run --bin cli -- --urls "https://example.com" --profile strict
```

### Run Engine Demo
```bash
cargo run --bin engine
```

---

## Workspace Layout

```
web-sanitizer/
├── cli/                 # Command-line interface frontend
│   └── src/main.rs      # Argument parsing, profile selection, batch execution
├── engine/              # Reusable sanitization library
│   └── src/
│       ├── lib.rs       # Library crate root
│       ├── policy.rs    # Declarative security policies and presets
│       ├── parser.rs    # Streaming HTML rewriting with lol_html
│       ├── network.rs   # Anti-SSRF fetcher with MIME sniffing
│       ├── pipeline.rs  # Multithreaded batch pipeline with crossbeam channels
│       ├── report.rs    # Structured audit reports & actions
│       └── main.rs      # Engine test driver
```

---
