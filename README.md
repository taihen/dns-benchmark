# DNS Benchmark Tool

[![Test](https://github.com/taihen/dns-benchmark/actions/workflows/test.yml/badge.svg)](https://github.com/taihen/dns-benchmark/actions/workflows/test.yml)
[![Release](https://github.com/taihen/dns-benchmark/actions/workflows/release.yml/badge.svg)](https://github.com/taihen/dns-benchmark/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/taihen/dns-benchmark)](https://goreportcard.com/report/github.com/taihen/dns-benchmark)

## Installation

### Homebrew

```bash
# Add Homebrew tap
brew tap taihen/tap

# Install dns-benchmark
brew install taihen/tap/dns-benchmark

# Update to latest version
brew update
brew upgrade taihen/tap/dns-benchmark
```

### Manual Installation

Download the latest release from the [releases page](https://github.com/taihen/dns-benchmark/releases) or build from source (see [Building](#building) section below).

---

This command-line tool benchmarks the performance and features of DNS resolvers. It helps users identify the fastest and most reliable recursive DNS server for their current network conditions by measuring various metrics across different protocols (UDP, TCP, DoT, DoH, DoQ).

Visit [taihen.org](https://taihen.org) for introductory [announcement](https://taihen.org/posts/dns_benchmarking/).

> [!WARNING]
> **Ethical Querying:** This tool implements safe querying practices (rate limiting, controlled concurrency) to avoid abusing public DNS services. Please use it responsively.

## Features

- **Protocols Supported:**
  - UDP (default)
  - TCP (`tcp://` prefix)
  - DNS over TLS (DoT) (`tls://` prefix)
  - DNS over HTTPS (DoH) (`https://` prefix)
  - DNS over QUIC (DoQ) (`quic://` prefix)
- **Metrics Measured:**
  - **Cached Latency:** Average and Standard Deviation for resolving likely cached domains.
  - **Uncached Latency:** Average and Standard Deviation for resolving unique, likely uncached domains.
  - **Reliability:** Percentage of latency probes that returned a structurally valid DNS response. Unexpected DNS rcodes are reported separately as DNS failures.
  - **.com Latency:** Latency for resolving a random `.com` NXDOMAIN lookup (`-dotcom` flag).
  - **Composite Score:** Weighted blend of uncached (0.50), cached (0.25), and .com (0.25) latency, renormalized when .com is not measured, then divided by effective reliability (probe success rate minus wrong-rcode DNS-failure rate). Lower is better; it is the default ranking key for the table and the recommendation. An unrankable server (no usable samples) shows `N/A` in the console table, an empty cell in CSV, and `null` in JSON.
- **Resolver Checks:**
  - **DNSSEC Validation:** Checks if the resolver validates DNSSEC signatures (`-dnssec` flag, default: false).
  - **NXDOMAIN Hijacking:** Detects if the resolver redirects non-existent domains (`-nxdomain` flag, default: false).
  - **DNS Rebinding Protection:** Checks if the resolver blocks queries for domains resolving to private IPs (`-rebinding` flag, default: false).
  - **Response Accuracy:** Verifies if the resolver returns the expected IP for a known domain (requires `-accuracy-file` flag).
- **Configuration:**
  - Use a built-in list of common public resolvers from Cloudflare, Google, Quad9, OpenDNS, AdGuard, and DNS4EU.
  - Provide a custom list of servers via file (`-f <filename>`), including protocol prefixes.
  - Include system-configured DNS servers (UDP only) (`-system` flag, default: true unless `-f` is used).
  - Adjust number of queries (`-n`, default: 50), timeout (`-t`), concurrency (`-c`), and rate limit (`-rate`).
- **Output:**
  - Formatted console table with results sorted by composite score (lowest first).
  - Console summary recommending the server with the best composite score (a modern-web-weighted blend of uncached, cached, and .com latency, penalized by reliability and DNS-failure rate), with confirmed accuracy when the accuracy check is enabled.
  - CSV output (`-format csv`).
  - JSON output (`-format json`).
  - Option to write output to a file (`-o <filename>`).
- **Interactive Runs:**
  - Live progress line on stderr when attached to a terminal.
  - Ctrl+C stops the benchmark early and reports the results collected so far (exit code 130). Skipped probes are excluded from reliability and score, shown as `skippedQueries` in JSON, and servers that were never probed read `N/A` instead of 0% reliability.
  - Latency probes are interleaved across servers, so an interrupted run still has samples for every server.

## Building

### Quick Start

```bash
# Using Makefile (recommended)
make build

# Or directly with Go
go build -o dns-benchmark ./cmd/main.go
```

### Development Workflow

```bash
# See all available commands
make help

# Build and run
make run

# Run tests
make test

# Format, lint, and test
make check

# Build for all platforms
make build-all
```

This will create an executable named `dns-benchmark` in the current directory.

## Usage

```bash
# Print version information
./dns-benchmark --version

# Print usage help
./dns-benchmark -h

# Run with defaults (UDP, default servers, system DNS)
./dns-benchmark

# Run with custom server list file, 5 queries, 1s timeout
./dns-benchmark -f my_servers.txt -n 5 -t 1s

# Run with defaults, but enable .com check and output to JSON file
./dns-benchmark -dotcom -format json -o results.json

# Run with defaults, enable DNSSEC, NXDomain Hijack and Rebinding checks
./dns-benchmark -dnssec -rebinding -nxdomain

# Run accuracy check using a file (e.g., accuracy.txt containing "mydomain.com 1.2.3.4")
./dns-benchmark -accuracy-file accuracy.txt

# Get help
./dns-benchmark -h
```

## Notes

- DoH requests include a `User-Agent` header: `dns-benchmark/1.0 (+https://github.com/taihen/dns-benchmark)`
- Accuracy check requires a file where each line contains a domain and its expected IP, separated by whitespace. The tool uses the first valid entry found.
- Rebinding check uses a placeholder domain (`private.dns-rebinding-test.com.`); replace this constant in the code if you have a specific test domain resolving to a private IP.
- Results reflect network conditions at the time of the test. Run multiple times for a broader picture.
- Please use responsibly and avoid excessive querying.

## License

[MIT](LICENSE)
