# DNS Benchmark Tool

[![Test](https://github.com/taihen/dns-benchmark/actions/workflows/test.yml/badge.svg)](https://github.com/taihen/dns-benchmark/actions/workflows/test.yml)
[![Release](https://github.com/taihen/dns-benchmark/actions/workflows/release.yml/badge.svg)](https://github.com/taihen/dns-benchmark/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/taihen/dns-benchmark)](https://goreportcard.com/report/github.com/taihen/dns-benchmark)

This command-line tool benchmarks the performance and features of DNS resolvers. It helps users identify the fastest and most reliable reqursive DNS server for their current network conditions by measuring various metrics across different protocols (UDP, TCP, DoT, DoH, DoQ).

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
  - **Reliability:** Percentage of successful latency queries.
  - **.com Latency:** Latency for resolving a unique `.com` domain (`-dotcom` flag).
- **Resolver Checks:**
  - **DNSSEC Validation:** Checks if the resolver validates DNSSEC signatures (`-dnssec` flag, default: false).
  - **NXDOMAIN Hijacking:** Detects if the resolver redirects non-existent domains (`-nxdomain` flag, default: false).
  - **DNS Rebinding Protection:** Checks if the resolver blocks queries for domains resolving to private IPs (`-rebinding` flag, default: false).
  - **Response Accuracy:** Verifies if the resolver returns the expected IP for a known domain (requires `-accuracy-file` flag).
- **Configuration:**
  - Use built-in list of common public resolvers (Cloudflare, Google, Quad9, Adguard).
  - Provide a custom list of servers via file (`-f <filename>`), including protocol prefixes.
  - Include system-configured DNS servers (UDP only) (`-system` flag, default: true unless `-f` is used).
  - Adjust number of queries (`-n`, default: 4), timeout (`-t`), concurrency (`-c`), and rate limit (`-rate`).
- **Output:**
  - Formatted console table with results sorted by uncached latency.
  - Console summary recommending the fastest reliable server and highlighting potential issues.
  - CSV output (`-format csv`).
  - JSON output (`-format json`).
  - Option to write output to a file (`-o <filename>`).

## Building

```bash
go build -o dns-benchmark ./cmd/main.go
```

This will create an executable named `dns-benchmark` in the current directory.

## Usage

```bash
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