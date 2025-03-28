# DNS Benchmark Tool (Go)

## Overview

This command-line tool benchmarks the performance and features of DNS resolvers. It helps users identify the fastest and most reliable DNS server for their current network conditions by measuring various metrics across different protocols (UDP, TCP, DoT, DoH, DoQ).

The design emphasizes:
*   **Modularity:** Code is separated into packages for configuration, querying, analysis, and output.
*   **Concurrency:** Uses goroutines with rate limiting and concurrency controls to test multiple servers efficiently without overwhelming them.
*   **Accuracy:** Measures key metrics beyond simple latency.
*   **Flexibility:** Supports various protocols and checks via command-line flags and configuration files.
*   **Ethical Querying:** Implements safe querying practices (rate limiting, controlled concurrency) to avoid abusing public DNS services.

## Features / Capabilities

*   **Protocols Supported:**
    *   UDP (default)
    *   TCP (`tcp://` prefix)
    *   DNS over TLS (DoT) (`tls://` prefix)
    *   DNS over HTTPS (DoH) (`https://` prefix)
    *   DNS over QUIC (DoQ) (`quic://` prefix)
*   **Metrics Measured:**
    *   **Cached Latency:** Average and Standard Deviation for resolving likely cached domains.
    *   **Uncached Latency:** Average and Standard Deviation for resolving unique, likely uncached domains.
    *   **Reliability:** Percentage of successful latency queries.
    *   **.com Latency (Optional):** Latency for resolving a unique `.com` domain (`-dotcom` flag).
*   **Resolver Checks:**
    *   **DNSSEC Validation:** Checks if the resolver validates DNSSEC signatures (`-dnssec` flag, default: true).
    *   **NXDOMAIN Hijacking:** Detects if the resolver redirects non-existent domains (`-nxdomain` flag, default: true).
    *   **DNS Rebinding Protection:** Checks if the resolver blocks queries for domains resolving to private IPs (`-rebinding` flag, default: true).
    *   **Response Accuracy:** Verifies if the resolver returns the expected IP for a known domain (requires `-accuracy-file` flag).
*   **Configuration:**
    *   Use built-in list of common public resolvers (Cloudflare, Google, Quad9).
    *   Provide a custom list of servers via file (`-f <filename>`), including protocol prefixes.
    *   Include system-configured DNS servers (UDP only) (`-system` flag, default: true unless `-f` is used).
    *   Adjust number of queries (`-n`), timeout (`-t`), concurrency (`-c`), and rate limit (`-rate`).
*   **Output:**
    *   Formatted console table with results sorted by uncached latency.
    *   Console summary recommending the fastest reliable server and highlighting potential issues.
    *   CSV output (`-format csv`).
    *   JSON output (`-format json`).
    *   Option to write output to a file (`-o <filename>`).

## Building

```bash
go build ./cmd/main.go
```

## Usage

```bash
# Run with defaults (UDP, default servers, system DNS)
./main

# Run with custom server list file, 5 queries, 1s timeout
./main -f my_servers.txt -n 5 -t 1s

# Run with defaults, but enable .com check and output to JSON file
./main -dotcom -format json -o results.json

# Run with defaults, disable DNSSEC check
./main -dnssec=false

# Run accuracy check using a file (e.g., accuracy.txt containing "mydomain.com 1.2.3.4")
./main -accuracy-file accuracy.txt

# Get help
./main -h
```

## Notes

*   DoH requests include a `User-Agent` header: `dns-benchmark/1.0 (+https://github.com/taihen/dns-benchmark)`
*   Accuracy check requires a file where each line contains a domain and its expected IP, separated by whitespace. The tool uses the first valid entry found.
*   Rebinding check uses a placeholder domain (`private.dns-rebinding-test.com.`); replace this constant in the code if you have a specific test domain resolving to a private IP.
*   Results reflect network conditions at the time of the test. Run multiple times for a broader picture.
*   Please use responsibly and avoid excessive querying.
