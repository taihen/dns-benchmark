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
  - UDP (default for bare custom addresses)
  - TCP (`tcp://` prefix)
  - DNS over TLS (DoT) (`tls://` prefix)
  - DNS over HTTPS (DoH) (`https://` prefix)
  - DNS over QUIC (DoQ) (`quic://` prefix)
- **Metrics Measured:**
  - **Cached Latency:** Average and Standard Deviation for resolving likely cached domains.
  - **Uncached Latency:** Average and Standard Deviation for resolving unique, likely uncached domains.
  - **Reliability:** Percentage of latency probes that returned a structurally valid DNS response. Unexpected DNS rcodes are reported separately as DNS failures.
  - **.com Latency:** Latency for resolving a random `.com` NXDOMAIN lookup (`-dotcom` flag).
  - **Composite Score:** Weighted blend of uncached (0.50), cached (0.25), and .com (0.25) latency, renormalized when .com is not measured, then divided by effective reliability (probe success rate minus wrong-rcode DNS-failure rate). Lower is better; it ranks results within matching filtering-policy, role, ECS, transport, and IP-family groups. An unrankable server (no usable samples) shows `N/A` in the console table, an empty cell in CSV, and `null` in JSON.
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
  - Formatted console table grouped by policy and transport, with composite scores sorted within each group.
  - Console recommendations for each policy/transport/family group, with confirmed accuracy when the accuracy check is enabled.
  - CSV output (`-format csv`).
  - JSON output (`-format json`).
  - Option to write output to a file (`-o <filename>`).
- **Interactive Runs:**
  - Live progress line on stderr when attached to a terminal.
  - Ctrl+C stops the benchmark early and reports the results collected so far (exit code 130). Skipped probes are excluded from reliability and score, shown as `skippedQueries` in JSON, and servers that were never probed read `N/A` instead of 0% reliability.
  - Latency probes are interleaved across servers, so an interrupted run still has samples for every server.


## Resolver catalogue and selection

The embedded [catalogue](pkg/catalog/resolvers.json) contains 30 profiles from
Cloudflare, Google, Quad9, OpenDNS, AdGuard, DNS4EU, Control D, CleanBrowsing,
DNS.SB, and DNS.WATCH. Profiles carry roles, filtering policy, ECS and DNSSEC
claims, source URLs, review dates, and lifecycle status. Claims describe provider
policy; they are not benchmark observations. Unknown claims remain `unknown`.
The catalogue contains one primary address per family, rather than every backup
address. DNS.WATCH has no encrypted endpoints; the additional OpenDNS profiles
currently include DoH and Do53 while their DoT documentation awaits verification.

The default `-preset legacy` retains six providers and 18 IPv4 UDP/DoT/DoH
endpoints, plus system DNS unless disabled. Other presets select profiles by role:
`general`, `security`, `family`, and `extended`. General profiles can still have
legal blocking requirements (DNS4EU uses `legal-only`), so their scores stay in a
separate policy group. Quad9 ECS variants retain their own ECS dimension.

```bash
# General-purpose IPv4 DoH profiles
./dns-benchmark -preset general -transports doh -ip-family ipv4 -system=false

# One family profile over IPv6, with documented policy probes
./dns-benchmark -profile cloudflare-family -transports udp,dot,doh -ip-family ipv6 -filtering -system=false

# Explicitly opt into the full catalogue, including documented DoQ endpoints
./dns-benchmark -preset extended -system=false
```

`-profile` accepts comma-separated stable profile IDs and overrides the preset.
`-transports` accepts `udp,tcp,dot,doh,doq`. DoQ is distinct from HTTP/3; HTTP/3 and
DNSCrypt are not implemented. `-ip-family auto` selects both families for explicit
catalogue selections; the legacy default selects IPv4. DoH connects directly to
its URL hostname using the selected family, without an HTTP proxy; DoT and DoQ
connect to catalogue IPs while authenticating documented TLS hostnames.

Existing `-f` files still accept IPs, hostnames, IPv6 literals, ports, and the
`udp://`, `tcp://`, `tls://`, `https://`, and `quic://` prefixes. File entries carry
`custom` provider/profile metadata. Unknown schemes and invalid ports are now
rejected with a warning instead of being silently reinterpreted. `-f` disables
system DNS and cannot be combined with explicit catalogue profiles or presets.

All endpoints receive the same randomly generated latency query corpus. Shared
caches can still influence measurements; random names are only *likely* uncached.
There are no warm-up queries. Connection establishment contributes to measured
latency, and reusable DoH/DoQ connections may benefit later probes. All probes use
the configured global rate limiter. Truncated replies are counted explicitly and
excluded from latency scoring; no uncounted TCP fallback is sent.

DNSSEC only reports validation failure evidence when a bogus-domain SERVFAIL has
a DNSSEC-related Extended DNS Error. Generic SERVFAIL is inconclusive. NXDOMAIN
checks use two reserved-domain names and recognize CNAME redirects. Rebinding
requires `-rebinding-domain` pointing to a controlled domain expected to return
private addresses; without it the result remains inconclusive and no probe is
sent. Accuracy files accept `domain IP[,IP...]` (first valid line), including IPv6;
the first expected address chooses A or AAAA. `-filtering` currently uses
Cloudflare's documented malware/adult test domains for its matching profiles;
profiles without documented probes report `not_applicable`. Policy probes never
contribute latency samples.

JSON schema version **2** changes the top-level array to an envelope:

```json
{"schemaVersion":"2","metadata":{"timestamp":"...","queryCorpusId":"sha256:...","requestedQueryCount":50,"skippedCount":0,"interrupted":false},"results":[]}
```

Each result includes provider, profile, roles, endpoint ID, family, transport,
TLS name, catalogue version, source URLs, comparison group, explicit probe states
(`pass`, `fail`, `inconclusive`, `not_applicable`), and separate truncation,
transport, timeout, malformed-response, RCODE, and EDE policy counters. Existing
boolean check fields remain compatibility aliases. CSV appends identity, policy,
probe state, and skipped-query columns after the existing metric columns.
Machine-readable stdout contains only JSON or CSV; progress goes to stderr.

Catalogue validation runs in the regular test suite, rejects active entries older
than 366 days, and excludes deprecated entries from selection. Tests use local
UDP, TCP, TLS, HTTPS, and QUIC fixtures; they do not query public resolvers. CI
uses the toolchain in `go.mod` and checks formatting, vet, race tests, and module
tidiness without updating module files. Public endpoint reachability is not
established by local fixture tests.

## Building

Requires Go 1.26 or later (the exact minimum is recorded in `go.mod`).

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

# Run with defaults (18 UDP/DoT/DoH endpoints, plus system DNS)
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
- Accuracy check requires a file where each line contains a domain and its expected IPs (comma-separated), separated by whitespace. The tool uses the first valid entry found.
- Rebinding checks require `-rebinding-domain` with a controlled domain expected to resolve to private addresses.
- Results reflect network conditions at the time of the test. Run multiple times for a broader picture.
- Please use responsibly and avoid excessive querying.

## License

[MIT](LICENSE)
