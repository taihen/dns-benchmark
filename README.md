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
  - **Uncached Latency:** Average and Standard Deviation for resolving random names that are unique per endpoint and per run, so they are likely uncached.
  - **Reliability:** Percentage of latency probes that returned a structurally valid DNS response. Unexpected DNS rcodes are reported separately as DNS failures.
  - **.com Latency:** Latency for resolving a random `.com` NXDOMAIN lookup (`-dotcom` flag). A server whose probe fails (any answer other than NXDOMAIN) or is inconclusive (timeout, transport error, truncation) is reported with a warning and is never recommended, since the missing sample would otherwise drop out of its score.
  - **Composite Score:** Weighted blend of uncached (0.50), cached (0.25), and .com (0.25) latency, renormalized when .com is not measured, then divided by effective reliability (probe success rate minus wrong-rcode DNS-failure rate). Lower is better; it ranks catalogue results across providers within each transport and IP-family group, alongside each result's filtering policy. An unrankable server (no usable samples) shows `N/A` in the console table, an empty cell in CSV, and `null` in JSON.
- **Resolver Checks:**
  - **DNSSEC Validation:** Checks if the resolver rejects a deliberately broken signed domain, using a correctly signed control domain (`-dnssec` flag, default: false).
  - **NXDOMAIN Hijacking:** Detects if the resolver redirects non-existent domains (`-nxdomain` flag, default: false).
  - **DNS Rebinding Protection:** Checks if the resolver strips private A and AAAA answers (`-rebinding` flag, default: false; requires `-rebinding-domain`). Confirming protection needs at least one tested resolver that passes the private answer through.
  - **Response Accuracy:** Verifies if the resolver returns the expected IP for a known domain (requires `-accuracy-file` flag). A missing or unreadable file, or one with no valid entry, is an error.
- **Configuration:**
  - Use a built-in list of common public resolvers from Cloudflare, Google, Quad9, OpenDNS, AdGuard, and DNS4EU.
  - Provide a custom list of servers via file (`-f <filename>`), including protocol prefixes.
  - Include system-configured DNS servers (UDP only) (`-system` flag, default: true unless `-f` is used).
  - Adjust number of queries (`-n`, default: 50), timeout (`-t`), concurrency (`-c`), and rate limit (`-rate`).
- **Output:**
  - Formatted console table grouped by transport and IP family, with composite scores sorted within each group. Custom and system endpoints keep score-only ordering.
  - Console recommendations: the fastest endpoint per transport and IP family (naming its filtering policy), plus the fastest like-for-like endpoint for each policy, role, ECS, transport and family group with at least two members. Accuracy (with `-accuracy-file`) and a successful `.com` probe (with `-dotcom`) are required for a recommendation. Failed and inconclusive checks are warned about for every server, including the recommended one; the console shows `Inconclusive` for an enabled check without conclusive evidence.
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
endpoints, plus system DNS unless disabled. The `general`, `security` and
`family` presets select profiles with that role; `extended` selects every active
profile, including the `ads` and `social` profiles that no role preset covers. General profiles can still have
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
`-transports` accepts `udp,tcp,dot,doh,doq`. It defaults to `udp,dot,doh` for the
`legacy`, `general`, `security` and `family` presets, and to all five transports
for `extended` and `-profile` selections. DoQ is distinct from HTTP/3; HTTP/3 and
DNSCrypt are not implemented. `-ip-family auto` selects both families for explicit
catalogue selections; the legacy default selects IPv4. DoH connects directly to
its URL hostname using the selected family, without an HTTP proxy; DoT and DoQ
connect to catalogue IPs while authenticating documented TLS hostnames.

Existing `-f` files still accept IPs, hostnames, IPv6 literals, ports, and the
`udp://`, `tcp://`, `tls://`, `https://`, and `quic://` prefixes. File entries carry
`custom` provider/profile metadata. As before, an unrecognised scheme (for example
`dns://1.2.3.4`) is treated as UDP and a non-numeric port (including a negative
one such as `:-1`) falls back to the protocol default, each with a warning.
Entries that could never have been benchmarked as written are now rejected
instead of being repaired with a warning: `http://` entries, ports outside 1–65535
(such as `:0`), bracketed IPv4 literals (`[1.2.3.4]`), extra-colon forms such as
`host:1:2`, and DoH URLs with user info (`https://user@host/...`), a `#fragment`,
or an out-of-range port. `-f` disables
system DNS and cannot be combined with explicit catalogue profiles or presets.
System resolvers that are already selected catalogue endpoints (for example
`1.1.1.1`) are benchmarked once, as the catalogue entry.

All endpoints receive the same latency workload: one randomly generated corpus of
name templates per run (identified by `queryCorpusId`). Each uncached template is
made unique per endpoint, so endpoints that share a provider cache (other
transports or address families) cannot warm each other's "uncached" names. Random
names are still only *likely* uncached.
Before measuring, each endpoint receives one warm-up query for the cached domain.
It is not scored, it goes through the rate limiter, and the total is reported as
`warmupQueryCount`. Without it, the first cached sample would carry the DoH/DoQ
handshake and possibly the cache miss that fills the resolver cache. Later DoQ
queries, including concurrent ones, share the warmed QUIC session on separate
streams; DoH reuses the client's keep-alive connections (HTTP/2 multiplexes
concurrent requests), though with HTTP/1.1 a concurrent request may still open a
new connection. DoT and TCP open a connection per query, so their samples
always include connection setup. All probes use
the configured global rate limiter. Truncated replies count as failed
probes in their own counter, are not used as latency samples or check evidence, and
no uncounted TCP fallback is sent.

DNSSEC queries the bogus domain `dnssec-failed.org` and a correctly signed
control domain, `ietf.org`. NOERROR for the bogus domain means no validation.
SERVFAIL counts as validation when it carries a DNSSEC-related Extended DNS Error,
or when the same resolver answers the control domain with NOERROR and records;
otherwise it is inconclusive, since a resolver that fails every query also returns
SERVFAIL. NXDOMAIN checks use two reserved-domain names and recognize CNAME
redirects. Rebinding requires `-rebinding-domain` pointing to a controlled domain
with private A and/or AAAA records; `-rebinding` without it is rejected. Both A and
AAAA are queried: a private, loopback or link-local address on either fails the
check. NOERROR without address records counts as protection only for a record type
that at least one other tested server passed through, which proves the domain
really serves that private record; a lapsed domain answers NOERROR without records
too. If no tested server passes the answer through, every server is inconclusive
and the summary says so; include a resolver without rebinding protection to
confirm the domain. Public-only answers, NXDOMAIN and REFUSED are inconclusive,
since a misconfigured or mistyped domain or a refusing resolver produces them too.
Accuracy files accept `domain IP[,IP...]` (first valid line), including IPv6. A is
queried when any expected address is IPv4 and AAAA when any is IPv6; a match on
either record type counts as accurate. `-filtering` currently uses
Cloudflare's documented malware/adult test domains for its matching profiles;
profiles without documented probes report `not_applicable`. Policy probes never
contribute latency samples.

**Breaking change:** JSON schema version **2** changes the top-level array to an
envelope. Consumers that read the old array (for example `jq '.[0]'`) should read
`.results` instead:

```json
{"schemaVersion":"2","metadata":{"startedAt":"...","queryCorpusId":"sha256:...","requestedQueryCount":50,"skippedCount":0,"warmupQueryCount":18,"interrupted":false},"results":[]}
```

Each result includes provider, profile, roles, endpoint ID, family, transport,
TLS name, catalogue version, source URLs, comparison group (empty for custom and
system endpoints), explicit probe states
(`pass`, `fail`, `inconclusive`, `not_applicable`), and separate truncation,
transport, timeout, malformed-response, RCODE, and EDE policy counters. Existing
boolean check fields remain compatibility aliases. `serverAddress` (and the first
CSV column) keeps the protocol-prefixed form accepted by `-f`, for example
`1.1.1.1:53`, `tls://one.one.one.one:853` or a DoH URL; use `endpointId` to tell
apart catalogue endpoints that share an address string across IP families. CSV appends identity, policy,
probe state (including `DotcomState`), and skipped-query columns after the existing metric and check columns.
Machine-readable stdout contains only JSON or CSV; progress goes to stderr.

Catalogue structure is validated on every load. Review freshness is a maintenance
check: a scheduled CI workflow fails once an active entry is older than 366 days
or dated in the future (run it locally with
`DNSBENCH_CHECK_CATALOG_FRESHNESS=1 go test -run TestCatalogFreshness ./pkg/catalog`).
It is not part of the per-PR test run, so an ageing catalogue does not block
unrelated changes. The binary only prints a warning to stderr and keeps running. Deprecated entries are
excluded from selection. Tests use local
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
# (private.example.net stands for a domain you control that resolves to a private IP)
./dns-benchmark -dnssec -nxdomain -rebinding -rebinding-domain private.example.net

# Run accuracy check using a file (e.g., accuracy.txt containing "mydomain.com 1.2.3.4")
./dns-benchmark -accuracy-file accuracy.txt

# Get help
./dns-benchmark -h
```

## Notes

- DoH requests include a `User-Agent` header: `dns-benchmark/1.0 (+https://github.com/taihen/dns-benchmark)`
- Accuracy check requires a file where each line contains a domain and its expected IPs (comma-separated), separated by whitespace. The tool uses the first valid entry found.
- Rebinding checks require `-rebinding-domain` with a controlled domain that has private A and/or AAAA records.
- Results reflect network conditions at the time of the test. Run multiple times for a broader picture.
- Please use responsibly and avoid excessive querying.

## License

[MIT](LICENSE)
