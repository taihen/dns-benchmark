# DNS Benchmark CLI Tool

## Overview

A DNS Benchmark CLI Tool utility written in Go that allows users to measure the response times of various DNS query types against a specified DNS server and domain.

## Features

- Outputs a Markdown-formatted report including:
  - Query timings.
  - **DNS Response Code (RCODE):** Indicates the status of the query (e.g., NOERROR, NXDOMAIN, REFUSED, N/A for network errors).
  - **Query Result:** Shows the actual DNS answer received or indicates errors/empty responses.
- Simple CLI interface for ease of use.

## Installation

### Prerequisites

- [Go](https://golang.org/doc/install) (**1.24** or later)

### Setup

Clone the repository and build the tool:

```bash
git clone https://github.com/taihen/dns-benchmark.git
cd dns-benchmark
go build -o dnsbenchmark ./cmd
```

## Usage

To use the DNS Benchmark tool, you must specify the DNS server and the domain to query.

```bash
./dnsbenchmark <dns-server> <query-domain>
```

### Options

- `-p <parallel_queries>`: Specifies the number of queries to run in parallel for each query type. Defaults to `10`.

  **Warning:** Setting this value too high (e.g., above 20) may result in rate limiting from public DNS servers, leading to errors or inaccurate results. Use with caution.

- `-d`: Enable debug mode. If set, prints raw aggregated timing data before the final sorted report. Defaults to `false`.

### Example

```bash
# Run with default 10 parallel queries
./dnsbenchmark 8.8.8.8 example.com

# Run with 5 parallel queries
./dnsbenchmark -p 5 1.1.1.1 cloudflare.com

# Run with debug output enabled
./dnsbenchmark -d 8.8.8.8 google.com
```

This will first check if the specified DNS server is responsive. If it is, it performs the specified number of parallel DNS queries against the server for the domain and outputs the average timings, success rate, RCODE, and last result for each supported query type. If `-d` is used, raw aggregation data will be printed before the final report.

## Output Format

The output is formatted in Markdown as follows (example timings/results):

```
# DNS Query Timing Report for 1.1.1.1 (Domain: cloudflare.com) - 5 Parallel Queries
| Query Type | Avg Time   | Success | RCODE   | Last Result                                |
|------------|------------|---------|---------|--------------------------------------------|
| A          | 15ms       | 5/5     | NOERROR | [cloudflare.com. 28 IN A 104.16.132.229]   |
| NS         | 16ms       | 5/5     | NOERROR | [cloudflare.com. 21455 IN NS ns7.cloudf...|
| AAAA       | 17ms       | 5/5     | NOERROR | [cloudflare.com. 211 IN AAAA 2606:4700::...|
| CNAME      | 20ms       | 5/5     | NOERROR | NOERROR (empty answer)                     |
| MX         | 22ms       | 5/5     | NOERROR | [cloudflare.com. 697 IN MX 20 mailstrea...|
| TXT        | 25ms       | 5/5     | NOERROR | NOERROR (empty answer)                     |
```

_(Note: Example timings/results. Long results are truncated in the output table)_

## Contributing

Contributions to improve the DNS Benchmark CLI Tool are welcome.

## License

This project is not worth any license ;-)
