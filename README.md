# DNS Benchmark CLI Tool

## Overview
Yet another DNS Benchmark CLI Tool utility written in Go that allows users to measure the response times of various DNS query types against a specified DNS server and domain. Queries DNS record types A, AAAA, CNAME, MX, TXT, and NS, providing a performance overview in a markdown report.

## Features
- Support for multiple DNS query types (A, AAAA, CNAME, MX, TXT, NS).
- Customizable target DNS server and query domain.
- Outputs a Markdown-formatted report with the performance metrics.
- Simple CLI interface for ease of use.

## Installation

### Prerequisites
- [Go](https://golang.org/doc/install) (1.15 or later)

### Setup
Clone the repository and build the tool:
```bash
git clone https://github.com/taihen/dns-benchmark.git
cd dns-benchmark
go build -o dnsbenchmark ./cmd
```

## Usage
To use the DNS Benchmark tool, you must specify the DNS server and the domain to query. Here is how you can run the tool:

```bash
./dnsbenchmark <dns-server> <query-domain>
```

### Example
```bash
./dnsbenchmark 8.8.8.8 example.com
```

This will perform DNS queries against the Google Public DNS server (`8.8.8.8`) for the domain `example.com` and output the timings for each supported query type.

## Output Format
The output is formatted in Markdown as follows:

```
# DNS Query Timing Report for 8.8.8.8 (Domain: example.com)
| Query Type | Time Taken |
|------------|------------|
| A          | 34ms       |
| AAAA       | 30ms       |
| CNAME      | 29ms       |
| MX         | 45ms       |
| TXT        | 32ms       |
| NS         | 26ms       |
```

## Contributing
Contributions to improve the DNS Benchmark CLI Tool are welcome.

## License
This project is licensed under the MIT License.
