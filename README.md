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

To use the DNS Benchmark tool, you must specify the DNS server and the domain to query. Here is how you can run the tool:

```bash
./dnsbenchmark <dns-server> <query-domain>
```

### Example

```bash
./dnsbenchmark 8.8.8.8 example.com
```

This will first check if `8.8.8.8` is responsive. If it is, it performs DNS queries against the Google Public DNS server for the domain `example.com` and outputs the timings, RCODE, and results for each supported query type.

If the server is unresponsive (e.g., `./dnsbenchmark 192.0.2.1 example.com` where `192.0.2.1` is not a DNS server):

```
Checking server responsiveness (192.0.2.1)...
Error: DNS server 192.0.2.1 is not responding or unreachable.
Details: Network Error: read udp 192.168.1.100:54321->192.0.2.1:53: i/o timeout
```

## Output Format

The output is formatted in Markdown as follows (example timings/results):

```
# DNS Query Timing Report for 8.8.8.8 (Domain: example.com)
| Query Type | Time Taken | RCODE   | Result                                     |
|------------|------------|---------|--------------------------------------------|
| NS         | 26ms       | NOERROR | [example.com. 21599 IN NS b.iana-servers...|
| CNAME      | 29ms       | NOERROR | NOERROR (empty answer)                     |
| AAAA       | 30ms       | NOERROR | [example.com. 86399 IN AAAA 2606:2800:22...|
| TXT        | 32ms       | NOERROR | NOERROR (empty answer)                     |
| A          | 34ms       | NOERROR | [example.com. 86399 IN A 93.184.216.34]    |
| MX         | 45ms       | NOERROR | NOERROR (empty answer)                     |
```

_(Note: Long results are truncated in the output table)_

## Contributing

Contributions to improve the DNS Benchmark CLI Tool are welcome.

## License

This project is not worth any license ;-)
