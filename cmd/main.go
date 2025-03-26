package main

import (
	"fmt"
	"os"

	"dns-benchmark/pkg/dnsquery"
	"github.com/miekg/dns" // Add import for dns constants like dns.TypeA
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dnsbenchmark <dns-server> <query-domain>")
		os.Exit(1)
	}

	dnsServer := os.Args[1]
	queryDomain := os.Args[2]

	fmt.Printf("Checking server responsiveness (%s)...\n", dnsServer)
	_, initialResultStr, initialRcode, _ := dnsquery.PerformDNSQuery(dnsServer, queryDomain, dns.TypeA)

	if initialRcode == -1 {
		fmt.Printf("Error: DNS server %s is not responding or unreachable.\n", dnsServer)
		fmt.Printf("Details: %s\n", initialResultStr)
		os.Exit(1)
	}
	fmt.Println("Server responded. Proceeding with benchmark...")

	results, err := dnsquery.PerformQueries(dnsServer, queryDomain)
	if err != nil {
		fmt.Printf("Error during benchmark: %v\n", err)
		os.Exit(1)
	}

	dnsquery.PrintReport(results, dnsServer, queryDomain)
}
