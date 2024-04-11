package main

import (
	"fmt"
	"os"

	"dns-benchmark/pkg/dnsquery"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dnsbenchmark <dns-server> <query-domain>")
		os.Exit(1)
	}

	dnsServer := os.Args[1]
	queryDomain := os.Args[2] // Capture the domain from command line
	results, err := dnsquery.PerformQueries(dnsServer, queryDomain)
	if err != nil {
		fmt.Printf("Failed to perform queries: %v\n", err)
		os.Exit(1)
	}

	dnsquery.PrintReport(results, dnsServer, queryDomain)
}
