package main

import (
	"flag"
	"fmt"
	"os"

	"dns-benchmark/pkg/dnsquery"
	"github.com/miekg/dns" // Add import for dns constants like dns.TypeA
)

func main() {
	// Define flags
	parallelFlag := flag.Int("p", 10, "Number of parallel queries")
	debugFlag := flag.Bool("d", false, "Enable debug output (raw aggregated data)")

	// Parse flags
	flag.Parse()

	// Check for required positional arguments (server and domain)
	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: dnsbenchmark [-p <parallel_queries>] <dns-server> <query-domain>")
		flag.PrintDefaults() // Print flag usage
		os.Exit(1)
	}

	dnsServer := args[0]
	queryDomain := args[1]
	numParallel := *parallelFlag // Get the value from the flag pointer
	debugMode := *debugFlag      // Get the value from the flag pointer

	fmt.Printf("Checking server responsiveness (%s)...\n", dnsServer)
	_, initialResultStr, initialRcode, _ := dnsquery.PerformDNSQuery(dnsServer, queryDomain, dns.TypeA)

	if initialRcode == -1 {
		fmt.Printf("Error: DNS server %s is not responding or unreachable.\n", dnsServer)
		fmt.Printf("Details: %s\n", initialResultStr)
		os.Exit(1)
	}
	fmt.Println("Server responded. Proceeding with benchmark...")

	fmt.Printf("Performing %d queries in parallel...\n", numParallel)
	results, err := dnsquery.PerformQueries(dnsServer, queryDomain, numParallel) // Pass numParallel
	if err != nil {
		fmt.Printf("Error during benchmark: %v\n", err)
		os.Exit(1)
	}

	dnsquery.PrintReport(results, dnsServer, queryDomain, numParallel, debugMode) // Pass numParallel and debugMode
}
