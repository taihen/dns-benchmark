package dnsquery

import (
	"fmt"
	"sort"
	"sync" // Added for WaitGroup
	"time"

	"github.com/miekg/dns"
)

// Represents the result of a single DNS query
type queryResult struct {
	QueryType uint16
	Duration  time.Duration
	Result    string
	Rcode     int
	Error     error // Added to capture potential errors within a goroutine
}

// Represents aggregated results for a specific query type after multiple parallel queries
type aggregatedQueryResult struct {
	QueryType     uint16
	TotalDuration time.Duration
	QueryCount    int
	SuccessCount  int    // Number of successful queries (Rcode != -1 and no network error)
	Rcode         int    // Rcode of the last received query for this type (for reporting)
	Result        string // Result of the last received query for this type (for reporting)
}

func PerformQueries(dnsServer string, queryDomain string, numParallel int) (map[uint16]aggregatedQueryResult, error) {
	queryTypes := []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeNS, // Standard order
	}
	totalQueries := len(queryTypes) * numParallel
	// Revert back to using a map of structs
	aggregatedResults := make(map[uint16]aggregatedQueryResult)
	resultsChan := make(chan queryResult, totalQueries) // Buffer for all results
	var wg sync.WaitGroup      // For worker goroutines
	// Removed aggWg and mapMutex
	// Removed concurrencyLimiter


	// Initialize aggregated results map first with structs
	for _, qType := range queryTypes {
		aggregatedResults[qType] = aggregatedQueryResult{QueryType: qType}
	}

	wg.Add(totalQueries) // Add count for worker queries upfront

	// Launch all worker goroutines, cycling through query types for better distribution
	for i := 0; i < totalQueries; i++ {
		// Removed semaphore acquisition
		qType := queryTypes[i%len(queryTypes)] // Cycle through types
		go func(qt uint16) { // Correct indentation
			defer wg.Done()
			// Removed semaphore release
			// Use the main PerformDNSQuery which creates its own client
			duration, resultStr, rcode, err := PerformDNSQuery(dnsServer, queryDomain, qt)
			resultsChan <- queryResult{
				QueryType: qt,
				Duration:  duration,
				Result:    resultStr,
				Rcode:     rcode,
				Error:     err,
			}
		}(qType)
	} // End of the outer for loop launching goroutines

	// Wait for all worker goroutines to finish *before* closing the channel
	wg.Wait()
	close(resultsChan)

	// Collect and aggregate results *after* all workers are done (back to simpler model)
	for res := range resultsChan {
		// Get the struct (copy) from the map
		aggRes := aggregatedResults[res.QueryType]
		// Modify the copy
		aggRes.QueryCount++
		aggRes.TotalDuration += res.Duration
		aggRes.Rcode = res.Rcode                 // Store last Rcode
		aggRes.Result = res.Result               // Store last Result
		if res.Rcode != -1 && res.Error == nil { // Consider Rcode and network error
			aggRes.SuccessCount++
		}
		// Write the modified copy back to the map
		aggregatedResults[res.QueryType] = aggRes
	}

	return aggregatedResults, nil
}

// PerformDNSQuery creates a temporary client and performs a single DNS query.
// Used for the initial responsiveness check.
func PerformDNSQuery(dnsServer string, queryDomain string, qType uint16) (time.Duration, string, int, error) {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second // Keep timeout for single check
	return performDNSQueryInternal(c, dnsServer, queryDomain, qType)
}

// performDNSQueryInternal performs a single DNS query using a provided client.
func performDNSQueryInternal(c *dns.Client, dnsServer string, queryDomain string, qType uint16) (time.Duration, string, int, error) {
	m := new(dns.Msg)
	// Remove duplicate SetQuestion call
	m.SetQuestion(dns.Fqdn(queryDomain), qType)
	startTime := time.Now()
	r, _, err := c.Exchange(m, dnsServer+":53") // Use the provided client 'c'
	endTime := time.Now() // Capture end time immediately
	duration := endTime.Sub(startTime) // Calculate duration explicitly

	if err != nil {
		return duration, fmt.Sprintf("Network Error: %v", err), -1, err
	}

	rcode := r.Rcode
	resultStr := ""

	if len(r.Answer) > 0 {
		answers := make([]string, len(r.Answer))
		for i, ans := range r.Answer {
			answers[i] = ans.String()
		}
		resultStr = fmt.Sprintf("%v", answers)
	} else {
		resultStr = dns.RcodeToString[rcode]
		if rcode == dns.RcodeSuccess {
			resultStr = "NOERROR (empty answer)"
		}
	}

	// Return the actual error from c.Exchange
	return duration, resultStr, rcode, err
}

func PrintReport(results map[uint16]aggregatedQueryResult, dnsServer string, queryDomain string, numParallel int, debugMode bool) {
	var resultsSlice []aggregatedQueryResult

	// --- DEBUG START: Print raw aggregated data before sorting ---
	if debugMode {
	fmt.Println("\n--- Raw Aggregated Data (Before Sort) ---")
	// Create a temporary slice just for ordered debug printing
	debugSlice := make([]aggregatedQueryResult, 0, len(results))
	for _, qr := range results {
		debugSlice = append(debugSlice, qr)
	}
	// Sort debug slice by type for consistent output order
	sort.Slice(debugSlice, func(i, j int) bool {
		return debugSlice[i].QueryType < debugSlice[j].QueryType
	})
	for _, qr := range debugSlice {
		fmt.Printf("Type: %-5s, Count: %2d, TotalDuration: %v\n", dns.TypeToString[qr.QueryType], qr.QueryCount, qr.TotalDuration)
	}
	fmt.Println("-------------------------------------------")
	}
	// --- DEBUG END ---

	// Populate the slice for actual report sorting
	for _, qr := range results {
		resultsSlice = append(resultsSlice, qr)
	}


	// Sort by average duration
	sort.Slice(resultsSlice, func(i, j int) bool {
		avgDurationI := time.Duration(0)
		if resultsSlice[i].QueryCount > 0 {
			avgDurationI = resultsSlice[i].TotalDuration / time.Duration(resultsSlice[i].QueryCount)
		}
		avgDurationJ := time.Duration(0)
		if resultsSlice[j].QueryCount > 0 {
			avgDurationJ = resultsSlice[j].TotalDuration / time.Duration(resultsSlice[j].QueryCount)
		}
		return avgDurationI < avgDurationJ
	})

	fmt.Printf("# DNS Query Timing Report for %s (Domain: %s) - %d Parallel Queries\n", dnsServer, queryDomain, numParallel)
	fmt.Println("| Query Type | Avg Time   | Success | RCODE   | Last Result                                |")
	fmt.Println("|------------|------------|---------|---------|--------------------------------------------|")
	for _, result := range resultsSlice {
		avgDuration := time.Duration(0)
		if result.QueryCount > 0 {
			avgDuration = result.TotalDuration / time.Duration(result.QueryCount)
		}

		rcodeStr := "N/A"
		if result.Rcode != -1 { // Use the Rcode from the aggregated result
			rcodeStr = dns.RcodeToString[result.Rcode]
		}

		resultStr := result.Result // Use the Result from the aggregated result
		if len(resultStr) > 40 {
			resultStr = resultStr[:37] + "..."
		}

		successRateStr := fmt.Sprintf("%d/%d", result.SuccessCount, result.QueryCount)

		fmt.Printf("| %-10s | %-10v | %-7s | %-7s | %-42s |\n",
			dns.TypeToString[result.QueryType],
			avgDuration,
			successRateStr,
			rcodeStr,
			resultStr)
	}
}
