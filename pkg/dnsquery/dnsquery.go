package dnsquery

import (
	"fmt"
	"sort"
	"time"

	"github.com/miekg/dns"
)

type queryResult struct {
	QueryType uint16
	Duration  time.Duration
}

func PerformQueries(dnsServer string, queryDomain string) (map[uint16]time.Duration, error) {
	queryTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeMX,
		dns.TypeTXT,
		dns.TypeNS,
	}
	results := make(map[uint16]time.Duration)

	for _, qType := range queryTypes {
		duration, err := performDNSQuery(dnsServer, queryDomain, qType)
		if err != nil {
			return nil, err
		}
		results[qType] = duration
	}

	return results, nil
}

func performDNSQuery(dnsServer string, queryDomain string, qType uint16) (time.Duration, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(queryDomain), qType)
	startTime := time.Now()
	_, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return 0, err
	}
	duration := time.Since(startTime)
	return duration, nil
}

func PrintReport(results map[uint16]time.Duration, dnsServer string, queryDomain string) {
	// Convert map to slice for sorting
	var resultsSlice []queryResult
	for qType, duration := range results {
		resultsSlice = append(resultsSlice, queryResult{QueryType: qType, Duration: duration})
	}

	// Sort slice by duration
	sort.Slice(resultsSlice, func(i, j int) bool {
		return resultsSlice[i].Duration < resultsSlice[j].Duration
	})

	// Print sorted results with DNS server and domain information
	fmt.Printf("# DNS Query Timing Report for %s (Domain: %s)\n", dnsServer, queryDomain)
	fmt.Println("| Query Type | Time Taken |")
	fmt.Println("|------------|------------|")
	for _, result := range resultsSlice {
		fmt.Printf("| %s | %v |\n", dns.TypeToString[result.QueryType], result.Duration)
	}
}
