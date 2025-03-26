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
	Result    string
	Rcode     int
}

func PerformQueries(dnsServer string, queryDomain string) (map[uint16]queryResult, error) {
	queryTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeMX,
		dns.TypeTXT,
		dns.TypeNS,
	}
	results := make(map[uint16]queryResult)

	for _, qType := range queryTypes {
		duration, resultStr, rcode, _ := PerformDNSQuery(dnsServer, queryDomain, qType)

		results[qType] = queryResult{
			QueryType: qType,
			Duration:  duration,
			Result:    resultStr,
			Rcode:     rcode,
		}

	}

	return results, nil
}

func PerformDNSQuery(dnsServer string, queryDomain string, qType uint16) (time.Duration, string, int, error) {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(queryDomain), qType)
	startTime := time.Now()
	r, _, err := c.Exchange(m, dnsServer+":53")
	duration := time.Since(startTime)

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

	return duration, resultStr, rcode, nil
}

func PrintReport(results map[uint16]queryResult, dnsServer string, queryDomain string) {
	var resultsSlice []queryResult
	for _, qr := range results {
		resultsSlice = append(resultsSlice, qr)
	}

	sort.Slice(resultsSlice, func(i, j int) bool {
		return resultsSlice[i].Duration < resultsSlice[j].Duration
	})

	fmt.Printf("# DNS Query Timing Report for %s (Domain: %s)\n", dnsServer, queryDomain)
	fmt.Println("| Query Type | Time Taken | RCODE   | Result                                     |")
	fmt.Println("|------------|------------|---------|--------------------------------------------|")
	for _, result := range resultsSlice {
		rcodeStr := "N/A"
		if result.Rcode != -1 {
			rcodeStr = dns.RcodeToString[result.Rcode]
		}

		resultStr := result.Result
		if len(resultStr) > 40 {
			resultStr = resultStr[:37] + "..."
		}
		fmt.Printf("| %-10s | %-10v | %-7s | %-42s |\n", dns.TypeToString[result.QueryType], result.Duration, rcodeStr, resultStr)
	}
}
