package dnsquery

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/config"
	"golang.org/x/time/rate"
)

const (
	dnssecCheckDomain         = "dnssec-ok.org."
	nxdomainCheckDomainPrefix = "nxdomain-test-"
	nxdomainCheckDomainSuffix = ".example.com."
	rebindingCheckDomain      = "private.dns-rebinding-test.com." // Placeholder - requires a real domain resolving to private IP
	dotcomCheckPrefix         = "dnsbench-dotcom-"
	dotcomCheckSuffix         = ".com."
	dohUserAgent              = "dns-benchmark/1.0 (+https://github.com/taihen/dns-benchmark)"
)

// QueryResult holds the result of a single DNS query.
type QueryResult struct {
	Latency  time.Duration
	Response *dns.Msg
	Error    error
}

// --- Protocol Specific Query Functions ---

// performQueryWithClient handles UDP, TCP, and DoT queries using miekg/dns client.
func performQueryWithClient(client *dns.Client, serverAddr, domain string, qType uint16, timeout time.Duration) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.SetEdns0(4096, true) // Request DNSSEC

	startTime := time.Now()
	response, _, err := client.Exchange(msg, serverAddr)
	latency := time.Since(startTime)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return QueryResult{Error: fmt.Errorf("query timed out after %v", timeout)}
		}
		return QueryResult{Error: fmt.Errorf("query failed: %w", err)}
	}
	if response == nil {
		return QueryResult{Error: fmt.Errorf("query succeeded but response was nil")}
	}
	return QueryResult{Latency: latency, Response: response, Error: nil}
}

func performUDPQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	client := &dns.Client{Net: "udp", Timeout: timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	return performQueryWithClient(client, serverInfo.Address, domain, qType, timeout)
}

func performTCPQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	client := &dns.Client{Net: "tcp", Timeout: timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	return performQueryWithClient(client, serverInfo.Address, domain, qType, timeout)
}

func performDoTQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	tlsConfig := &tls.Config{
		ServerName: serverInfo.Hostname, // SNI
		MinVersion: tls.VersionTLS12,
	}
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Timeout:   timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout,
	}
	return performQueryWithClient(client, serverInfo.Address, domain, qType, timeout)
}

// performDoHQuery sends a query using DNS over HTTPS.
func performDoHQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.SetEdns0(4096, true)

	packedMsg, err := msg.Pack()
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to pack DoH message: %w", err)}
	}

	httpClient := &http.Client{Timeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", serverInfo.Address, bytes.NewReader(packedMsg))
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to create DoH request: %w", err)}
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", dohUserAgent)

	startTime := time.Now()
	httpResp, err := httpClient.Do(req)
	latency := time.Since(startTime)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return QueryResult{Error: fmt.Errorf("doh query timed out after %v", timeout)}
		}
		return QueryResult{Error: fmt.Errorf("doh http request failed: %w", err)}
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return QueryResult{Error: fmt.Errorf("doh query failed with status code %d", httpResp.StatusCode)}
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to read DoH response body: %w", err)}
	}

	response := new(dns.Msg)
	if err = response.Unpack(body); err != nil {
		return QueryResult{Error: fmt.Errorf("failed to unpack DoH response: %w", err)}
	}

	return QueryResult{Latency: latency, Response: response, Error: nil}
}

// performDoQQuery sends a query using DNS over QUIC.
func performDoQQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.SetEdns0(4096, true)

	packedMsg, err := msg.Pack()
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to pack DoQ message: %w", err)}
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"doq"}, // ALPN for DoQ
		ServerName: serverInfo.Hostname,
		MinVersion: tls.VersionTLS12,
	}

	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Dial QUIC connection
	// TODO: Consider reusing QUIC sessions for multiple queries to the same server if performance is critical.
	session, err := quic.DialAddrEarly(ctx, serverInfo.Address, tlsConfig, nil)
	if err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to dial %s: %w", serverInfo.Address, err)}
	}
	defer session.CloseWithError(0, "")

	// Open stream
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to open stream: %w", err)}
	}

	// Write query with length prefix
	lenPrefix := []byte{byte(len(packedMsg) >> 8), byte(len(packedMsg))}
	if _, err = stream.Write(append(lenPrefix, packedMsg...)); err != nil {
		stream.CancelRead(0) // Cancel reading if write fails
		return QueryResult{Error: fmt.Errorf("doq failed to write query: %w", err)}
	}
	stream.Close() // Close write side

	// Read response length prefix
	lenBuf := make([]byte, 2)
	if _, err = io.ReadFull(stream, lenBuf); err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to read length prefix: %w", err)}
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// Read response body
	// TODO: Add protection against excessively large response lengths?
	respBuf := make([]byte, respLen)
	if _, err = io.ReadFull(stream, respBuf); err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to read response body: %w", err)}
	}
	latency := time.Since(startTime)

	response := new(dns.Msg)
	if err = response.Unpack(respBuf); err != nil {
		return QueryResult{Error: fmt.Errorf("failed to unpack DoQ response: %w", err)}
	}

	return QueryResult{Latency: latency, Response: response, Error: nil}
}

// PerformQuery acts as a dispatcher based on protocol.
func PerformQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	switch serverInfo.Protocol {
	case config.UDP:
		return performUDPQuery(serverInfo, domain, qType, timeout)
	case config.TCP:
		return performTCPQuery(serverInfo, domain, qType, timeout)
	case config.DOT:
		return performDoTQuery(serverInfo, domain, qType, timeout)
	case config.DOH:
		return performDoHQuery(serverInfo, domain, qType, timeout)
	case config.DOQ:
		return performDoQQuery(serverInfo, domain, qType, timeout)
	default:
		return QueryResult{Error: fmt.Errorf("unsupported protocol: %s", serverInfo.Protocol)}
	}
}

// queryJob represents a single query task.
type queryJob struct {
	serverInfo config.ServerInfo
	domain     string
	qType      uint16
	queryType  analysis.QueryType // For latency jobs
	checkType  string             // For specific checks
}

// queryJobResult holds the result of a queryJob.
type queryJobResult struct {
	serverInfo config.ServerInfo
	result     QueryResult
	queryType  analysis.QueryType // For latency jobs
	checkType  string             // For specific checks
}

// Benchmarker manages the benchmarking process.
type Benchmarker struct {
	Config  *config.Config
	Results *analysis.BenchmarkResults
	Limiter *rate.Limiter
}

// NewBenchmarker creates a new Benchmarker instance.
func NewBenchmarker(cfg *config.Config) *Benchmarker {
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	if cfg.RateLimit <= 0 {
		limiter = rate.NewLimiter(rate.Inf, 0)
	}
	return &Benchmarker{
		Config:  cfg,
		Results: analysis.NewBenchmarkResults(),
		Limiter: limiter,
	}
}

// Run performs the benchmark against the configured servers.
func (b *Benchmarker) Run() *analysis.BenchmarkResults {
	servers := b.Config.Servers

	// Initialize Results map
	for _, server := range servers {
		b.Results.Results[server.String()] = &analysis.ServerResult{ServerAddress: server.String()}
	}

	// Run Latency Benchmark
	b.runLatencyBenchmark(servers)

	// Run Specific Checks Concurrently
	b.runChecksConcurrently(servers)

	return b.Results
}

// runLatencyBenchmark handles the cached/uncached latency tests.
func (b *Benchmarker) runLatencyBenchmark(servers []config.ServerInfo) {
	// Determine number of cached vs uncached queries
	var numCached, numUncached int
	totalQueries := b.Config.NumQueries
	if totalQueries < 1 {
		numCached, numUncached = 0, 0
	} else if totalQueries == 1 {
		numCached, numUncached = 0, 1
	} else if totalQueries == 2 {
		numCached, numUncached = 1, 1
	} else if totalQueries == 3 {
		numCached, numUncached = 1, 2
	} else {
		numCached, numUncached = totalQueries/2, totalQueries-(totalQueries/2)
	}

	totalLatencyJobsPerServer := numCached + numUncached
	totalLatencyJobs := len(servers) * totalLatencyJobsPerServer
	if totalLatencyJobs == 0 {
		return
	}

	jobs := make(chan queryJob, totalLatencyJobs)
	resultsChan := make(chan queryJobResult, totalLatencyJobs)
	var wg sync.WaitGroup

	concurrency := b.Config.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > totalLatencyJobs {
		concurrency = totalLatencyJobs
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go b.queryWorker(&wg, jobs, resultsChan)
	}

	qType := dns.StringToType[strings.ToUpper(b.Config.QueryType)]
	if qType == 0 {
		qType = dns.TypeA
	}
	cachedDomain := b.Config.Domain

	for _, server := range servers {
		serverKey := server.String()
		serverResult := b.Results.Results[serverKey]
		serverResult.TotalQueries = totalLatencyJobsPerServer
		serverResult.CachedLatencies = make([]time.Duration, 0, numCached)
		serverResult.UncachedLatencies = make([]time.Duration, 0, numUncached)

		for i := 0; i < numCached; i++ {
			jobs <- queryJob{serverInfo: server, domain: cachedDomain, qType: qType, queryType: analysis.Cached}
		}
		for i := 0; i < numUncached; i++ {
			uncachedDomain := generateUniqueDomain(nxdomainCheckDomainPrefix, ".net.")
			jobs <- queryJob{serverInfo: server, domain: uncachedDomain, qType: qType, queryType: analysis.Uncached}
		}
	}
	close(jobs)

	wg.Wait()
	close(resultsChan)

	// Collect latency results
	for res := range resultsChan {
		serverKey := res.serverInfo.String()
		serverResult, ok := b.Results.Results[serverKey]
		if !ok {
			continue
		}

		if res.result.Error != nil {
			serverResult.Errors++
			if b.Config.Verbose {
				fmt.Fprintf(os.Stderr, "Latency query error for %s (%s): %v\n", serverKey, res.queryType, res.result.Error)
			}
		} else {
			switch res.queryType {
			case analysis.Cached:
				serverResult.CachedLatencies = append(serverResult.CachedLatencies, res.result.Latency)
			case analysis.Uncached:
				serverResult.UncachedLatencies = append(serverResult.UncachedLatencies, res.result.Latency)
			}
		}
	}
}

// runChecksConcurrently runs DNSSEC, NXDOMAIN, Rebinding, Accuracy, Dotcom checks.
func (b *Benchmarker) runChecksConcurrently(servers []config.ServerInfo) {
	var checkJobsList []queryJob

	// Prepare check jobs
	for _, server := range servers {
		if b.Config.CheckDNSSEC {
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: dnssecCheckDomain, qType: dns.TypeA, checkType: "dnssec"})
		}
		if b.Config.CheckNXDOMAIN {
			nxDomain := generateUniqueDomain(nxdomainCheckDomainPrefix, nxdomainCheckDomainSuffix)
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: nxDomain, qType: dns.TypeA, checkType: "nxdomain"})
		}
		if b.Config.CheckRebinding {
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: rebindingCheckDomain, qType: dns.TypeA, checkType: "rebinding"})
		}
		if b.Config.AccuracyCheckFile != "" {
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: b.Config.AccuracyCheckDomain, qType: dns.TypeA, checkType: "accuracy"})
		}
		if b.Config.CheckDotcom {
			dotcomDomain := generateUniqueDomain(dotcomCheckPrefix, dotcomCheckSuffix)
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: dotcomDomain, qType: dns.TypeA, checkType: "dotcom"})
		}
	}

	if len(checkJobsList) == 0 {
		return
	} // No checks enabled

	jobs := make(chan queryJob, len(checkJobsList))
	resultsChan := make(chan queryJobResult, len(checkJobsList))
	var wg sync.WaitGroup

	concurrency := b.Config.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(checkJobsList) {
		concurrency = len(checkJobsList)
	}

	// Start check workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go b.queryWorker(&wg, jobs, resultsChan)
	}

	// Distribute check jobs
	for _, job := range checkJobsList {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	close(resultsChan)

	// Process check results
	for res := range resultsChan {
		serverKey := res.serverInfo.String()
		serverResult, ok := b.Results.Results[serverKey]
		if !ok {
			continue
		}

		if res.result.Error != nil && b.Config.Verbose {
			fmt.Fprintf(os.Stderr, "%s check error for %s: %v\n", strings.Title(res.checkType), serverKey, res.result.Error)
		}

		// Update results based on check type
		switch res.checkType {
		case "dnssec":
			supportsDNSSEC := checkADFlag(res.result)
			serverResult.SupportsDNSSEC = &supportsDNSSEC
		case "nxdomain":
			hijacks := checkNXDOMAINHijack(res.result)
			serverResult.HijacksNXDOMAIN = &hijacks
		case "rebinding":
			blocks := checkRebindingProtection(res.result)
			serverResult.BlocksRebinding = &blocks
		case "accuracy":
			accurate := checkResponseAccuracy(res.result, b.Config.AccuracyCheckIP)
			serverResult.IsAccurate = &accurate
		case "dotcom":
			if res.result.Error == nil {
				latency := res.result.Latency
				serverResult.DotcomLatency = &latency
			}
		}
	}
}

// queryWorker executes query jobs (used for both latency and checks).
func (b *Benchmarker) queryWorker(wg *sync.WaitGroup, jobs <-chan queryJob, results chan<- queryJobResult) {
	defer wg.Done()
	for job := range jobs {
		_ = b.Limiter.Wait(context.Background()) // Apply rate limit
		queryResult := PerformQuery(job.serverInfo, job.domain, job.qType, b.Config.Timeout)
		// Pass back identifying info
		results <- queryJobResult{
			serverInfo: job.serverInfo,
			result:     queryResult,
			queryType:  job.queryType, // Will be zero value if it's a check job
			checkType:  job.checkType, // Will be empty if it's a latency job
		}
	}
}

// generateUniqueDomain creates a unique domain name.
func generateUniqueDomain(prefix, suffix string) string {
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		randomBytes = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	} // Fallback
	uniquePart := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("%s%s%s", prefix, uniquePart, suffix)
}

// --- Check Helper Functions ---

func checkADFlag(result QueryResult) bool {
	if result.Error != nil || result.Response == nil {
		return false
	}
	return result.Response.AuthenticatedData
}

func checkNXDOMAINHijack(result QueryResult) bool {
	if result.Error != nil || result.Response == nil {
		return false
	}
	rcode := result.Response.Rcode
	if rcode == dns.RcodeNameError {
		return false
	}
	if rcode == dns.RcodeSuccess && len(result.Response.Answer) > 0 {
		return true
	}
	return false
}

func checkRebindingProtection(result QueryResult) bool {
	if result.Error != nil {
		return true
	}
	if result.Response == nil {
		return true
	}
	if result.Response.Rcode != dns.RcodeSuccess {
		return true
	}
	if len(result.Response.Answer) == 0 {
		return true
	}
	return false // Received NOERROR with answers
}

func checkResponseAccuracy(result QueryResult, expectedIP string) bool {
	if result.Error != nil || result.Response == nil || result.Response.Rcode != dns.RcodeSuccess {
		return false
	}
	// TODO: Handle multiple expected IPs if accuracy file format allows it.
	for _, rr := range result.Response.Answer {
		if aRecord, ok := rr.(*dns.A); ok {
			if aRecord.A.String() == expectedIP {
				return true
			}
		}
		// TODO: Add check for AAAA records if needed/specified.
	}
	return false
}
