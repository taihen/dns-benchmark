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

// Function variables for mocking in tests
var (
	performUDPQueryFunc = performUDPQuery
	performTCPQueryFunc = performTCPQuery
	performDoTQueryFunc = performDoTQuery
	performDoHQueryFunc = performDoHQuery
	performDoQQueryFunc = performDoQQuery
)

// HTTP client cache for DoH servers, shared across all queries
var (
	dohClientsMu    sync.RWMutex
	dohClientsCache map[string]*http.Client
)

const (
	dnssecCheckDomain         = "dnssec-ok.org."
	nxdomainCheckDomainPrefix = "nxdomain-test-"
	nxdomainCheckDomainSuffix = ".example.com."
	rebindingCheckDomain      = "private.dns-rebinding-test.com." // Placeholder - requires a real domain resolving to private IP
	dotcomCheckPrefix         = "dnsbench-dotcom-"
	dotcomCheckSuffix         = ".com."
	dohUserAgent              = "dns-benchmark/1.0 (+https://github.com/taihen/dns-benchmark)"

	// QUIC connection pool configuration
	maxPooledConnections = 10
	connectionTTL        = 30 * time.Second
	maxIdleTime          = 15 * time.Second
)

// QueryResult holds the result of a single DNS query.
type QueryResult struct {
	Latency  time.Duration
	Response *dns.Msg
	Error    error
}

// quicConnection represents a pooled QUIC connection
type quicConnection struct {
	session   *quic.Conn
	lastUsed  time.Time
	createdAt time.Time
	inUse     bool
}

// quicConnectionPool manages QUIC connections for DoQ queries
type quicConnectionPool struct {
	mu          sync.RWMutex
	connections map[string][]*quicConnection // key: serverAddress
	cleanup     chan struct{}
	cleanupDone chan struct{}
}

// Global connection pool instance
var globalQuicPool = &quicConnectionPool{
	connections: make(map[string][]*quicConnection),
	cleanup:     make(chan struct{}),
	cleanupDone: make(chan struct{}),
}

// Initialize the cleanup goroutine
func init() {
	go globalQuicPool.startCleanup()
}

// startCleanup runs the cleanup goroutine that removes stale connections
func (p *quicConnectionPool) startCleanup() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupStaleConnections()
		case <-p.cleanup:
			p.closeAllConnections()
			close(p.cleanupDone)
			return
		}
	}
}

// cleanupStaleConnections removes expired and idle connections
func (p *quicConnectionPool) cleanupStaleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for serverAddr, conns := range p.connections {
		var activeConns []*quicConnection

		for _, conn := range conns {
			// Remove connections that are too old or have been idle too long
			if !conn.inUse &&
				(now.Sub(conn.createdAt) > connectionTTL ||
					now.Sub(conn.lastUsed) > maxIdleTime) {
				if conn.session != nil {
					conn.session.CloseWithError(0, "cleanup")
				}
				continue
			}
			activeConns = append(activeConns, conn)
		}

		if len(activeConns) == 0 {
			delete(p.connections, serverAddr)
		} else {
			p.connections[serverAddr] = activeConns
		}
	}
}

// getConnection retrieves or creates a QUIC connection for the server
func (p *quicConnectionPool) getConnection(serverAddr string, tlsConfig *tls.Config) (*quic.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Look for an available connection
	if conns, exists := p.connections[serverAddr]; exists {
		for _, conn := range conns {
			// Check if connection is still valid and not in use
			if !conn.inUse {
				select {
				case <-conn.session.Context().Done():
					// Connection is closed, remove it
					continue
				default:
					// Connection is still valid, mark as in use
					conn.inUse = true
					conn.lastUsed = time.Now()
					return conn.session, nil
				}
			}
		}
	}

	// No available connection, create a new one if under limit
	if conns := p.connections[serverAddr]; len(conns) >= maxPooledConnections {
		// Pool is full, create a temporary connection (not pooled)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return quic.DialAddrEarly(ctx, serverAddr, tlsConfig, nil)
	}

	// Create new connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := quic.DialAddrEarly(ctx, serverAddr, tlsConfig, nil)
	if err != nil {
		return nil, err
	}

	// Add to pool
	conn := &quicConnection{
		session:   session,
		lastUsed:  time.Now(),
		createdAt: time.Now(),
		inUse:     true,
	}

	p.connections[serverAddr] = append(p.connections[serverAddr], conn)
	return session, nil
}

// returnConnection marks a connection as available for reuse
func (p *quicConnectionPool) returnConnection(serverAddr string, session *quic.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conns, exists := p.connections[serverAddr]; exists {
		for _, conn := range conns {
			if conn.session == session {
				conn.inUse = false
				conn.lastUsed = time.Now()
				return
			}
		}
	}
}

// closeAllConnections closes all pooled connections
func (p *quicConnectionPool) closeAllConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conns := range p.connections {
		for _, conn := range conns {
			if conn.session != nil {
				conn.session.CloseWithError(0, "shutdown")
			}
		}
	}
	p.connections = make(map[string][]*quicConnection)
}

// shutdownPool gracefully shuts down the connection pool
func (p *quicConnectionPool) shutdownPool() {
	close(p.cleanup)
	<-p.cleanupDone
}

// CleanupQuicPool gracefully shuts down the global QUIC connection pool
func CleanupQuicPool() {
	globalQuicPool.shutdownPool()
}

// performQueryWithClient performs a DNS query using a provided dns.Client.
// It sets up the query message, including EDNS0 for DNSSEC, and handles the client exchange.
func performQueryWithClient(client *dns.Client, serverAddr, domain string, qType uint16, timeout time.Duration) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.SetEdns0(4096, true) // Opt-in to DNSSEC requests via EDNS0

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

// performUDPQuery performs a DNS query over UDP.
func performUDPQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	client := &dns.Client{Net: "udp", Timeout: timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	return performQueryWithClient(client, serverInfo.Address, domain, qType, timeout)
}

// performTCPQuery performs a DNS query over TCP.
func performTCPQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	client := &dns.Client{Net: "tcp", Timeout: timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	return performQueryWithClient(client, serverInfo.Address, domain, qType, timeout)
}

// performDoTQuery performs a DNS query over TLS (DoT).
// It configures TLS settings and uses the "tcp-tls" network.
func performDoTQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	tlsConfig := &tls.Config{
		ServerName: serverInfo.Hostname, // for SNI
		MinVersion: tls.VersionTLS12,
	}
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Timeout:   timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout,
	}
	return performQueryWithClient(client, serverInfo.Address, domain, qType, timeout)
}

// performDoHQuery performs a DNS query over HTTPS (DoH).
// It constructs an HTTP request with the DNS query message and sends it to the DoH server.
func performDoHQuery(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.SetEdns0(4096, true)

	packedMsg, err := msg.Pack()
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to pack DoH message: %w", err)}
	}

	var httpClient *http.Client
	dohClientsMu.RLock()
	if dohClientsCache != nil {
		httpClient = dohClientsCache[serverInfo.Address]
	}
	dohClientsMu.RUnlock()

	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

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

// performDoQQuery performs a DNS query over QUIC (DoQ).
// It uses connection pooling to reuse QUIC sessions for better performance.
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

	// Get QUIC connection from pool
	session, err := globalQuicPool.getConnection(serverInfo.Address, tlsConfig)
	if err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to get connection for %s: %w", serverInfo.Address, err)}
	}

	// Return connection to pool when done
	defer globalQuicPool.returnConnection(serverInfo.Address, session)

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
	if _, err = stream.Read(lenBuf); err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to read length prefix: %w", err)}
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// Add protection against excessively large response lengths
	const maxResponseSize = 64 * 1024 // 64KB limit
	if respLen > maxResponseSize {
		return QueryResult{Error: fmt.Errorf("doq response too large: %d bytes (max %d)", respLen, maxResponseSize)}
	}

	// Read response body
	respBuf := make([]byte, respLen)
	totalRead := 0
	for totalRead < respLen {
		n, err := stream.Read(respBuf[totalRead:])
		if err != nil {
			return QueryResult{Error: fmt.Errorf("doq failed to read response body: %w", err)}
		}
		totalRead += n
	}
	latency := time.Since(startTime)

	response := new(dns.Msg)
	if err = response.Unpack(respBuf); err != nil {
		return QueryResult{Error: fmt.Errorf("failed to unpack DoQ response: %w", err)}
	}

	return QueryResult{Latency: latency, Response: response, Error: nil}
}

// performQueryImpl is the actual implementation, assigned to PerformQueryFunc.
func performQueryImpl(serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	switch serverInfo.Protocol {
	case config.UDP:
		return performUDPQueryFunc(serverInfo, domain, qType, timeout)
	case config.TCP:
		return performTCPQueryFunc(serverInfo, domain, qType, timeout)
	case config.DOT:
		return performDoTQueryFunc(serverInfo, domain, qType, timeout)
	case config.DOH:
		return performDoHQueryFunc(serverInfo, domain, qType, timeout)
	case config.DOQ:
		return performDoQQueryFunc(serverInfo, domain, qType, timeout)
	default:
		return QueryResult{Error: fmt.Errorf("unsupported protocol: %s", serverInfo.Protocol)}
	}
}

// PerformQueryFunc is a variable holding the query function implementation, allowing mocking.
var PerformQueryFunc = performQueryImpl

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
	Config     *config.Config
	Results    *analysis.BenchmarkResults
	Limiter    *rate.Limiter
	dohClients map[string]*http.Client // HTTP clients for DoH servers
}

// NewBenchmarker creates a new Benchmarker instance.
func NewBenchmarker(cfg *config.Config) *Benchmarker {
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	if cfg.RateLimit <= 0 {
		limiter = rate.NewLimiter(rate.Inf, 0)
	}

	dohClients := make(map[string]*http.Client)
	for _, server := range cfg.Servers {
		if server.Protocol == config.DOH {
			dohClients[server.Address] = &http.Client{Timeout: cfg.Timeout}
		}
	}

	return &Benchmarker{
		Config:     cfg,
		Results:    analysis.NewBenchmarkResults(),
		Limiter:    limiter,
		dohClients: dohClients,
	}
}

// Run performs the benchmark against the configured servers.
func (b *Benchmarker) Run() *analysis.BenchmarkResults {
	servers := b.Config.Servers

	dohClientsMu.Lock()
	dohClientsCache = b.dohClients
	dohClientsMu.Unlock()

	b.prewarmConnections(servers)

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

// prewarmConnections makes a dummy query to each DoH, DoT, and TCP server to establish
// connections before running the benchmark. This prevents connection setup overhead from
// biasing the cached query results.
func (b *Benchmarker) prewarmConnections(servers []config.ServerInfo) {
	for _, server := range servers {
		if server.Protocol == config.DOH {
			_ = performDoHQueryFunc(server, "example.com", dns.TypeA, b.Config.Timeout)
		} else if server.Protocol == config.DOT {
			_ = performDoTQueryFunc(server, "example.com", dns.TypeA, b.Config.Timeout)
		} else if server.Protocol == config.TCP {
			_ = performTCPQueryFunc(server, "example.com", dns.TypeA, b.Config.Timeout)
		}
	}
}

// calculateLatencyQueryCounts determines the number of cached and uncached queries.
func calculateLatencyQueryCounts(totalQueries int) (numCached, numUncached int) {
	if totalQueries < 1 {
		return 0, 0
	}
	if totalQueries == 1 {
		return 0, 1
	}
	if totalQueries == 2 {
		return 1, 1
	}
	if totalQueries == 3 {
		return 1, 2
	}
	// For 4 or more, split roughly evenly, prioritizing uncached if odd.
	numCached = totalQueries / 2
	numUncached = totalQueries - numCached
	return numCached, numUncached
}

// runLatencyBenchmark handles the cached/uncached latency tests.
func (b *Benchmarker) runLatencyBenchmark(servers []config.ServerInfo) {
	numCached, numUncached := calculateLatencyQueryCounts(b.Config.NumQueries)
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
		b.processLatencyResult(res)
	}
}

// processLatencyResult updates the benchmark results based on a single latency query job result.
func (b *Benchmarker) processLatencyResult(res queryJobResult) {
	serverKey := res.serverInfo.String()
	serverResult, ok := b.Results.Results[serverKey]
	if !ok {
		return // Should not happen if initialized correctly
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

// prepareCheckJobs creates a list of query jobs for the enabled checks.
func (b *Benchmarker) prepareCheckJobs(servers []config.ServerInfo) []queryJob {
	var checkJobsList []queryJob
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
	return checkJobsList
}

// runChecksConcurrently runs DNSSEC, NXDOMAIN, Rebinding, Accuracy, Dotcom checks.
func (b *Benchmarker) runChecksConcurrently(servers []config.ServerInfo) {
	checkJobsList := b.prepareCheckJobs(servers)
	if len(checkJobsList) == 0 {
		return // No checks enabled
	}

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
		b.processCheckResult(res)
	}
}

// processCheckResult updates the benchmark results based on a single check job result.
func (b *Benchmarker) processCheckResult(res queryJobResult) {
	serverKey := res.serverInfo.String()
	serverResult, ok := b.Results.Results[serverKey]
	if !ok {
		return // Should not happen
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

// queryWorker executes query jobs (used for both latency and checks).
func (b *Benchmarker) queryWorker(wg *sync.WaitGroup, jobs <-chan queryJob, results chan<- queryJobResult) {
	defer wg.Done()
	for job := range jobs {
		_ = b.Limiter.Wait(context.Background())                                                 // Apply rate limit
		queryResult := PerformQueryFunc(job.serverInfo, job.domain, job.qType, b.Config.Timeout) // Use the variable
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

// checkADFlag checks if the Authenticated Data (AD) flag is set in the DNS response.
// This indicates DNSSEC validation by the resolver.
func checkADFlag(result QueryResult) bool {
	if result.Error != nil || result.Response == nil {
		return false
	}
	return result.Response.AuthenticatedData
}

// checkNXDOMAINHijack checks for NXDOMAIN hijacking.
// It determines if a server returns a NOERROR response with records for a deliberately non-existent domain,
// which is indicative of hijacking.
func checkNXDOMAINHijack(result QueryResult) bool {
	if result.Error != nil || result.Response == nil {
		return false
	}
	rcode := result.Response.Rcode
	if rcode == dns.RcodeNameError {
		return false // Expected NXDOMAIN
	}
	if rcode == dns.RcodeSuccess && len(result.Response.Answer) > 0 {
		return true // Unexpected NOERROR with answer for NXDOMAIN query
	}
	return false // Other cases: SERVFAIL, etc., or legitimate NXDOMAIN
}

// checkRebindingProtection checks for DNS rebinding protection.
// It queries a domain known to trigger rebinding attempts and expects either an error or no answer.
// A successful response with answers indicates lack of rebinding protection.
func checkRebindingProtection(result QueryResult) bool {
	if result.Error != nil {
		return true // Error implies protection (e.g., refused to resolve private IP)
	}
	if result.Response == nil {
		return true // No response also implies protection
	}
	if result.Response.Rcode != dns.RcodeSuccess {
		return true // Non-success Rcode also implies protection
	}
	if len(result.Response.Answer) == 0 {
		return true // No answer implies protection
	}
	return false // Received NOERROR with answers - vulnerable to rebinding
}

// checkResponseAccuracy checks if the DNS response is accurate by comparing the answer to an expected IP.
// It verifies that at least one A record in the answer matches the expected IP address.
func checkResponseAccuracy(result QueryResult, expectedIP string) bool {
	if result.Error != nil || result.Response == nil || result.Response.Rcode != dns.RcodeSuccess {
		return false // Not accurate if error, no response, or not successful
	}
	// TODO: Handle multiple expected IPs if accuracy file format allows it.
	for _, rr := range result.Response.Answer {
		if aRecord, ok := rr.(*dns.A); ok {
			if aRecord.A.String() == expectedIP {
				return true // Found matching A record
			}
		}
		// TODO: Add check for AAAA records if needed/specified.
	}
	return false // No matching A record found
}
