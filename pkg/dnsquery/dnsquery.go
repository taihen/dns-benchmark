package dnsquery

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
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

const (
	dnssecCheckDomain         = "dnssec-failed.org."
	nxdomainCheckDomainPrefix = "nxdomain-test-"
	nxdomainCheckDomainSuffix = ".invalid."

	dotcomCheckPrefix = "dnsbench-dotcom-"
	dotcomCheckSuffix = ".com."
	// uncachedQuerySuffix is the zone for random uncached latency names.
	uncachedQuerySuffix = ".net."
	dohUserAgent        = "dns-benchmark/1.0 (+https://github.com/taihen/dns-benchmark)"

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

// QueryOutcome classifies the outcome of a DNS query attempt.
type QueryOutcome string

const (
	OutcomeSuccess    QueryOutcome = "success"
	OutcomeDNSFailure QueryOutcome = "dns_failure"
	OutcomeTimeout    QueryOutcome = "timeout"
	OutcomeTransport  QueryOutcome = "transport_error"
	OutcomeMalformed  QueryOutcome = "malformed_response"
)

// quicConnection represents a pooled QUIC connection
type quicConnection struct {
	session   *quic.Conn
	lastUsed  time.Time
	createdAt time.Time
	inUse     bool
}

// quicConnectionPool manages QUIC connections for DoQ queries
type quicConnectionPool struct {
	mu           sync.RWMutex
	connections  map[string][]*quicConnection // key: serverAddress|serverName
	dialing      map[string]int               // in-flight dials reserving pool slots
	closed       bool
	cleanup      chan struct{}
	cleanupDone  chan struct{}
	shutdownOnce sync.Once
}

func newQuicConnectionPool() *quicConnectionPool {
	pool := &quicConnectionPool{
		connections: make(map[string][]*quicConnection),
		dialing:     make(map[string]int),
		cleanup:     make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	go pool.startCleanup()
	return pool
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
					_ = conn.session.CloseWithError(0, "cleanup")
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

// getConnection retrieves or creates a QUIC connection for the server.
// The returned bool indicates whether the session is pooled. The pool lock is
// never held while dialling, so an unreachable endpoint cannot delay queries
// to other endpoints; in-flight dials reserve pool slots to keep the limit.
func (p *quicConnectionPool) getConnection(ctx context.Context, serverAddr string, tlsConfig *tls.Config) (*quic.Conn, bool, error) {
	key := serverAddr + "|" + tlsConfig.ServerName

	p.mu.Lock()
	for _, conn := range p.connections[key] {
		if conn.inUse {
			continue
		}
		select {
		case <-conn.session.Context().Done():
			// Connection is closed; cleanup removes it.
			continue
		default:
			conn.inUse = true
			conn.lastUsed = time.Now()
			p.mu.Unlock()
			return conn.session, true, nil
		}
	}
	// Reserve a pool slot when under the limit; otherwise dial a temporary
	// connection that the caller closes after use.
	pooled := !p.closed && len(p.connections[key])+p.dialing[key] < maxPooledConnections
	if pooled {
		p.dialing[key]++
	}
	p.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	session, err := quic.DialAddrEarly(dialCtx, serverAddr, tlsConfig, nil)

	if !pooled {
		if err != nil {
			return nil, false, err
		}
		return session, false, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialing[key]--
	if p.dialing[key] == 0 {
		delete(p.dialing, key)
	}
	if err != nil {
		return nil, false, err
	}
	if p.closed {
		// The pool shut down during the dial; hand back a temporary session.
		return session, false, nil
	}
	now := time.Now()
	p.connections[key] = append(p.connections[key], &quicConnection{
		session:   session,
		lastUsed:  now,
		createdAt: now,
		inUse:     true,
	})
	return session, true, nil
}

// returnConnection marks a connection as available for reuse
func (p *quicConnectionPool) returnConnection(serverAddr string, session *quic.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conns := range p.connections {
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
				_ = conn.session.CloseWithError(0, "shutdown")
			}
		}
	}
	p.connections = make(map[string][]*quicConnection)
	p.closed = true
}

// shutdownPool gracefully shuts down the connection pool
func (p *quicConnectionPool) shutdownPool() {
	p.shutdownOnce.Do(func() {
		close(p.cleanup)
		<-p.cleanupDone
	})
}

// DNSExchanger permits local fixtures and alternate DNS clients.
type DNSExchanger interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

// performQueryWithClient exchanges and validates a DNS message using an injectable client.
func performQueryWithClient(ctx context.Context, client DNSExchanger, serverAddr, domain string, qType uint16, timeout time.Duration) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.SetEdns0(4096, true) // Opt-in to DNSSEC requests via EDNS0

	startTime := time.Now()
	response, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	latency := time.Since(startTime)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return QueryResult{Error: fmt.Errorf("query timed out after %v", timeout)}
		}
		return QueryResult{Error: fmt.Errorf("query failed: %w", err)}
	}
	if response == nil {
		return QueryResult{Error: &ResponseValidationError{Reason: "query succeeded but response was nil"}}
	}
	if err := validateResponseMatchesQuery(msg, response); err != nil {
		return QueryResult{Error: fmt.Errorf("invalid dns response: %w", err)}
	}
	return QueryResult{Latency: latency, Response: response, Error: nil}
}

// performUDPQuery performs a DNS query over UDP.
func performUDPQuery(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	client := &dns.Client{Net: networkForFamily("udp", serverInfo.IPFamily), Timeout: timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	return performQueryWithClient(ctx, client, serverInfo.Address, domain, qType, timeout)
}

// performTCPQuery performs a DNS query over TCP.
func performTCPQuery(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	client := &dns.Client{Net: networkForFamily("tcp", serverInfo.IPFamily), Timeout: timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	return performQueryWithClient(ctx, client, serverInfo.Address, domain, qType, timeout)
}

// performDoTQuery performs a DNS query over TLS (DoT).
// It configures TLS settings and uses the "tcp-tls" network.
func performDoTQuery(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	tlsConfig := &tls.Config{
		ServerName: authenticationName(serverInfo),
		RootCAs:    serverInfo.TLSRootCAs,
		MinVersion: tls.VersionTLS12,
	}
	client := &dns.Client{
		Net:       networkForFamily("tcp", serverInfo.IPFamily) + "-tls",
		TLSConfig: tlsConfig,
		Timeout:   timeout, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout,
	}
	return performQueryWithClient(ctx, client, serverInfo.Address, domain, qType, timeout)
}

// performDoHQuery performs a DNS query over HTTPS (DoH).
// It constructs an HTTP request with the DNS query message and sends it to the DoH server.
// If httpClient is nil, a new client is created for this query.
func performDoHQuery(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration, httpClient *http.Client) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.SetEdns0(4096, true)

	packedMsg, err := msg.Pack()
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to pack DoH message: %w", err)}
	}

	if httpClient == nil {
		httpClient = newDoHClient(serverInfo, timeout)
		defer httpClient.CloseIdleConnections()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
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

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return QueryResult{Error: fmt.Errorf("doh query timed out after %v", timeout)}
		}
		return QueryResult{Error: fmt.Errorf("doh http request failed: %w", err)}
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		return QueryResult{Error: fmt.Errorf("doh query failed with status code %d", httpResp.StatusCode)}
	}

	mediaType, _, typeErr := mime.ParseMediaType(httpResp.Header.Get("Content-Type"))
	if typeErr != nil || mediaType != "application/dns-message" {
		return QueryResult{Error: &ResponseValidationError{Reason: "invalid DoH content type"}}
	}
	const maxDoHResponseSize = 65535
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxDoHResponseSize+1))
	if len(body) > maxDoHResponseSize {
		return QueryResult{Error: &ResponseValidationError{Reason: "DoH response exceeds 65535 bytes"}}
	}
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to read DoH response body: %w", err)}
	}

	response := new(dns.Msg)
	if err = response.Unpack(body); err != nil {
		return QueryResult{Error: fmt.Errorf("failed to unpack DoH response: %w", err)}
	}
	if err := validateResponseMatchesQuery(msg, response); err != nil {
		return QueryResult{Error: fmt.Errorf("invalid DoH response: %w", err)}
	}

	return QueryResult{Latency: time.Since(startTime), Response: response, Error: nil}
}

// performDoQQuery performs a DNS query over QUIC (DoQ).
// It uses connection pooling to reuse QUIC sessions for better performance.
func performDoQQuery(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration, pool *quicConnectionPool) QueryResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)
	msg.Id = 0
	msg.SetEdns0(4096, true)

	packedMsg, err := msg.Pack()
	if err != nil {
		return QueryResult{Error: fmt.Errorf("failed to pack DoQ message: %w", err)}
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"doq"}, // ALPN for DoQ
		ServerName: authenticationName(serverInfo),
		RootCAs:    serverInfo.TLSRootCAs,
		MinVersion: tls.VersionTLS13,
	}

	startTime := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	serverAddress := serverInfo.Address
	if serverInfo.IPFamily == "ipv4" || serverInfo.IPFamily == "ipv6" {
		host, port, err := net.SplitHostPort(serverAddress)
		if err != nil {
			return QueryResult{Error: err}
		}
		if net.ParseIP(host) == nil {
			network := "ip4"
			if serverInfo.IPFamily == "ipv6" {
				network = "ip6"
			}
			addresses, err := net.DefaultResolver.LookupIP(ctx, network, host)
			if err != nil {
				return QueryResult{Error: err}
			}
			if len(addresses) == 0 {
				return QueryResult{Error: fmt.Errorf("no %s address for %s", network, host)}
			}
			serverAddress = net.JoinHostPort(addresses[0].String(), port)
		}
	}
	// Get QUIC connection from pool
	session, pooled, err := pool.getConnection(ctx, serverAddress, tlsConfig)
	if err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to get connection for %s: %w", serverInfo.Address, err)}
	}

	// Return pooled connection, or close temporary one.
	defer func() {
		if pooled {
			pool.returnConnection(serverAddress, session)
			return
		}
		_ = session.CloseWithError(0, "temporary session complete")
	}()

	// Open stream
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to open stream: %w", err)}
	}

	defer stream.CancelRead(0)
	defer stream.CancelWrite(0)
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() { stream.CancelRead(0); stream.CancelWrite(0) })
	defer stopCancel()
	// Write query with length prefix
	lenPrefix := []byte{byte(len(packedMsg) >> 8), byte(len(packedMsg))}
	if _, err = stream.Write(append(lenPrefix, packedMsg...)); err != nil {
		stream.CancelRead(0) // Cancel reading if write fails
		return QueryResult{Error: fmt.Errorf("doq failed to write query: %w", err)}
	}
	_ = stream.Close() // Close write side

	// Read response length prefix
	lenBuf := make([]byte, 2)
	if _, err = io.ReadFull(stream, lenBuf); err != nil {
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
	if _, err = io.ReadFull(stream, respBuf); err != nil {
		return QueryResult{Error: fmt.Errorf("doq failed to read response body: %w", err)}
	}
	latency := time.Since(startTime)

	response := new(dns.Msg)
	if err = response.Unpack(respBuf); err != nil {
		return QueryResult{Error: fmt.Errorf("failed to unpack DoQ response: %w", err)}
	}
	if err := validateResponseMatchesQuery(msg, response); err != nil {
		return QueryResult{Error: fmt.Errorf("invalid DoQ response: %w", err)}
	}

	return QueryResult{Latency: latency, Response: response, Error: nil}
}

// performQuery executes a DNS query with proper dependency injection for HTTP clients.
func (b *Benchmarker) performQuery(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
	switch serverInfo.Protocol {
	case config.UDP:
		return performUDPQueryFunc(ctx, serverInfo, domain, qType, timeout)
	case config.TCP:
		return performTCPQueryFunc(ctx, serverInfo, domain, qType, timeout)
	case config.DOT:
		return performDoTQueryFunc(ctx, serverInfo, domain, qType, timeout)
	case config.DOH:
		httpClient := b.dohClients[serverInfo.String()]
		return performDoHQueryFunc(ctx, serverInfo, domain, qType, timeout, httpClient)
	case config.DOQ:
		return performDoQQueryFunc(ctx, serverInfo, domain, qType, timeout, b.quicPool)
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
	skipped    bool               // Job not attempted (or aborted) due to cancellation
}

// Benchmarker manages the benchmarking process.
type Benchmarker struct {
	Config  *config.Config
	Results *analysis.BenchmarkResults
	Limiter *rate.Limiter
	// ProgressWriter, when non-nil, receives an in-place progress line during
	// Run (intended for an interactive stderr). Nil disables progress output.
	ProgressWriter io.Writer
	dohClients     map[string]*http.Client // HTTP clients for DoH servers
	quicPool       *quicConnectionPool
	progress       *progressTracker
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
			dohClients[server.String()] = newDoHClient(server, cfg.Timeout)
		}
	}

	return &Benchmarker{
		Config:     cfg,
		Results:    analysis.NewBenchmarkResults(),
		Limiter:    limiter,
		dohClients: dohClients,
		quicPool:   newQuicConnectionPool(),
	}
}

// Close releases benchmark-scoped resources.
func (b *Benchmarker) Close() {
	if b == nil || b.quicPool == nil {
		return
	}
	b.quicPool.shutdownPool()
	for _, client := range b.dohClients {
		client.CloseIdleConnections()
	}
}

// Run performs the benchmark against the configured servers. Cancelling ctx
// stops the benchmark early; results collected so far remain valid, with the
// unattempted queries recorded as skipped.
func (b *Benchmarker) Run(ctx context.Context) *analysis.BenchmarkResults {
	servers := b.Config.Servers
	b.Results = analysis.NewBenchmarkResults()
	b.Results.Metadata.StartedAt = time.Now().UTC()
	b.Results.Metadata.RequestedQueries = b.Config.NumQueries
	defer func() {
		b.Results.Metadata.Interrupted = ctx.Err() != nil
		for _, r := range b.Results.Results {
			b.Results.Metadata.Skipped += r.Skipped
		}
	}()

	// Initialize Results map
	for _, server := range servers {
		b.Results.Results[server.String()] = &analysis.ServerResult{ServerAddress: server.AddressString(), Protocol: server.Protocol.Label(), Metadata: server.Metadata, Checks: initialCheckStates(b.Config, server)}
	}

	if b.ProgressWriter != nil {
		numCached, numUncached := calculateLatencyQueryCounts(b.Config.NumQueries)
		totalJobs := len(servers)*(numCached+numUncached) + len(b.prepareCheckJobs(servers))
		b.progress = newProgressTracker(b.ProgressWriter, int64(totalJobs))
		defer b.progress.stop()
	}

	// Run Latency Benchmark
	b.runLatencyBenchmark(ctx, servers)

	// Run Specific Checks Concurrently
	b.runChecksConcurrently(ctx, servers)

	return b.Results
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
func (b *Benchmarker) runLatencyBenchmark(ctx context.Context, servers []config.ServerInfo) {
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
		go b.queryWorker(ctx, &wg, jobs, resultsChan)
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
	}

	// Enqueue jobs round-robin across servers so an interrupted run still has
	// samples for every server instead of exhausting the first server's queue.
	//
	// The corpus is a per-run list of name templates shared by every endpoint, so
	// all endpoints get the same workload (identified by CorpusID). Each uncached
	// template is made unique per endpoint by endpointQueryName; otherwise the
	// first endpoint to ask would warm the cache shared by the provider's other
	// endpoints (other transports and families) and their "uncached" samples
	// would really be cache hits.
	corpus := make([]string, totalLatencyJobsPerServer)
	for i := range corpus {
		corpus[i] = cachedDomain
		if i >= numCached {
			corpus[i] = generateUniqueDomain(nxdomainCheckDomainPrefix, "")
		}
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s", qType, strings.Join(corpus, "\n"))))
	b.Results.Metadata.CorpusID = fmt.Sprintf("sha256:%x", hash)
	for i := 0; i < totalLatencyJobsPerServer; i++ {
		for _, server := range servers {
			if i < numCached {
				jobs <- queryJob{serverInfo: server, domain: cachedDomain, qType: qType, queryType: analysis.Cached}
			} else {
				uncachedDomain := endpointQueryName(corpus[i], uncachedQuerySuffix, server)
				jobs <- queryJob{serverInfo: server, domain: uncachedDomain, qType: qType, queryType: analysis.Uncached}
			}
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

	// Cancellation skips are not the server's fault; track separately.
	if res.skipped {
		serverResult.Skipped++
		return
	}

	policyResponse := false
	if response := res.result.Response; response != nil {
		if opt := response.IsEdns0(); opt != nil {
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					serverResult.ExtendedDNSErrors = append(serverResult.ExtendedDNSErrors, ede.InfoCode)
					if ede.InfoCode >= 15 && ede.InfoCode <= 18 {
						policyResponse = true
					}
				}
			}
		}
	}
	if policyResponse {
		serverResult.PolicyResponses++
	}
	// Record latency for any valid DNS response, regardless of rcode.
	// NXDOMAIN is the expected response for uncached queries to random domains.
	if res.result.Error == nil && res.result.Response != nil {
		if res.result.Response.Truncated {
			// Counted as a failed probe in its own category; Errors equals the sum
			// of the timeout, transport, malformed and truncated counters.
			serverResult.TruncatedResponses++
			serverResult.Errors++
			if b.Config.Verbose {
				fmt.Fprintf(os.Stderr, "Latency query for %s (%s) was truncated; not scored\n", serverKey, res.queryType)
			}
			return
		}
		if isUnexpectedLatencyRcode(res.queryType, res.result.Response.Rcode) {
			serverResult.DNSFailures++
		}
		switch res.queryType {
		case analysis.Cached:
			serverResult.CachedLatencies = append(serverResult.CachedLatencies, res.result.Latency)
		case analysis.Uncached:
			serverResult.UncachedLatencies = append(serverResult.UncachedLatencies, res.result.Latency)
		}
		return
	}

	serverResult.Errors++
	outcome := classifyQueryResult(res.result)
	switch outcome {
	case OutcomeTimeout:
		serverResult.TimeoutErrors++
	case OutcomeMalformed:
		serverResult.MalformedResponses++
	default:
		serverResult.TransportErrors++
	}
	if b.Config.Verbose {
		fmt.Fprintf(os.Stderr, "Latency query error for %s (%s): %v\n", serverKey, res.queryType, res.result.Error)
	}
}

func isUnexpectedLatencyRcode(queryType analysis.QueryType, rcode int) bool {
	switch queryType {
	case analysis.Uncached:
		return rcode != dns.RcodeNameError
	default:
		return rcode != dns.RcodeSuccess
	}
}

// prepareCheckJobs creates a list of query jobs for the enabled checks.
func (b *Benchmarker) prepareCheckJobs(servers []config.ServerInfo) []queryJob {
	var checkJobsList []queryJob
	dotcomTemplate := generateUniqueDomain(dotcomCheckPrefix, "")
	nxDomain := generateUniqueDomain(nxdomainCheckDomainPrefix, nxdomainCheckDomainSuffix)
	for _, server := range servers {
		if b.Config.CheckDNSSEC {
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: dnssecCheckDomain, qType: dns.TypeA, checkType: "dnssec"})
		}
		if b.Config.CheckNXDOMAIN {
			for _, name := range []string{nxDomain, "second." + nxDomain} {
				checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: name, qType: dns.TypeA, checkType: "nxdomain"})
			}
		}
		if b.Config.CheckRebinding && b.Config.RebindingDomain != "" {
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: b.Config.RebindingDomain, qType: dns.TypeA, checkType: "rebinding"})
		}
		if b.Config.CheckFiltering {
			for _, domain := range server.FilteringProbeDomains {
				checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: domain, qType: dns.TypeA, checkType: "filtering"})
			}
		}
		if b.Config.AccuracyCheckFile != "" {
			qtype := uint16(dns.TypeA)
			first := strings.Split(b.Config.AccuracyCheckIP, ",")[0]
			if ip := net.ParseIP(first); ip != nil && ip.To4() == nil {
				qtype = dns.TypeAAAA
			}
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: b.Config.AccuracyCheckDomain, qType: qtype, checkType: "accuracy"})
		}
		if b.Config.CheckDotcom {
			checkJobsList = append(checkJobsList, queryJob{serverInfo: server, domain: endpointQueryName(dotcomTemplate, dotcomCheckSuffix, server), qType: dns.TypeA, checkType: "dotcom"})
		}
	}
	return checkJobsList
}

// runChecksConcurrently runs DNSSEC, NXDOMAIN, Rebinding, Accuracy, Dotcom checks.
func (b *Benchmarker) runChecksConcurrently(ctx context.Context, servers []config.ServerInfo) {
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
		go b.queryWorker(ctx, &wg, jobs, resultsChan)
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

	// Skipped checks stay in their inconclusive (nil) state.
	if res.skipped {
		return
	}

	if res.result.Error != nil && b.Config.Verbose {
		fmt.Fprintf(os.Stderr, "%s check error for %s: %v\n", strings.ToUpper(res.checkType), serverKey, res.result.Error)
	}

	if serverResult.Checks == nil {
		serverResult.Checks = initialCheckStates(b.Config, res.serverInfo)
	}
	// Update results based on check type
	switch res.checkType {
	case "dnssec":
		serverResult.SupportsDNSSEC = checkDNSSECValidation(res.result)
		serverResult.Checks["dnssec"] = analysis.StateFromBool(serverResult.SupportsDNSSEC, false)
	case "nxdomain":
		value := checkNXDOMAINHijack(res.result)
		serverResult.NXDOMAINProbes++
		if value == nil {
			serverResult.NXDOMAINInconclusive = true
		}
		if value != nil && *value {
			serverResult.HijacksNXDOMAIN = boolPtr(true)
		} else if serverResult.HijacksNXDOMAIN == nil || !*serverResult.HijacksNXDOMAIN {
			if serverResult.NXDOMAINProbes >= 2 && !serverResult.NXDOMAINInconclusive {
				serverResult.HijacksNXDOMAIN = boolPtr(false)
			}
		}
		serverResult.Checks["nxdomain"] = analysis.StateFromBool(serverResult.HijacksNXDOMAIN, true)
	case "rebinding":
		serverResult.BlocksRebinding = checkRebindingProtection(res.result)
		serverResult.Checks["rebinding"] = analysis.StateFromBool(serverResult.BlocksRebinding, false)
	case "filtering":
		state := analysis.Inconclusive
		if conclusiveResponse(res.result) && res.result.Response.Rcode == dns.RcodeSuccess && len(res.result.Response.Answer) > 0 {
			state = analysis.Fail
			for _, rr := range res.result.Response.Answer {
				if a, ok := rr.(*dns.A); ok && a.A.IsUnspecified() {
					state = analysis.Pass
				}
			}
		}
		serverResult.FilteringProbes++
		serverResult.FilteringStates = append(serverResult.FilteringStates, state)
		serverResult.Checks["filtering"] = combineProbeStates(serverResult.FilteringStates, len(res.serverInfo.FilteringProbeDomains))
	case "accuracy":
		serverResult.IsAccurate = checkResponseAccuracy(res.result, b.Config.AccuracyCheckIP)
		serverResult.Checks["accuracy"] = analysis.StateFromBool(serverResult.IsAccurate, false)
	case "dotcom":
		if conclusiveResponse(res.result) {
			latency := res.result.Latency
			serverResult.DotcomLatency = &latency
		}
	}
}

// queryWorker executes query jobs (used for both latency and checks).
// After ctx is cancelled, remaining jobs are drained and reported as skipped
// so partial results stay valid.
func (b *Benchmarker) queryWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan queryJob, results chan<- queryJobResult) {
	defer wg.Done()
	for job := range jobs {
		results <- b.executeJob(ctx, job)
		b.progress.increment()
	}
}

// executeJob runs a single query job, mapping cancellation to a skipped result.
func (b *Benchmarker) executeJob(ctx context.Context, job queryJob) queryJobResult {
	skippedResult := queryJobResult{
		serverInfo: job.serverInfo,
		queryType:  job.queryType,
		checkType:  job.checkType,
		skipped:    true,
	}

	if ctx.Err() != nil {
		return skippedResult
	}
	if err := b.Limiter.Wait(ctx); err != nil {
		if ctx.Err() != nil {
			return skippedResult
		}
		return queryJobResult{
			serverInfo: job.serverInfo,
			result: QueryResult{
				Error: fmt.Errorf("rate limiter wait failed: %w", err),
			},
			queryType: job.queryType,
			checkType: job.checkType,
		}
	}
	queryResult := b.performQuery(ctx, job.serverInfo, job.domain, job.qType, b.Config.Timeout)
	if queryResult.Error != nil && ctx.Err() != nil {
		// Query was aborted by cancellation, not by the server.
		return skippedResult
	}
	return queryJobResult{
		serverInfo: job.serverInfo,
		result:     queryResult,
		queryType:  job.queryType,
		checkType:  job.checkType,
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

// endpointQueryName derives an endpoint-specific name from a shared corpus
// template. The endpoint token is appended to the same label rather than added
// as a subdomain: a subdomain of a shared non-existent name could be answered
// from a cached NXDOMAIN for its parent (RFC 8020), defeating the uniqueness.
func endpointQueryName(template, suffix string, server config.ServerInfo) string {
	sum := sha256.Sum256([]byte(server.String()))
	return fmt.Sprintf("%s-%x%s", template, sum[:4], suffix)
}

func boolPtr(value bool) *bool {
	return &value
}

// ResponseValidationError indicates a DNS response failed structural validation
// (wrong ID, missing Response bit, question mismatch, etc.).
type ResponseValidationError struct {
	Reason string
}

func (e *ResponseValidationError) Error() string {
	return e.Reason
}

func validateResponseMatchesQuery(query *dns.Msg, response *dns.Msg) error {
	if response == nil {
		return &ResponseValidationError{Reason: "dns response was nil"}
	}
	if !response.Response {
		return &ResponseValidationError{Reason: "dns message is not marked as a response"}
	}
	if response.Id != query.Id {
		return &ResponseValidationError{Reason: "dns response ID mismatch"}
	}
	if len(response.Question) != len(query.Question) {
		return &ResponseValidationError{Reason: "dns question count mismatch"}
	}
	for i := range query.Question {
		if response.Question[i] != query.Question[i] {
			return &ResponseValidationError{Reason: "dns question mismatch"}
		}
	}
	return nil
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out")
}

func isMalformedResponseError(err error) bool {
	if err == nil {
		return false
	}
	var valErr *ResponseValidationError
	if errors.As(err, &valErr) {
		return true
	}
	// External library (miekg/dns) unpack errors are also malformed responses.
	return strings.Contains(strings.ToLower(err.Error()), "unpack")
}

func classifyQueryResult(result QueryResult) QueryOutcome {
	if result.Error != nil {
		if isTimeoutError(result.Error) {
			return OutcomeTimeout
		}
		if isMalformedResponseError(result.Error) {
			return OutcomeMalformed
		}
		return OutcomeTransport
	}
	if result.Response == nil {
		return OutcomeMalformed
	}
	if result.Response.Rcode != dns.RcodeSuccess {
		return OutcomeDNSFailure
	}
	return OutcomeSuccess
}

// --- Check Helper Functions ---

// conclusiveResponse reports whether a check result can be used as evidence.
// Errors, missing responses and truncated (TC) replies are inconclusive: a
// truncated answer section cannot prove the absence of records.
func conclusiveResponse(result QueryResult) bool {
	return result.Error == nil && result.Response != nil && !result.Response.Truncated
}

// checkDNSSECValidation checks whether the resolver performs DNSSEC validation.
// The check query uses a deliberately broken DNSSEC domain, so validating resolvers
// should return SERVFAIL while non-validating resolvers typically return NOERROR.
func checkDNSSECValidation(result QueryResult) *bool {
	if !conclusiveResponse(result) {
		return nil
	}
	switch result.Response.Rcode {
	case dns.RcodeServerFailure:
		if opt := result.Response.IsEdns0(); opt != nil {
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok && ede.InfoCode >= 6 && ede.InfoCode <= 12 {
					return boolPtr(true)
				}
			}
		}
		return nil
	case dns.RcodeSuccess:
		return boolPtr(false)
	default:
		return nil
	}
}

// checkNXDOMAINHijack checks for NXDOMAIN hijacking.
// It determines if a server returns a NOERROR response with records for a deliberately non-existent domain,
// which is indicative of hijacking.
func checkNXDOMAINHijack(result QueryResult) *bool {
	if !conclusiveResponse(result) {
		return nil
	}
	rcode := result.Response.Rcode
	if rcode == dns.RcodeNameError {
		return boolPtr(false) // Expected NXDOMAIN
	}
	if rcode == dns.RcodeSuccess && len(result.Response.Answer) > 0 {
		return boolPtr(true) // Unexpected NOERROR with answer for NXDOMAIN query
	}
	return nil // Inconclusive (SERVFAIL, REFUSED, or NOERROR with empty answers)
}

// checkRebindingProtection checks for DNS rebinding protection.
// It queries a controlled domain that resolves to a private address. Protection
// is reported only when the resolver answers NOERROR without address records,
// which is how rebinding filters strip private answers. Address records mean
// the private answer was passed through. NXDOMAIN and REFUSED are inconclusive:
// they also result from a mistyped or lapsed test domain, or a resolver that
// refuses the client, and so are not evidence of rebinding protection.
func checkRebindingProtection(result QueryResult) *bool {
	if !conclusiveResponse(result) || result.Response.Rcode != dns.RcodeSuccess {
		return nil
	}
	for _, rr := range result.Response.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			return boolPtr(false) // Address records passed through: vulnerable to rebinding
		}
	}
	return boolPtr(true) // NOERROR without address records
}

// checkResponseAccuracy checks if the DNS response is accurate by comparing the answer to an expected IP.
// It verifies that at least one A record in the answer matches the expected IP address.
func checkResponseAccuracy(result QueryResult, expectedIP string) *bool {
	if !conclusiveResponse(result) {
		return nil
	}
	if result.Response.Rcode != dns.RcodeSuccess {
		return nil
	}
	expected := []net.IP{}
	for _, value := range strings.Split(expectedIP, ",") {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil
		}
		expected = append(expected, ip)
	}
	found := false
	for _, rr := range result.Response.Answer {
		var address net.IP
		switch record := rr.(type) {
		case *dns.A:
			address = record.A
		case *dns.AAAA:
			address = record.AAAA
		}
		if address == nil {
			continue
		}
		found = true
		for _, ip := range expected {
			if address.Equal(ip) {
				return boolPtr(true)
			}
		}
	}
	if !found {
		return nil
	}
	return boolPtr(false)
}
