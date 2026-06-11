package dnsquery

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/taihen/dns-benchmark/pkg/config"
)

func TestFormatProgress(t *testing.T) {
	assert.Equal(t, "Benchmarking: 0/10 queries (0%)", formatProgress(0, 10))
	assert.Equal(t, "Benchmarking: 412/950 queries (43%)", formatProgress(412, 950))
	assert.Equal(t, "Benchmarking: 10/10 queries (100%)", formatProgress(10, 10))
}

func TestProgressTracker_NilSafe(t *testing.T) {
	var p *progressTracker
	assert.NotPanics(t, func() {
		p.increment()
		p.stop()
	})
}

func TestBenchmarker_Run_WritesProgressToWriter(t *testing.T) {
	serverInfo := config.ServerInfo{Address: "1.1.1.1:53", Protocol: config.UDP, Hostname: "1.1.1.1"}
	cachedDomain := "cached.example.com"
	cfg := &config.Config{
		Servers:     []config.ServerInfo{serverInfo},
		NumQueries:  4, // 2 cached + 2 uncached
		Timeout:     time.Second,
		Concurrency: 2,
		RateLimit:   0,
		QueryType:   "A",
		Domain:      cachedDomain,
		CheckDotcom: true, // +1 check job -> 5 total
	}

	mockFunc := func(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(domain), qType)
		rcode := dns.RcodeSuccess
		if domain != cachedDomain {
			rcode = dns.RcodeNameError
		}
		return QueryResult{Latency: time.Millisecond, Response: createTestResponse(req, rcode)}
	}
	restore := mockAllProtocolFuncs(mockFunc)
	defer restore()

	var buf bytes.Buffer
	benchmarker := NewBenchmarker(cfg)
	defer benchmarker.Close()
	benchmarker.ProgressWriter = &buf

	benchmarker.Run(context.Background())

	out := buf.String()
	assert.Contains(t, out, "5/5", "final progress state should be rendered")
	assert.Contains(t, out, "queries")
}

func TestBenchmarker_Run_NoProgressWriterWritesNothing(t *testing.T) {
	serverInfo := config.ServerInfo{Address: "1.1.1.1:53", Protocol: config.UDP, Hostname: "1.1.1.1"}
	cfg := &config.Config{
		Servers:     []config.ServerInfo{serverInfo},
		NumQueries:  2,
		Timeout:     time.Second,
		Concurrency: 1,
		RateLimit:   0,
		QueryType:   "A",
		Domain:      "cached.example.com",
	}
	mockFunc := func(ctx context.Context, serverInfo config.ServerInfo, domain string, qType uint16, timeout time.Duration) QueryResult {
		return QueryResult{Latency: time.Millisecond, Response: nxdomainResponse()}
	}
	restore := mockAllProtocolFuncs(mockFunc)
	defer restore()

	benchmarker := NewBenchmarker(cfg)
	defer benchmarker.Close()
	assert.NotPanics(t, func() {
		benchmarker.Run(context.Background())
	})
}
