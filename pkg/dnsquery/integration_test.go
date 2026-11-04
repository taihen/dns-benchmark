package dnsquery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/catalog"
	"github.com/taihen/dns-benchmark/pkg/config"
)

func fixtureCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "resolver.fixture"}, DNSNames: []string{"resolver.fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func fixtureReply(query *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
	return reply
}

func TestLocalDNSWireTransports(t *testing.T) {
	certificate, roots := fixtureCertificate(t)
	for _, protocol := range []config.ProtocolType{config.UDP, config.TCP, config.DOT} {
		t.Run(string(protocol), func(t *testing.T) {
			ready := make(chan struct{})
			done := make(chan error, 1)
			server := &dns.Server{Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { _ = w.WriteMsg(fixtureReply(q)) }), NotifyStartedFunc: func() { close(ready) }}
			var address string
			if protocol == config.UDP {
				socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				server.PacketConn = socket
				address = socket.LocalAddr().String()
			} else {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				address = listener.Addr().String()
				if protocol == config.DOT {
					listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				}
				server.Listener = listener
			}
			go func() { done <- server.ActivateAndServe() }()
			<-ready
			defer func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) }()
			info := config.ServerInfo{Address: address, Hostname: "127.0.0.1", Protocol: protocol, TLSRootCAs: roots, Metadata: catalog.Metadata{TLSServerName: "resolver.fixture", IPFamily: "ipv4"}}
			var result QueryResult
			switch protocol {
			case config.UDP:
				result = performUDPQuery(context.Background(), info, "example.test", dns.TypeA, time.Second)
			case config.TCP:
				result = performTCPQuery(context.Background(), info, "example.test", dns.TypeA, time.Second)
			case config.DOT:
				result = performDoTQuery(context.Background(), info, "example.test", dns.TypeA, time.Second)
			}
			require.NoError(t, result.Error)
			require.NotNil(t, result.Response)
			assert.Len(t, result.Response.Answer, 1)
			if protocol == config.DOT {
				info.TLSServerName = "wrong.fixture"
				assert.Error(t, performDoTQuery(context.Background(), info, "example.test", dns.TypeA, time.Second).Error)
			}
		})
	}
}

// paddedReply returns a valid packed reply to query whose total size is
// exactly size bytes, using EDNS0 padding (RFC 7830).
func paddedReply(t *testing.T, query *dns.Msg, size int) []byte {
	t.Helper()
	reply := fixtureReply(query)
	reply.SetEdns0(4096, false)
	base, err := reply.Pack()
	require.NoError(t, err)
	padding := size - len(base) - 4 // option code and length
	require.GreaterOrEqual(t, padding, 0)
	opt := reply.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, padding)})
	packed, err := reply.Pack()
	require.NoError(t, err)
	require.Len(t, packed, size)
	return packed
}

func TestLocalDoHWireAndValidation(t *testing.T) {
	const limit = 65535
	tests := []struct {
		name        string
		contentType string
		body        func(t *testing.T, q *dns.Msg) []byte
		wantReason  string // empty means the query must succeed
	}{
		{name: "valid", contentType: "application/dns-message"},
		{name: "valid at the size limit", contentType: "application/dns-message", body: func(t *testing.T, q *dns.Msg) []byte { return paddedReply(t, q, limit) }},
		{name: "invalid type", contentType: "text/html", wantReason: "invalid DoH content type"},
		{name: "missing type", contentType: "", wantReason: "invalid DoH content type"},
		{
			// A well-formed DNS message one byte over the limit, so only the
			// size bound can reject it.
			name: "valid message one byte over the limit", contentType: "application/dns-message", wantReason: "exceeds 65535 bytes",
			body: func(t *testing.T, q *dns.Msg) []byte { return paddedReply(t, q, limit+1) },
		},
		// A DoH reply is not checked by miekg's exchange, so these pin the
		// anti-spoofing check that matches the reply to the query.
		{name: "not marked as a response", contentType: "application/dns-message", wantReason: "not marked as a response",
			body: mutatedReply(func(m *dns.Msg) { m.Response = false })},
		{name: "wrong ID", contentType: "application/dns-message", wantReason: "ID mismatch",
			body: mutatedReply(func(m *dns.Msg) { m.Id++ })},
		{name: "missing question", contentType: "application/dns-message", wantReason: "question count mismatch",
			body: mutatedReply(func(m *dns.Msg) { m.Question = nil })},
		{name: "wrong question", contentType: "application/dns-message", wantReason: "dns question mismatch",
			body: mutatedReply(func(m *dns.Msg) { m.Question[0].Name = "spoofed.test." })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				packet, _ := io.ReadAll(r.Body)
				q := new(dns.Msg)
				if q.Unpack(packet) != nil {
					w.WriteHeader(400)
					return
				}
				w.Header()["Content-Type"] = []string{tt.contentType}
				body := fixtureReplyBytes(t, q)
				if tt.body != nil {
					body = tt.body(t, q)
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			result := performDoHQuery(context.Background(), config.ServerInfo{Address: server.URL}, "example.test", dns.TypeA, 5*time.Second, server.Client())
			if tt.wantReason == "" {
				require.NoError(t, result.Error)
				assert.Len(t, result.Response.Answer, 1)
				return
			}
			var validationErr *ResponseValidationError
			require.ErrorAs(t, result.Error, &validationErr)
			assert.Contains(t, validationErr.Reason, tt.wantReason)
			assert.Equal(t, OutcomeMalformed, classifyQueryResult(result))
		})
	}
}

// TestLocalDoHStopsReadingOversizedBody checks that the client stops reading a
// hostile, very large DoH body instead of buffering all of it.
func TestLocalDoHStopsReadingOversizedBody(t *testing.T) {
	const bodySize = 256 << 20 // far beyond any socket buffering
	written := make(chan int64, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		n, _ := io.Copy(w, io.LimitReader(zeroReader{}, bodySize))
		written <- n
	}))
	defer server.Close()

	result := performDoHQuery(context.Background(), config.ServerInfo{Address: server.URL}, "example.test", dns.TypeA, 30*time.Second, server.Client())
	var validationErr *ResponseValidationError
	require.ErrorAs(t, result.Error, &validationErr)
	assert.Contains(t, validationErr.Reason, "exceeds 65535 bytes")
	select {
	case n := <-written:
		assert.Less(t, n, int64(bodySize), "client read the entire oversized body")
	case <-time.After(10 * time.Second):
		t.Fatal("server handler did not finish after the client gave up")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// mutatedReply returns a DoH body builder that packs fixtureReply after mutate.
func mutatedReply(mutate func(*dns.Msg)) func(t *testing.T, q *dns.Msg) []byte {
	return func(t *testing.T, q *dns.Msg) []byte {
		t.Helper()
		reply := fixtureReply(q)
		mutate(reply)
		packed, err := reply.Pack()
		require.NoError(t, err)
		return packed
	}
}

func fixtureReplyBytes(t *testing.T, query *dns.Msg) []byte {
	t.Helper()
	packed, err := fixtureReply(query).Pack()
	require.NoError(t, err)
	return packed
}

func TestLocalDoQWireTransport(t *testing.T) {
	certificate, roots := fixtureCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, nil)
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	observedID := make(chan uint16, 1)
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		var size uint16
		if err = binary.Read(stream, binary.BigEndian, &size); err != nil {
			done <- err
			return
		}
		packet := make([]byte, size)
		if _, err = io.ReadFull(stream, packet); err != nil {
			done <- err
			return
		}
		q := new(dns.Msg)
		if err = q.Unpack(packet); err != nil {
			done <- err
			return
		}
		observedID <- q.Id
		reply, err := fixtureReply(q).Pack()
		if err != nil {
			done <- err
			return
		}
		if err = binary.Write(stream, binary.BigEndian, uint16(len(reply))); err == nil {
			_, err = stream.Write(reply)
		}
		if err == nil {
			err = stream.Close()
		}
		done <- err
	}()
	pool := newQuicConnectionPool()
	defer pool.shutdownPool()
	info := config.ServerInfo{Address: listener.Addr().String(), Hostname: "127.0.0.1", TLSRootCAs: roots, Metadata: catalog.Metadata{TLSServerName: "resolver.fixture"}}
	result := performDoQQuery(ctx, info, "example.test", dns.TypeA, time.Second, pool)
	require.NoError(t, result.Error)
	require.NoError(t, <-done)
	assert.Equal(t, uint16(0), <-observedID)
	assert.Len(t, result.Response.Answer, 1)
}

// TestSharedCorpusAndCountedWarmup checks that every endpoint gets the same
// workload plus exactly one reported warm-up query for the cached domain.
func TestSharedCorpusAndCountedWarmup(t *testing.T) {
	var mu sync.Mutex
	names := map[string][]string{}
	restore := mockAllProtocolFuncs(func(ctx context.Context, s config.ServerInfo, domain string, qtype uint16, timeout time.Duration) QueryResult {
		mu.Lock()
		names[s.Address] = append(names[s.Address], domain)
		mu.Unlock()
		return QueryResult{Response: &dns.Msg{}, Latency: time.Millisecond}
	})
	defer restore()
	cfg := &config.Config{Servers: []config.ServerInfo{{Address: "a:853", Protocol: config.DOT}, {Address: "b:853", Protocol: config.DOT}}, NumQueries: 6, Domain: "example.test", Concurrency: 1, Timeout: time.Second}
	b := NewBenchmarker(cfg)
	defer b.Close()
	results := b.Run(context.Background())
	// One warm-up per endpoint (cached domain, unscored) plus the six samples.
	require.Len(t, names["a:853"], 7)
	require.Len(t, names["b:853"], 7)
	assert.Equal(t, "example.test", names["a:853"][0])
	assert.Equal(t, "example.test", names["b:853"][0])
	names["a:853"], names["b:853"] = names["a:853"][1:], names["b:853"][1:]
	assert.Equal(t, 2, results.Metadata.WarmupQueries)
	for _, addr := range []string{"a:853", "b:853"} {
		res := results.Results[config.ServerInfo{Address: addr, Protocol: config.DOT}.String()]
		require.NotNil(t, res)
		assert.Len(t, res.CachedLatencies, 3, "warm-up must not be scored")
	}
	assert.NotEmpty(t, results.Metadata.CorpusID)
	// Same workload: identical cached names and identical uncached templates,
	// but no uncached name is shared between endpoints.
	template := func(name string) string {
		if !strings.HasPrefix(name, nxdomainCheckDomainPrefix) {
			return name
		}
		return name[:strings.LastIndex(name, "-")]
	}
	var templatesA, templatesB []string
	for i := range names["a:853"] {
		templatesA = append(templatesA, template(names["a:853"][i]))
		templatesB = append(templatesB, template(names["b:853"][i]))
	}
	assert.ElementsMatch(t, templatesA, templatesB)
	uncachedA := map[string]bool{}
	for _, name := range names["a:853"] {
		if strings.HasPrefix(name, nxdomainCheckDomainPrefix) {
			uncachedA[name] = true
		}
	}
	assert.NotEmpty(t, uncachedA)
	for _, name := range names["b:853"] {
		assert.False(t, uncachedA[name], "uncached name %s reused across endpoints", name)
	}
}

func TestLocalDoQStreamTimeout(t *testing.T) {
	certificate, roots := fixtureCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, nil)
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, stream)
		<-ctx.Done()
	}()
	pool := newQuicConnectionPool()
	defer pool.shutdownPool()
	start := time.Now()
	result := performDoQQuery(ctx, config.ServerInfo{Address: listener.Addr().String(), TLSRootCAs: roots, Metadata: catalog.Metadata{TLSServerName: "resolver.fixture"}}, "example.test", dns.TypeA, 150*time.Millisecond, pool)
	assert.Error(t, result.Error)
	assert.Less(t, time.Since(start), time.Second)
	cancel()
	<-done
}

func TestProbeEvidence(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("example.test.", dns.TypeA)
	genericFailure := new(dns.Msg)
	genericFailure.SetRcode(request, dns.RcodeServerFailure)
	assert.Nil(t, checkDNSSECValidation(QueryResult{Response: genericFailure}), "generic SERVFAIL cannot prove DNSSEC validation")
	response := fixtureReply(request)
	response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}}
	assert.Equal(t, boolPtr(true), checkResponseAccuracy(QueryResult{Response: response}, "192.0.2.1,2001:db8::1"))
	response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "redirect.example."}}
	assert.Equal(t, boolPtr(true), checkNXDOMAINHijack(QueryResult{Response: response}))
	cfg := &config.Config{CheckRebinding: true}
	b := NewBenchmarker(cfg)
	defer b.Close()
	assert.Empty(t, b.prepareCheckJobs([]config.ServerInfo{{Address: "fixture"}}), "no uncontrolled rebinding probe")
	assert.Equal(t, analysis.Inconclusive, initialCheckStates(cfg)["rebinding"])
}

func TestTruncationIsNotScored(t *testing.T) {
	server := config.ServerInfo{Address: "fixture", Protocol: config.UDP}
	b := NewBenchmarker(&config.Config{})
	defer b.Close()
	result := &analysis.ServerResult{ServerAddress: server.String()}
	b.Results.Results[server.String()] = result
	b.processLatencyResult(queryJobResult{serverInfo: server, result: QueryResult{Response: &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}}, Latency: time.Millisecond}})
	assert.Equal(t, 1, result.TruncatedResponses)
	assert.Equal(t, 1, result.Errors)
	assert.Empty(t, result.CachedLatencies)
}

func TestDoHPinnedTargetAndAuthenticationName(t *testing.T) {
	certificate, roots := fixtureCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, _ := io.ReadAll(r.Body)
		query := new(dns.Msg)
		if query.Unpack(packet) != nil {
			w.WriteHeader(400)
			return
		}
		response, _ := fixtureReply(query).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	address := server.Listener.Addr().String()
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	info := config.ServerInfo{Address: "https://resolver.fixture:" + port + "/dns-query", Hostname: "resolver.fixture", ConnectAddress: address, TLSRootCAs: roots, Metadata: catalog.Metadata{IPFamily: "ipv4", TLSServerName: "resolver.fixture"}}
	result := performDoHQuery(context.Background(), info, "example.test", dns.TypeA, time.Second, nil)
	require.NoError(t, result.Error)
	assert.Len(t, result.Response.Answer, 1)
	info.TLSServerName = "wrong.fixture"
	assert.Error(t, performDoHQuery(context.Background(), info, "example.test", dns.TypeA, time.Second, nil).Error)
}

func TestFilteringProbeStates(t *testing.T) {
	server := config.ServerInfo{Address: "fixture", Metadata: catalog.Metadata{FilteringProbeDomains: []string{"malware.fixture."}}}
	for _, tt := range []struct {
		name     string
		response *dns.Msg
		want     analysis.CheckState
	}{
		{"blocked", &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4zero}}}, analysis.Pass},
		{"allowed", &dns.Msg{Answer: []dns.RR{&dns.A{A: net.ParseIP("192.0.2.1")}}}, analysis.Fail},
		{"generic failure", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}, analysis.Inconclusive},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBenchmarker(&config.Config{CheckFiltering: true})
			defer b.Close()
			result := &analysis.ServerResult{}
			b.Results.Results[server.String()] = result
			b.processCheckResult(queryJobResult{serverInfo: server, checkType: "filtering", result: QueryResult{Response: tt.response}})
			assert.Equal(t, tt.want, result.Checks["filtering"])
			assert.Empty(t, result.CachedLatencies)
			assert.Empty(t, result.UncachedLatencies)
		})
	}
}

// serveDoQ answers every DoQ stream on listener with fixtureReply until ctx ends.
func serveDoQ(ctx context.Context, listener *quic.Listener) {
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		go func() {
			for {
				stream, err := connection.AcceptStream(ctx)
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = stream.Close() }()
					var size uint16
					if binary.Read(stream, binary.BigEndian, &size) != nil {
						return
					}
					packet := make([]byte, size)
					if _, err := io.ReadFull(stream, packet); err != nil {
						return
					}
					q := new(dns.Msg)
					if q.Unpack(packet) != nil {
						return
					}
					reply, err := fixtureReply(q).Pack()
					if err != nil {
						return
					}
					_ = binary.Write(stream, binary.BigEndian, uint16(len(reply)))
					_, _ = stream.Write(reply)
				}()
			}
		}()
	}
}

func startDoQFixture(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	certificate, roots := fixtureCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	go serveDoQ(ctx, listener)
	return listener.Addr().String(), roots
}

// TestDoQAuthenticatesTLSServerName checks that a DoQ endpoint is verified
// against its catalogue TLS name, not the IP it connects to, and that a
// certificate for another name is rejected.
func TestDoQAuthenticatesTLSServerName(t *testing.T) {
	address, roots := startDoQFixture(t)
	tests := []struct {
		name       string
		serverName string
		wantErr    bool
	}{
		{"matching name", "resolver.fixture", false},
		{"other name", "wrong.fixture", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := newQuicConnectionPool()
			defer pool.shutdownPool()
			info := config.ServerInfo{Address: address, Hostname: "127.0.0.1", TLSRootCAs: roots, Metadata: catalog.Metadata{TLSServerName: tt.serverName}}
			result := performDoQQuery(context.Background(), info, "example.test", dns.TypeA, 2*time.Second, pool)
			if tt.wantErr {
				var hostnameErr x509.HostnameError
				require.Error(t, result.Error)
				assert.ErrorAs(t, result.Error, &hostnameErr, "the failure must be certificate name verification, not an unrelated error")
				return
			}
			require.NoError(t, result.Error)
			assert.Len(t, result.Response.Answer, 1)
		})
	}
}

// TestDoQPoolDialDoesNotBlockOtherEndpoints checks that a dial to an
// unreachable DoQ endpoint does not hold the pool and delay healthy endpoints.
func TestDoQPoolDialDoesNotBlockOtherEndpoints(t *testing.T) {
	healthy, roots := startDoQFixture(t)
	// A bound UDP socket that never reads: QUIC handshakes to it stall.
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = blackhole.Close() }()

	pool := newQuicConnectionPool()
	defer pool.shutdownPool()
	ctx := context.Background()
	server := func(address string) config.ServerInfo {
		return config.ServerInfo{Address: address, TLSRootCAs: roots, Metadata: catalog.Metadata{TLSServerName: "resolver.fixture"}}
	}

	stalled := make(chan QueryResult, 1)
	go func() {
		stalled <- performDoQQuery(ctx, server(blackhole.LocalAddr().String()), "example.test", dns.TypeA, 3*time.Second, pool)
	}()
	time.Sleep(100 * time.Millisecond) // let the stalled dial start first

	start := time.Now()
	result := performDoQQuery(ctx, server(healthy), "example.test", dns.TypeA, 2*time.Second, pool)
	elapsed := time.Since(start)
	require.NoError(t, result.Error)
	assert.Less(t, elapsed, time.Second, "healthy endpoint waited on the stalled dial")
	assert.Error(t, (<-stalled).Error)
}

// TestDoQPoolLimitHoldsUnderConcurrentDials checks that concurrent first
// queries to one endpoint never pool more than maxPooledConnections sessions.
func TestDoQPoolLimitHoldsUnderConcurrentDials(t *testing.T) {
	address, roots := startDoQFixture(t)
	pool := newQuicConnectionPool()
	defer pool.shutdownPool()
	info := config.ServerInfo{Address: address, TLSRootCAs: roots, Metadata: catalog.Metadata{TLSServerName: "resolver.fixture"}}

	const queries = 3 * maxPooledConnections
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, queries)
	for range queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Generous timeout: this test checks the pool limit, and a burst of
			// localhost QUIC handshakes can occasionally lose a packet.
			errs <- performDoQQuery(context.Background(), info, "example.test", dns.TypeA, 10*time.Second, pool).Error
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	assert.LessOrEqual(t, len(pool.connections[address+"|resolver.fixture"]), maxPooledConnections)
	assert.Empty(t, pool.dialing)
	for _, conn := range pool.connections[address+"|resolver.fixture"] {
		assert.Zero(t, conn.streams)
	}
}

// TestDoQSessionSharedAfterWarmup checks that once a session exists, concurrent
// queries share it on separate streams instead of dialling new sessions, so
// the warm-up handshake is the only one and scored samples do not pay for it.
func TestDoQSessionSharedAfterWarmup(t *testing.T) {
	address, roots := startDoQFixture(t)
	pool := newQuicConnectionPool()
	defer pool.shutdownPool()
	info := config.ServerInfo{Address: address, TLSRootCAs: roots, Metadata: catalog.Metadata{TLSServerName: "resolver.fixture"}}
	key := address + "|resolver.fixture"

	require.NoError(t, performDoQQuery(context.Background(), info, "example.test", dns.TypeA, 5*time.Second, pool).Error)

	const queries = 8
	var wg sync.WaitGroup
	errs := make(chan error, queries)
	for range queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- performDoQQuery(context.Background(), info, "example.test", dns.TypeA, 5*time.Second, pool).Error
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	require.Len(t, pool.connections[key], 1, "concurrent queries dialled extra sessions")
	assert.Zero(t, pool.connections[key][0].streams)
}

func TestCombineProbeStates(t *testing.T) {
	pass, fail, inconclusive := analysis.Pass, analysis.Fail, analysis.Inconclusive
	tests := []struct {
		name     string
		states   []analysis.CheckState
		expected int
		want     analysis.CheckState
	}{
		{"all passed", []analysis.CheckState{pass, pass}, 2, pass},
		{"fail with a missing probe stays fail", []analysis.CheckState{fail}, 2, fail},
		{"fail after a pass", []analysis.CheckState{pass, fail}, 2, fail},
		{"fail beats inconclusive", []analysis.CheckState{inconclusive, fail}, 2, fail},
		{"pass with a missing probe is inconclusive", []analysis.CheckState{pass}, 2, inconclusive},
		{"pass and inconclusive", []analysis.CheckState{pass, inconclusive}, 2, inconclusive},
		{"no probes yet", nil, 2, inconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, combineProbeStates(tt.states, tt.expected))
		})
	}
}

// TestNXDOMAINProbeAggregation feeds both NXDOMAIN probes through
// processCheckResult and checks the combined verdict. A clean result needs two
// conclusive NXDOMAIN answers; any hijacked answer is conclusive on its own.
func TestNXDOMAINProbeAggregation(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("nx.example.test.", dns.TypeA)
	nxdomain := new(dns.Msg)
	nxdomain.SetRcode(request, dns.RcodeNameError)
	hijacked := fixtureReply(request)
	truncated := new(dns.Msg)
	truncated.SetRcode(request, dns.RcodeNameError)
	truncated.Truncated = true

	type probe struct {
		result  QueryResult
		skipped bool
	}
	ok := probe{result: QueryResult{Response: nxdomain}}
	hijack := probe{result: QueryResult{Response: hijacked}}
	failed := probe{result: QueryResult{Error: errors.New("doh http request failed")}}
	trunc := probe{result: QueryResult{Response: truncated}}
	skipped := probe{skipped: true}

	tests := []struct {
		name      string
		probes    []probe
		wantValue *bool
		wantState analysis.CheckState
	}{
		{"both NXDOMAIN", []probe{ok, ok}, boolPtr(false), analysis.Pass},
		{"single probe only", []probe{ok}, nil, analysis.Inconclusive},
		{"second probe errored", []probe{ok, failed}, nil, analysis.Inconclusive},
		{"first probe errored", []probe{failed, ok}, nil, analysis.Inconclusive},
		{"second probe skipped", []probe{ok, skipped}, nil, analysis.Inconclusive},
		{"truncated probe is not evidence", []probe{ok, trunc}, nil, analysis.Inconclusive},
		{"hijack then error", []probe{hijack, failed}, boolPtr(true), analysis.Fail},
		{"error then hijack", []probe{failed, hijack}, boolPtr(true), analysis.Fail},
		{"NXDOMAIN then hijack", []probe{ok, hijack}, boolPtr(true), analysis.Fail},
		{"hijack then NXDOMAIN", []probe{hijack, ok}, boolPtr(true), analysis.Fail},
		{"both errored", []probe{failed, failed}, nil, analysis.Inconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := config.ServerInfo{Address: "fixture", Protocol: config.UDP}
			b := NewBenchmarker(&config.Config{CheckNXDOMAIN: true})
			defer b.Close()
			result := &analysis.ServerResult{Checks: map[string]analysis.CheckState{}}
			b.Results.Results[server.String()] = result
			for _, p := range tt.probes {
				b.processCheckResult(queryJobResult{serverInfo: server, checkType: "nxdomain", result: p.result, skipped: p.skipped})
			}
			assert.Equal(t, tt.wantValue, result.HijacksNXDOMAIN)
			assert.Equal(t, tt.wantState, result.Checks["nxdomain"])
		})
	}
}

// TestDNSSECEvidence feeds the bogus-domain and signed-control probes through
// processCheckResult in both orders and checks the combined verdict.
func TestDNSSECEvidence(t *testing.T) {
	bogusQuery := new(dns.Msg)
	bogusQuery.SetQuestion(dnssecCheckDomain, dns.TypeA)
	controlQuery := new(dns.Msg)
	controlQuery.SetQuestion(dnssecControlDomain, dns.TypeA)

	servfail := new(dns.Msg)
	servfail.SetRcode(bogusQuery, dns.RcodeServerFailure)
	servfailEDE := servfail.Copy()
	servfailEDE.SetEdns0(1232, true)
	servfailEDE.IsEdns0().Option = append(servfailEDE.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeDNSBogus})
	accepted := fixtureReply(bogusQuery)
	controlOK := fixtureReply(controlQuery)
	controlEmpty := new(dns.Msg)
	controlEmpty.SetRcode(controlQuery, dns.RcodeSuccess)
	controlServfail := new(dns.Msg)
	controlServfail.SetRcode(controlQuery, dns.RcodeServerFailure)
	controlTruncated := controlOK.Copy()
	controlTruncated.Truncated = true
	// NXDOMAIN with a CNAME answer: records present, but the name did not resolve.
	controlNXDOMAIN := new(dns.Msg)
	controlNXDOMAIN.SetRcode(controlQuery, dns.RcodeNameError)
	controlNXDOMAIN.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: dnssecControlDomain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "gone.example."}}

	type probe struct {
		checkType string
		result    QueryResult
		skipped   bool
	}
	bogus := func(m *dns.Msg) probe { return probe{checkType: "dnssec", result: QueryResult{Response: m}} }
	control := func(m *dns.Msg) probe { return probe{checkType: "dnssec-control", result: QueryResult{Response: m}} }
	controlTimeout := probe{checkType: "dnssec-control", result: QueryResult{Error: errors.New("query timed out after 1s")}}
	controlSkipped := probe{checkType: "dnssec-control", skipped: true}

	tests := []struct {
		name      string
		probes    []probe
		wantValue *bool
		wantState analysis.CheckState
	}{
		{"plain SERVFAIL then working control", []probe{bogus(servfail), control(controlOK)}, boolPtr(true), analysis.Pass},
		{"working control then plain SERVFAIL", []probe{control(controlOK), bogus(servfail)}, boolPtr(true), analysis.Pass},
		{"plain SERVFAIL without control yet", []probe{bogus(servfail)}, nil, analysis.Inconclusive},
		{"plain SERVFAIL, control SERVFAIL", []probe{bogus(servfail), control(controlServfail)}, nil, analysis.Inconclusive},
		{"plain SERVFAIL, control NXDOMAIN with CNAME", []probe{bogus(servfail), control(controlNXDOMAIN)}, nil, analysis.Inconclusive},
		{"plain SERVFAIL, control empty", []probe{bogus(servfail), control(controlEmpty)}, nil, analysis.Inconclusive},
		{"plain SERVFAIL, control truncated", []probe{bogus(servfail), control(controlTruncated)}, nil, analysis.Inconclusive},
		{"plain SERVFAIL, control timed out", []probe{bogus(servfail), controlTimeout}, nil, analysis.Inconclusive},
		{"plain SERVFAIL, control skipped", []probe{bogus(servfail), controlSkipped}, nil, analysis.Inconclusive},
		{"EDE SERVFAIL needs no control", []probe{bogus(servfailEDE), controlTimeout}, boolPtr(true), analysis.Pass},
		{"bogus accepted despite working control", []probe{control(controlOK), bogus(accepted)}, boolPtr(false), analysis.Fail},
		{"control alone proves nothing", []probe{control(controlOK)}, nil, analysis.Inconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := config.ServerInfo{Address: "fixture", Protocol: config.UDP}
			b := NewBenchmarker(&config.Config{CheckDNSSEC: true})
			defer b.Close()
			result := &analysis.ServerResult{}
			b.Results.Results[server.String()] = result
			for _, p := range tt.probes {
				b.processCheckResult(queryJobResult{serverInfo: server, checkType: p.checkType, result: p.result, skipped: p.skipped})
			}
			assert.Equal(t, tt.wantValue, result.SupportsDNSSEC)
			assert.Equal(t, tt.wantState, result.Checks["dnssec"])
		})
	}
}

// TestRebindingProbeAggregation checks how A and AAAA probes combine across
// servers: a passed-through private answer fails the check, and a stripped
// answer counts as protection only for record types that some server in the
// run passed through, proving the test domain serves them.
func TestRebindingProbeAggregation(t *testing.T) {
	queryA := new(dns.Msg)
	queryA.SetQuestion(rebindingCheckDomain, dns.TypeA)
	queryAAAA := new(dns.Msg)
	queryAAAA.SetQuestion(rebindingCheckDomain, dns.TypeAAAA)

	passedA := fixtureReply(queryA)
	passedA.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: rebindingCheckDomain, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.168.1.1")}}
	passedAAAA := fixtureReply(queryAAAA)
	passedAAAA.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: rebindingCheckDomain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("fd00::1")}}
	strippedA := new(dns.Msg)
	strippedA.SetRcode(queryA, dns.RcodeSuccess)
	strippedAAAA := new(dns.Msg)
	strippedAAAA.SetRcode(queryAAAA, dns.RcodeSuccess)

	type probe struct {
		qType   uint16
		result  QueryResult
		skipped bool
	}
	a := func(m *dns.Msg) probe { return probe{qType: dns.TypeA, result: QueryResult{Response: m}} }
	aaaa := func(m *dns.Msg) probe { return probe{qType: dns.TypeAAAA, result: QueryResult{Response: m}} }
	failedAAAA := probe{qType: dns.TypeAAAA, result: QueryResult{Error: errors.New("doh http request failed")}}
	skippedAAAA := probe{qType: dns.TypeAAAA, skipped: true}

	tests := []struct {
		name      string
		control   []probe // probes of a second server in the same run
		probes    []probe
		wantValue *bool
		wantState analysis.CheckState
	}{
		{"only AAAA passes through", nil, []probe{a(strippedA), aaaa(passedAAAA)}, boolPtr(false), analysis.Fail},
		{"only A passes through", nil, []probe{a(passedA), aaaa(strippedAAAA)}, boolPtr(false), analysis.Fail},
		{"AAAA passes through, A errored", nil, []probe{{qType: dns.TypeA, result: QueryResult{Error: errors.New("timeout")}}, aaaa(passedAAAA)}, boolPtr(false), analysis.Fail},
		{"both stripped, both types controlled", []probe{a(passedA), aaaa(passedAAAA)}, []probe{a(strippedA), aaaa(strippedAAAA)}, boolPtr(true), analysis.Pass},
		{"both stripped, no server passed through", []probe{a(strippedA), aaaa(strippedAAAA)}, []probe{a(strippedA), aaaa(strippedAAAA)}, nil, analysis.Inconclusive},
		{"both stripped, single server", nil, []probe{a(strippedA), aaaa(strippedAAAA)}, nil, analysis.Inconclusive},
		{"A-only domain: AAAA not required", []probe{a(passedA), aaaa(strippedAAAA)}, []probe{a(strippedA), failedAAAA}, boolPtr(true), analysis.Pass},
		{"A stripped, AAAA skipped, both controlled", []probe{a(passedA), aaaa(passedAAAA)}, []probe{a(strippedA), skippedAAAA}, nil, analysis.Inconclusive},
		{"A stripped, AAAA errored, both controlled", []probe{a(passedA), aaaa(passedAAAA)}, []probe{a(strippedA), failedAAAA}, nil, analysis.Inconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := config.ServerInfo{Address: "fixture", Protocol: config.UDP}
			control := config.ServerInfo{Address: "control", Protocol: config.UDP}
			servers := []config.ServerInfo{server}
			b := NewBenchmarker(&config.Config{CheckRebinding: true, RebindingDomain: rebindingCheckDomain})
			defer b.Close()
			result := &analysis.ServerResult{}
			b.Results.Results[server.String()] = result
			if tt.control != nil {
				servers = append(servers, control)
				b.Results.Results[control.String()] = &analysis.ServerResult{}
			}
			feed := func(s config.ServerInfo, probes []probe) {
				for _, p := range probes {
					b.processCheckResult(queryJobResult{serverInfo: s, checkType: "rebinding", qType: p.qType, result: p.result, skipped: p.skipped})
				}
			}
			feed(server, tt.probes)
			feed(control, tt.control)
			b.finalizeRebinding(servers)
			assert.Equal(t, tt.wantValue, result.BlocksRebinding)
			assert.Equal(t, tt.wantState, result.Checks["rebinding"])
		})
	}
}

// TestMixedFamilyAccuracy checks that an accuracy file listing IPv4 and IPv6
// addresses queries both record types and that a match on either is accurate.
func TestMixedFamilyAccuracy(t *testing.T) {
	assert.Equal(t, []uint16{dns.TypeA}, accuracyQueryTypes("192.0.2.1"))
	assert.Equal(t, []uint16{dns.TypeAAAA}, accuracyQueryTypes("2001:db8::1"))
	assert.Equal(t, []uint16{dns.TypeA, dns.TypeAAAA}, accuracyQueryTypes("2001:db8::1,192.0.2.1"))
	assert.Equal(t, []uint16{dns.TypeA}, accuracyQueryTypes("not-an-ip"))

	const domain = "accuracy.fixture."
	const expected = "2001:db8::1,192.0.2.1"
	reply := func(qType uint16, rr dns.RR) QueryResult {
		q := new(dns.Msg)
		q.SetQuestion(domain, qType)
		m := fixtureReply(q)
		if rr != nil {
			m.Answer = []dns.RR{rr}
		}
		return QueryResult{Response: m}
	}
	hdrA := dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET}
	hdrAAAA := dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}
	goodA := reply(dns.TypeA, &dns.A{Hdr: hdrA, A: net.ParseIP("192.0.2.1")})
	badA := reply(dns.TypeA, &dns.A{Hdr: hdrA, A: net.ParseIP("192.0.2.99")})
	goodAAAA := reply(dns.TypeAAAA, &dns.AAAA{Hdr: hdrAAAA, AAAA: net.ParseIP("2001:db8::1")})
	badAAAA := reply(dns.TypeAAAA, &dns.AAAA{Hdr: hdrAAAA, AAAA: net.ParseIP("2001:db8::99")})
	timeout := QueryResult{Error: errors.New("timeout")}

	tests := []struct {
		name      string
		a, aaaa   QueryResult
		wantState analysis.CheckState
	}{
		{"IPv4 matches, IPv6 differs", goodA, badAAAA, analysis.Pass},
		{"IPv6 matches, IPv4 differs", badA, goodAAAA, analysis.Pass},
		{"neither matches", badA, badAAAA, analysis.Fail},
		{"IPv4 differs, IPv6 timed out", badA, timeout, analysis.Fail},
		{"both timed out", timeout, timeout, analysis.Inconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := config.ServerInfo{Address: "fixture", Protocol: config.UDP}
			cfg := &config.Config{AccuracyCheckFile: "file", AccuracyCheckDomain: domain, AccuracyCheckIP: expected}
			b := NewBenchmarker(cfg)
			defer b.Close()
			jobs := b.prepareCheckJobs([]config.ServerInfo{server})
			require.Len(t, jobs, 2)
			result := &analysis.ServerResult{Checks: initialCheckStates(cfg, server)}
			b.Results.Results[server.String()] = result
			b.processCheckResult(queryJobResult{serverInfo: server, checkType: "accuracy", qType: dns.TypeA, result: tt.a})
			b.processCheckResult(queryJobResult{serverInfo: server, checkType: "accuracy", qType: dns.TypeAAAA, result: tt.aaaa})
			assert.Equal(t, tt.wantState, result.Checks["accuracy"])
		})
	}
}

func TestExtendedDNSErrorCounting(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	withEDE := func(codes ...uint16) QueryResult {
		reply := fixtureReply(query)
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		for _, code := range codes {
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code})
		}
		reply.Extra = append(reply.Extra, opt)
		return QueryResult{Response: reply, Latency: time.Millisecond}
	}
	tests := []struct {
		name         string
		codes        []uint16
		wantPolicies int
	}{
		{"no EDE", nil, 0},
		{"DNSSEC bogus is not policy", []uint16{dns.ExtendedErrorCodeDNSBogus}, 0},
		{"below the policy range", []uint16{14}, 0},
		{"blocked starts the range", []uint16{dns.ExtendedErrorCodeBlocked}, 1},
		{"filtered ends the range", []uint16{dns.ExtendedErrorCodeFiltered}, 1},
		{"above the policy range", []uint16{19}, 0},
		{"two policy codes count one response", []uint16{dns.ExtendedErrorCodeBlocked, dns.ExtendedErrorCodeCensored}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := config.ServerInfo{Address: "fixture", Protocol: config.UDP}
			b := NewBenchmarker(&config.Config{})
			defer b.Close()
			result := &analysis.ServerResult{}
			b.Results.Results[server.String()] = result
			b.processLatencyResult(queryJobResult{serverInfo: server, result: withEDE(tt.codes...)})
			assert.Equal(t, tt.wantPolicies, result.PolicyResponses)
			if len(tt.codes) == 0 {
				assert.Empty(t, result.ExtendedDNSErrors)
			} else {
				assert.Equal(t, tt.codes, result.ExtendedDNSErrors)
			}
		})
	}
}

func TestDotcomProbeStates(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("dnsbench-dotcom-x.com.", dns.TypeA)
	reply := func(rcode int) QueryResult {
		m := new(dns.Msg)
		m.SetRcode(query, rcode)
		return QueryResult{Response: m, Latency: 7 * time.Millisecond}
	}
	tests := []struct {
		name        string
		result      QueryResult
		skipped     bool
		wantState   analysis.CheckState
		wantLatency bool
	}{
		{"NXDOMAIN passes and is scored", reply(dns.RcodeNameError), false, analysis.Pass, true},
		{"SERVFAIL fails", reply(dns.RcodeServerFailure), false, analysis.Fail, false},
		{"NOERROR fails", reply(dns.RcodeSuccess), false, analysis.Fail, false},
		{"timeout is inconclusive", QueryResult{Error: errors.New("i/o timeout")}, false, analysis.Inconclusive, false},
		{"truncated is inconclusive", QueryResult{Response: &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true, Rcode: dns.RcodeNameError}}}, false, analysis.Inconclusive, false},
		{"skipped is inconclusive", QueryResult{}, true, analysis.Inconclusive, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{CheckDotcom: true}
			server := config.ServerInfo{Address: "fixture", Protocol: config.UDP}
			b := NewBenchmarker(cfg)
			defer b.Close()
			result := &analysis.ServerResult{Checks: initialCheckStates(cfg, server)}
			b.Results.Results[server.String()] = result
			b.processCheckResult(queryJobResult{serverInfo: server, checkType: "dotcom", result: tt.result, skipped: tt.skipped})
			assert.Equal(t, tt.wantState, result.Checks["dotcom"])
			assert.Equal(t, tt.wantLatency, result.DotcomLatency != nil)
		})
	}
	assert.Equal(t, analysis.NotApplicable, initialCheckStates(&config.Config{})["dotcom"])
}

// TestRunResetsCheckEvidence checks that multi-probe evidence from one Run
// cannot leak into the next when a Benchmarker is reused.
func TestRunResetsCheckEvidence(t *testing.T) {
	cfg := &config.Config{}
	b := NewBenchmarker(cfg)
	defer b.Close()
	b.evidenceFor("stale").rebinding = map[uint16]analysis.CheckState{dns.TypeA: analysis.Fail}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.Run(ctx)
	assert.Empty(t, b.evidence)
}
