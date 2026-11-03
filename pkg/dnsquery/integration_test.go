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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestLocalDoHWireAndValidation(t *testing.T) {
	for _, tt := range []struct {
		name, contentType string
		oversize, fail    bool
	}{
		{"valid", "application/dns-message", false, false},
		{"invalid type", "text/html", false, true},
		{"missing type", "", false, true},
		{"oversize", "application/dns-message", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				packet, _ := io.ReadAll(r.Body)
				q := new(dns.Msg)
				if q.Unpack(packet) != nil {
					w.WriteHeader(400)
					return
				}
				w.Header()["Content-Type"] = []string{tt.contentType}
				if tt.oversize {
					_, _ = w.Write(make([]byte, 65536))
					return
				}
				reply, _ := fixtureReply(q).Pack()
				_, _ = w.Write(reply)
			}))
			defer server.Close()
			result := performDoHQuery(context.Background(), config.ServerInfo{Address: server.URL}, "example.test", dns.TypeA, time.Second, server.Client())
			if tt.fail {
				assert.Error(t, result.Error)
			} else {
				require.NoError(t, result.Error)
				assert.Len(t, result.Response.Answer, 1)
			}
		})
	}
}

func TestLocalDoQWireTransport(t *testing.T) {
	certificate, roots := fixtureCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, nil)
	require.NoError(t, err)
	defer listener.Close()
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

func TestSharedCorpusAndNoWarmup(t *testing.T) {
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
	assert.Len(t, names["a:853"], 6)
	assert.Equal(t, names["a:853"], names["b:853"])
	assert.NotEmpty(t, results.Metadata.CorpusID)
}

func TestLocalDoQStreamTimeout(t *testing.T) {
	certificate, roots := fixtureCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, nil)
	require.NoError(t, err)
	defer listener.Close()
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
