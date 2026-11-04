package dnsquery

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/taihen/dns-benchmark/pkg/catalog"
	"github.com/taihen/dns-benchmark/pkg/config"
	"github.com/taihen/dns-benchmark/pkg/output"
)

// TestDualFamilyEndpointsStayDistinct runs IPv4 and IPv6 DoT endpoints that
// share a serverAddress (both report tls://one.one.one.one:853) through Run and
// the CSV and JSON writers. Keying results by address instead of endpoint
// identity would merge them, so each must keep its own result, row and object.
func TestDualFamilyEndpointsStayDistinct(t *testing.T) {
	endpoint := func(id, address, family string) config.ServerInfo {
		return config.ServerInfo{
			Address:  address,
			Protocol: config.DOT,
			Metadata: catalog.Metadata{
				Provider: "cloudflare", Profile: "cloudflare-default", EndpointID: id,
				IPFamily: family, Transport: "dot", TLSServerName: "one.one.one.one", CatalogVersion: "test",
			},
		}
	}
	v4 := endpoint("cloudflare-dot-ipv4", "1.1.1.1:853", "ipv4")
	v6 := endpoint("cloudflare-dot-ipv6", "[2606:4700:4700::1111]:853", "ipv6")
	require.Equal(t, v4.AddressString(), v6.AddressString(), "fixture must share a serverAddress")
	require.NotEqual(t, v4.String(), v6.String())

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	reply := createTestResponse(query, dns.RcodeSuccess)
	latencies := map[string]time.Duration{v4.String(): 10 * time.Millisecond, v6.String(): 40 * time.Millisecond}
	restore := mockAllProtocolFuncs(func(_ context.Context, s config.ServerInfo, _ string, _ uint16, _ time.Duration) QueryResult {
		return QueryResult{Latency: latencies[s.String()], Response: reply}
	})
	defer restore()

	cfg := &config.Config{Servers: []config.ServerInfo{v4, v6}, NumQueries: 4, Timeout: time.Second, Concurrency: 2, Domain: "example.com", QueryType: "A"}
	b := NewBenchmarker(cfg)
	defer b.Close()
	results := b.Run(context.Background())
	results.Analyze()

	require.Len(t, results.Results, 2)
	assert.Equal(t, 10*time.Millisecond, results.Results[v4.String()].AvgCachedLatency)
	assert.Equal(t, 40*time.Millisecond, results.Results[v6.String()].AvgCachedLatency)

	var csvBuf bytes.Buffer
	require.NoError(t, output.WriteCSVResults(&csvBuf, results, cfg))
	records, err := csv.NewReader(&csvBuf).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 3, "header plus one row per endpoint")
	endpointColumn := -1
	for i, name := range records[0] {
		if name == "EndpointID" {
			endpointColumn = i
		}
	}
	require.GreaterOrEqual(t, endpointColumn, 0)
	assert.ElementsMatch(t, []string{v4.EndpointID, v6.EndpointID}, []string{records[1][endpointColumn], records[2][endpointColumn]})

	var jsonBuf bytes.Buffer
	require.NoError(t, output.WriteJSONResults(&jsonBuf, results, cfg))
	var report struct {
		Results []struct {
			ServerAddress string `json:"serverAddress"`
			EndpointID    string `json:"endpointId"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(jsonBuf.Bytes(), &report))
	require.Len(t, report.Results, 2)
	ids := []string{}
	for _, r := range report.Results {
		assert.Equal(t, "tls://one.one.one.one:853", r.ServerAddress)
		ids = append(ids, r.EndpointID)
	}
	assert.ElementsMatch(t, []string{v4.EndpointID, v6.EndpointID}, ids)
}
