package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/catalog"
	"github.com/taihen/dns-benchmark/pkg/config"
)

func TestPolicyGroupsAndMetadata(t *testing.T) {
	general := &analysis.ServerResult{ServerAddress: "general-endpoint", Protocol: "DoH", Score: 10, Metadata: catalog.Metadata{Provider: "Provider A", Profile: "a-general", Roles: []string{"general"}, FilteringPolicy: "unfiltered", IPFamily: "ipv4", Transport: "doh", EndpointID: "a-doh-v4", CatalogVersion: "test"}}
	family := &analysis.ServerResult{ServerAddress: "family-endpoint", Protocol: "DoH", Score: 1, Metadata: catalog.Metadata{Provider: "Provider B", Profile: "b-family", Roles: []string{"family"}, FilteringPolicy: "adult", IPFamily: "ipv4", Transport: "doh", EndpointID: "b-doh-v4", CatalogVersion: "test"}}
	var summary bytes.Buffer
	printSummary(&summary, []*analysis.ServerResult{general, family}, &config.Config{})
	assert.Equal(t, 1, strings.Count(summary.String(), "Fastest "), "one DoH/ipv4 ranking, no single-member policy groups")
	assert.Contains(t, summary.String(), "Fastest DoH / ipv4: Provider B (b-family, policy adult), family-endpoint")
	assert.NotContains(t, summary.String(), "matching policy groups")
	results := analysis.NewBenchmarkResults()
	results.Results["a"] = general
	results.Results["b"] = family
	results.Metadata = analysis.RunMetadata{StartedAt: time.Now(), CorpusID: "sha256:fixture", RequestedQueries: 5, Skipped: 2, Interrupted: true}
	var encoded bytes.Buffer
	require.NoError(t, WriteJSONResults(&encoded, results, &config.Config{}))
	var report JSONReport
	require.NoError(t, json.Unmarshal(encoded.Bytes(), &report))
	assert.Equal(t, "2", report.SchemaVersion)
	assert.Equal(t, results.Metadata.CorpusID, report.Metadata.CorpusID)
	assert.True(t, report.Metadata.Interrupted)
	assert.NotEqual(t, report.Results[0].ComparisonGroup, report.Results[1].ComparisonGroup)
	encoded.Reset()
	require.NoError(t, WriteCSVResults(&encoded, results, &config.Config{}))
	rows, err := csv.NewReader(&encoded).ReadAll()
	require.NoError(t, err)
	header := map[string]int{}
	for i, name := range rows[0] {
		header[name] = i
	}
	assert.Equal(t, "b-family", rows[1][header["Profile"]])
	assert.Equal(t, "Provider A", rows[2][header["Provider"]])
	assert.Equal(t, "a-doh-v4", rows[2][header["EndpointID"]])
}

func TestSummaryForUncataloguedEndpoints(t *testing.T) {
	catalogued := func(address string, score float64) *analysis.ServerResult {
		return &analysis.ServerResult{ServerAddress: address, Protocol: "UDP", Score: score, Reliability: 100, Metadata: catalog.Metadata{Provider: "Provider A", Profile: "a-general", Roles: []string{"general"}, FilteringPolicy: "unfiltered", ECS: "no", IPFamily: "ipv4", Transport: "udp", EndpointID: "a-udp-" + address, CatalogVersion: "test"}}
	}
	custom := func(address string, score float64) *analysis.ServerResult {
		return &analysis.ServerResult{ServerAddress: address, Protocol: "UDP", Score: score, Reliability: 100, Metadata: catalog.Metadata{Provider: "custom", Profile: "custom", Roles: []string{"custom"}, IPFamily: "ipv4", Transport: "udp"}}
	}
	system := &analysis.ServerResult{ServerAddress: "192.0.2.53:53", Protocol: "UDP", Score: 3, Reliability: 100, Metadata: catalog.Metadata{Provider: "system", Profile: "system", Roles: []string{"system"}, IPFamily: "ipv4", Transport: "udp"}}

	tests := []struct {
		name        string
		results     []*analysis.ServerResult
		contains    []string
		notContains []string
	}{
		{
			name:        "custom file only keeps the original conclusion",
			results:     []*analysis.ServerResult{custom("192.0.2.1:53", 5), custom("tls://dns.example:853", 2)},
			contains:    []string{"--- Conclusion ---", "Recommended server: tls://dns.example:853", "Other tested servers performed reliably", "Note: Results are based on"},
			notContains: []string{"Fastest ", "Recommendations by"},
		},
		{
			name:        "catalogue groups plus system DNS",
			results:     []*analysis.ServerResult{catalogued("1.1.1.1:53", 4), catalogued("1.0.0.1:53", 6), system},
			contains:    []string{"--- Recommendations by transport and IP family ---", "Fastest UDP / ipv4: Provider A (a-general, policy unfiltered), 1.1.1.1:53", "--- Fastest within matching policy groups ---", "Fastest unfiltered / general / no / UDP / ipv4: Provider A (a-general), 1.1.1.1:53", "--- Conclusion (system and custom endpoints, no catalogue policy) ---", "Recommended server: 192.0.2.53:53"},
			notContains: []string{"Fastest custom", "Fastest system"},
		},
		{
			name:        "catalogue only has no conclusion block",
			results:     []*analysis.ServerResult{catalogued("1.1.1.1:53", 4)},
			contains:    []string{"Fastest UDP / ipv4"},
			notContains: []string{"--- Conclusion", "Other tested servers", "matching policy groups"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printSummary(&buf, tt.results, &config.Config{})
			for _, want := range tt.contains {
				assert.Contains(t, buf.String(), want)
			}
			for _, unwanted := range tt.notContains {
				assert.NotContains(t, buf.String(), unwanted)
			}
		})
	}
}

// TestDefaultPresetRanksAcrossProviders reproduces the legacy preset shape: six
// providers with distinct policies, each on three transports. Every transport
// must produce a cross-provider ranking, with no trivially true
// single-member policy lines.
func TestDefaultPresetRanksAcrossProviders(t *testing.T) {
	providers := []struct {
		name, profile, policy, role, ecs string
		score                            float64
	}{
		{"Cloudflare", "cloudflare-standard", "unfiltered", "general", "disabled", 3},
		{"Google", "google-standard", "unfiltered", "general", "enabled", 2},
		{"Quad9", "quad9-secure", "malware", "security", "disabled", 1},
		{"AdGuard", "adguard-default", "ads+trackers", "ads", "unknown", 6},
		{"DNS4EU", "dns4eu-unfiltered", "legal-only", "general", "unknown", 5},
		{"OpenDNS", "opendns-core", "security+configurable", "security", "unknown", 4},
	}
	transports := []struct{ protocol, transport string }{{"UDP", "udp"}, {"DoT", "dot"}, {"DoH", "doh"}}
	var results []*analysis.ServerResult
	for _, tr := range transports {
		for _, p := range providers {
			results = append(results, &analysis.ServerResult{
				ServerAddress: p.profile + "-" + tr.transport, Protocol: tr.protocol, Score: p.score, Reliability: 100,
				Metadata: catalog.Metadata{Provider: p.name, Profile: p.profile, Roles: []string{p.role}, FilteringPolicy: p.policy, ECS: p.ecs, IPFamily: "ipv4", Transport: tr.transport, CatalogVersion: "test"},
			})
		}
	}

	var buf bytes.Buffer
	printSummary(&buf, results, &config.Config{})
	out := buf.String()
	assert.Equal(t, 3, strings.Count(out, "Fastest "))
	for _, tr := range transports {
		assert.Contains(t, out, "Fastest "+tr.protocol+" / ipv4: Quad9 (quad9-secure, policy malware), quad9-secure-"+tr.transport)
	}
	assert.NotContains(t, out, "matching policy groups")

	sortServerResults(results)
	assert.Equal(t, "quad9-secure-doh", results[0].ServerAddress)
	assert.Equal(t, "google-standard-doh", results[1].ServerAddress)
	assert.Equal(t, "DoH / ipv4", results[5].RankingGroup())
	assert.Equal(t, "DoT / ipv4", results[6].RankingGroup())
}
