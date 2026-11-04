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
	assert.Equal(t, 2, strings.Count(summary.String(), "Fastest "))
	assert.Contains(t, summary.String(), "general-endpoint")
	assert.Contains(t, summary.String(), "family-endpoint")
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
			notContains: []string{"Fastest ", "comparison group"},
		},
		{
			name:        "catalogue groups plus system DNS",
			results:     []*analysis.ServerResult{catalogued("1.1.1.1:53", 4), catalogued("1.0.0.1:53", 6), system},
			contains:    []string{"--- Recommendations by comparison group ---", "Fastest unfiltered / general / no / UDP / ipv4: Provider A (a-general), 1.1.1.1:53", "--- Conclusion (system and custom endpoints, no catalogue policy) ---", "Recommended server: 192.0.2.53:53"},
			notContains: []string{"Fastest custom", "Fastest system"},
		},
		{
			name:        "catalogue only has no conclusion block",
			results:     []*analysis.ServerResult{catalogued("1.1.1.1:53", 4)},
			contains:    []string{"Fastest unfiltered"},
			notContains: []string{"--- Conclusion", "Other tested servers"},
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
