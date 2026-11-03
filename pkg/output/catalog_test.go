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
