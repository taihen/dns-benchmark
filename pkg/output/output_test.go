package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/catalog"
	"github.com/taihen/dns-benchmark/pkg/config"
)

// Test cases for formatting latency values.
func TestFormatLatency(t *testing.T) {
	tests := []struct {
		name       string
		latency    time.Duration
		hasSuccess bool
		want       string
	}{
		{"zero duration success", 0, true, "0.0 ms"},
		{"zero duration no success", 0, false, "N/A"},
		{"positive duration success", 123456 * time.Microsecond, true, "123.5 ms"}, // Rounds up
		{"positive duration no success", 123 * time.Millisecond, false, "N/A"},
		{"sub-millisecond", 500 * time.Microsecond, true, "0.5 ms"},
		{"large duration", 2 * time.Second, true, "2000.0 ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatLatency(tt.latency, tt.hasSuccess); got != tt.want {
				t.Errorf("formatLatency() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatStdDev(t *testing.T) {
	tests := []struct {
		name          string
		stdDev        time.Duration
		hasEnoughData bool // Needs > 1 data point
		want          string
	}{
		{"zero stddev enough data", 0, true, "0.0 ms"},
		{"zero stddev not enough data", 0, false, "N/A"},
		{"positive stddev enough data", 56789 * time.Microsecond, true, "56.8 ms"}, // Rounds up
		{"positive stddev not enough data", 56 * time.Millisecond, false, "N/A"},
		{"sub-millisecond", 750 * time.Microsecond, true, "0.8 ms"}, // Rounds up
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatStdDev(tt.stdDev, tt.hasEnoughData); got != tt.want {
				t.Errorf("formatStdDev() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatDurationPointer(t *testing.T) {
	d1 := 123456 * time.Microsecond
	d2 := 500 * time.Microsecond
	tests := []struct {
		name string
		d    *time.Duration
		want string
	}{
		{"nil duration", nil, "N/A"},
		{"valid duration", &d1, "123.5 ms"},
		{"sub-millisecond", &d2, "0.5 ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDurationPointer(tt.d); got != tt.want {
				t.Errorf("formatDurationPointer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatBoolPointer(t *testing.T) {
	bTrue := true
	bFalse := false
	tests := []struct {
		name     string
		val      *bool
		trueStr  string
		falseStr string
		nilStr   string
		want     string
	}{
		{"nil value", nil, "Yes", "No", "Maybe", "Maybe"},
		{"true value", &bTrue, "Pass", "Fail", "N/A", "Pass"},
		{"false value", &bFalse, "OK", "Bad", "Unknown", "Bad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBoolPointer(tt.val, tt.trueStr, tt.falseStr, tt.nilStr); got != tt.want {
				t.Errorf("formatBoolPointer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatMillisFloat(t *testing.T) {
	tests := []struct {
		name       string
		d          time.Duration
		applicable bool
		want       string
	}{
		{"zero duration applicable", 0, true, "0.000"},
		{"zero duration not applicable", 0, false, "N/A"},
		{"positive duration applicable", 123456 * time.Microsecond, true, "123.456"},
		{"positive duration not applicable", 123 * time.Millisecond, false, "N/A"},
		{"sub-millisecond", 500 * time.Microsecond, true, "0.500"},
		{"rounding", 123999 * time.Microsecond, true, "123.999"}, // No rounding here
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatMillisFloat(tt.d, tt.applicable); got != tt.want {
				t.Errorf("formatMillisFloat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatMillisFloatPointer(t *testing.T) {
	d1 := 123456 * time.Microsecond
	d2 := 500 * time.Microsecond
	tests := []struct {
		name string
		d    *time.Duration
		want string
	}{
		{"nil duration", nil, "N/A"},
		{"valid duration", &d1, "123.456"},
		{"sub-millisecond", &d2, "0.500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatMillisFloatPointer(tt.d); got != tt.want {
				t.Errorf("formatMillisFloatPointer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatBoolPointerCSV(t *testing.T) {
	bTrue := true
	bFalse := false
	tests := []struct {
		name string
		val  *bool
		want string
	}{
		{"nil value", nil, "N/A"},
		{"true value", &bTrue, "true"},
		{"false value", &bFalse, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBoolPointerCSV(tt.val); got != tt.want {
				t.Errorf("formatBoolPointerCSV() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatScoreCSV(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		want  string
	}{
		{"finite", 12.3456, "12.346"},
		{"zero", 0, "0.000"},
		{"infinite", math.Inf(1), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatScoreCSV(tt.score); got != tt.want {
				t.Errorf("formatScoreCSV() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatScore(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		want  string
	}{
		{"finite", 12.34, "12.3 ms"},
		{"zero", 0, "0.0 ms"},
		{"infinite", math.Inf(1), "N/A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatScore(tt.score); got != tt.want {
				t.Errorf("formatScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Tests for Main Output Functions ---

// Helper to create sample results
func createSampleResults() *analysis.BenchmarkResults {
	bTrue := true
	bFalse := false
	dotcomLatency := 15 * time.Millisecond
	res := analysis.NewBenchmarkResults()
	res.Results["1.1.1.1:53"] = &analysis.ServerResult{
		ServerAddress:         "1.1.1.1:53",
		Protocol:              "UDP",
		CachedLatencies:       []time.Duration{10 * time.Millisecond, 12 * time.Millisecond},
		UncachedLatencies:     []time.Duration{20 * time.Millisecond, 25 * time.Millisecond, 30 * time.Millisecond},
		TotalQueries:          5,
		SupportsDNSSEC:        &bTrue,
		HijacksNXDOMAIN:       &bFalse,
		BlocksRebinding:       &bTrue,
		IsAccurate:            &bTrue,
		DotcomLatency:         &dotcomLatency,
		AvgCachedLatency:      11 * time.Millisecond,
		StdDevCachedLatency:   1414213 * time.Nanosecond, // sqrt(((10-11)^2+(12-11)^2)/(2-1)) = sqrt(1+1) = sqrt(2) = 1.414... ms
		AvgUncachedLatency:    25 * time.Millisecond,
		StdDevUncachedLatency: 5 * time.Millisecond, // sqrt(((20-25)^2+(25-25)^2+(30-25)^2)/(3-1)) = sqrt((25+0+25)/2) = sqrt(25) = 5 ms
		Reliability:           100.0,
		Errors:                0,
		Score:                 26.7, // distinct from AvgUncached so the Score column is independently assertable
	}
	res.Results["8.8.8.8:53"] = &analysis.ServerResult{
		ServerAddress:         "8.8.8.8:53",
		Protocol:              "UDP",
		CachedLatencies:       []time.Duration{15 * time.Millisecond},
		UncachedLatencies:     []time.Duration{35 * time.Millisecond},
		TotalQueries:          3, // One error
		SupportsDNSSEC:        &bTrue,
		HijacksNXDOMAIN:       nil, // Check not run or failed
		BlocksRebinding:       &bFalse,
		IsAccurate:            &bFalse,
		DotcomLatency:         nil,
		AvgCachedLatency:      15 * time.Millisecond,
		StdDevCachedLatency:   0, // n=1
		AvgUncachedLatency:    35 * time.Millisecond,
		StdDevUncachedLatency: 0, // n=1
		Reliability:           66.7,
		Errors:                1,
		Score:                 36.2, // distinct from AvgUncached so the Score column is independently assertable
	}
	res.Results["tls://9.9.9.9:853"] = &analysis.ServerResult{
		ServerAddress:         "tls://9.9.9.9:853",
		Protocol:              "DoT",
		CachedLatencies:       []time.Duration{}, // All errors
		UncachedLatencies:     []time.Duration{}, // All errors
		TotalQueries:          4,
		SupportsDNSSEC:        nil,
		HijacksNXDOMAIN:       nil,
		BlocksRebinding:       nil,
		IsAccurate:            nil,
		DotcomLatency:         nil,
		AvgCachedLatency:      0,
		StdDevCachedLatency:   0,
		AvgUncachedLatency:    0,
		StdDevUncachedLatency: 0,
		Reliability:           0.0,
		Errors:                4,
		Score:                 math.Inf(1),
	}
	return res
}

func TestPrintConsoleResults(t *testing.T) {
	results := createSampleResults()
	cfg := &config.Config{
		CheckDNSSEC:         true,
		CheckNXDOMAIN:       true,
		CheckRebinding:      true,
		AccuracyCheckFile:   "dummy.txt", // Enable accuracy check output
		AccuracyCheckDomain: "test.local.",
		CheckDotcom:         true,
	}

	var buf bytes.Buffer
	require.NoError(t, PrintConsoleResults(&buf, results, cfg))
	output := buf.String()

	// Basic checks - presence of headers and server addresses
	assert.Contains(t, output, "DNS Server")
	assert.Contains(t, output, "Protocol")
	assert.Contains(t, output, "DoT") // protocol label for tls://9.9.9.9:853
	assert.Contains(t, output, "Avg Cached")
	assert.Contains(t, output, "StdDev Cached")
	assert.Contains(t, output, "Avg Uncached")
	assert.Contains(t, output, "StdDev Uncached")
	assert.Contains(t, output, "Score")
	assert.Contains(t, output, "Reliability")
	assert.Contains(t, output, ".com Latency")
	assert.Contains(t, output, "DNSSEC")
	assert.Contains(t, output, "NXDOMAIN Policy")
	assert.Contains(t, output, "Rebind Protect")
	assert.Contains(t, output, "Accuracy")

	// Check server order (sorted by composite Score ascending, unrankable last)
	assert.Regexp(t, `1\.1\.1\.1:53.*8\.8\.8\.8:53.*tls://9\.9\.9\.9:853`, strings.ReplaceAll(output, "\n", " "))

	// Check specific values for the best server (1.1.1.1)
	assert.Contains(t, output, "1.1.1.1:53")
	assert.Contains(t, output, "11.0 ms")   // Avg Cached
	assert.Contains(t, output, "1.4 ms")    // StdDev Cached
	assert.Contains(t, output, "25.0 ms")   // Avg Uncached
	assert.Contains(t, output, "26.7 ms")   // Score (distinct from Avg Uncached)
	assert.Contains(t, output, "5.0 ms")    // StdDev Uncached
	assert.Contains(t, output, "100.0%")    // Reliability
	assert.Contains(t, output, "15.0 ms")   // .com Latency
	assert.Contains(t, output, "Yes")       // DNSSEC
	assert.Contains(t, output, "No Hijack") // NXDOMAIN
	assert.Contains(t, output, "Blocks")    // Rebinding
	assert.Contains(t, output, "Accurate")  // Accuracy

	// Check specific values for the second server (8.8.8.8)
	assert.Contains(t, output, "8.8.8.8:53")
	assert.Contains(t, output, "15.0 ms") // Avg Cached
	assert.Contains(t, output, "N/A")     // StdDev Cached (n=1)
	assert.Contains(t, output, "35.0 ms") // Avg Uncached
	assert.Contains(t, output, "36.2 ms") // Score (distinct from Avg Uncached)
	// assert.Contains(t, output, "N/A")     // StdDev Uncached (n=1) - This might appear multiple times, check specific column context if needed
	assert.Contains(t, output, "66.7%") // Reliability
	// assert.Contains(t, output, "N/A")     // .com Latency
	assert.Contains(t, output, "Yes")          // DNSSEC
	assert.Contains(t, output, "Inconclusive") // NXDOMAIN enabled but no conclusive probe, not "N/A"
	assert.Contains(t, output, "Allows")       // Rebinding
	assert.Contains(t, output, "Mismatch")     // Accuracy

	// The summary goes to any writer, so -format console -o FILE keeps the
	// recommendation and the inconclusive warnings.
	assert.Contains(t, output, "--- Conclusion ---")
	assert.Contains(t, output, "Recommended server: 1.1.1.1:53")
	assert.Contains(t, output, "Warning (8.8.8.8:53): Returned inaccurate results")
	assert.Contains(t, output, "Warning (tls://9.9.9.9:853): Accuracy check for test.local. was inconclusive.")
}

func TestWriteCSVResults(t *testing.T) {
	results := createSampleResults()
	cfg := &config.Config{
		CheckDNSSEC:       true,
		CheckNXDOMAIN:     true,
		CheckRebinding:    true,
		AccuracyCheckFile: "dummy.txt",
		CheckDotcom:       true,
	}

	var buf bytes.Buffer
	err := WriteCSVResults(&buf, results, cfg)
	require.NoError(t, err)

	output := buf.String()
	// Use CSV reader to parse and verify
	r := csv.NewReader(strings.NewReader(output))
	records, err := r.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 4) // Header + 3 data rows

	// Check Header
	expectedHeader := []string{
		"ServerAddress",
		"Protocol",
		"AvgCachedLatency(ms)", "StdDevCachedLatency(ms)",
		"AvgUncachedLatency(ms)", "StdDevUncachedLatency(ms)",
		"Score(ms)",
		"Reliability(%)",
		"SuccessfulCachedQueries", "SuccessfulUncachedQueries",
		"FailedLatencyQueries", "TimeoutErrors", "TransportErrors", "DNSFailures", "MalformedResponses", "TotalLatencyQueries",
		"DotcomLatency(ms)",
		"SupportsDNSSEC", "HijacksNXDOMAIN", "BlocksRebinding", "IsAccurate",
	}
	expectedHeader = append(expectedHeader, "Provider", "Profile", "Roles", "EndpointID", "IPFamily", "Transport", "TLSServerName", "CatalogVersion", "FilteringPolicy", "ComparisonGroup", "TruncatedResponses", "PolicyResponses", "DNSSECState", "NXDOMAINState", "RebindingState", "AccuracyState", "FilteringState", "DotcomState", "SkippedQueries")
	assert.Equal(t, expectedHeader, records[0])

	// Check Data Rows (order is sorted: 1.1.1.1, 8.8.8.8, 9.9.9.9)
	// Row 1: 1.1.1.1
	assert.Equal(t, "1.1.1.1:53", records[1][0])
	assert.Equal(t, "UDP", records[1][1])     // Protocol
	assert.Equal(t, "11.000", records[1][2])  // Avg Cached
	assert.Equal(t, "1.414", records[1][3])   // StdDev Cached
	assert.Equal(t, "25.000", records[1][4])  // Avg Uncached
	assert.Equal(t, "5.000", records[1][5])   // StdDev Uncached
	assert.Equal(t, "26.700", records[1][6])  // Score
	assert.Equal(t, "100.0", records[1][7])   // Reliability
	assert.Equal(t, "2", records[1][8])       // Success Cached
	assert.Equal(t, "3", records[1][9])       // Success Uncached
	assert.Equal(t, "0", records[1][10])      // Errors
	assert.Equal(t, "0", records[1][11])      // Timeout Errors
	assert.Equal(t, "0", records[1][12])      // Transport Errors
	assert.Equal(t, "0", records[1][13])      // DNS Failures
	assert.Equal(t, "0", records[1][14])      // Malformed Responses
	assert.Equal(t, "5", records[1][15])      // Total Queries
	assert.Equal(t, "15.000", records[1][16]) // Dotcom
	assert.Equal(t, "true", records[1][17])   // DNSSEC
	assert.Equal(t, "false", records[1][18])  // NXDOMAIN
	assert.Equal(t, "true", records[1][19])   // Rebinding
	assert.Equal(t, "true", records[1][20])   // Accuracy

	// Row 2: 8.8.8.8
	assert.Equal(t, "8.8.8.8:53", records[2][0])
	assert.Equal(t, "UDP", records[2][1])    // Protocol
	assert.Equal(t, "15.000", records[2][2]) // Avg Cached
	assert.Equal(t, "N/A", records[2][3])    // StdDev Cached (n=1)
	assert.Equal(t, "35.000", records[2][4]) // Avg Uncached
	assert.Equal(t, "N/A", records[2][5])    // StdDev Uncached (n=1)
	assert.Equal(t, "36.200", records[2][6]) // Score
	assert.Equal(t, "66.7", records[2][7])   // Reliability
	assert.Equal(t, "1", records[2][8])      // Success Cached
	assert.Equal(t, "1", records[2][9])      // Success Uncached
	assert.Equal(t, "1", records[2][10])     // Errors
	assert.Equal(t, "0", records[2][11])     // Timeout Errors
	assert.Equal(t, "0", records[2][12])     // Transport Errors
	assert.Equal(t, "0", records[2][13])     // DNS Failures
	assert.Equal(t, "0", records[2][14])     // Malformed Responses
	assert.Equal(t, "3", records[2][15])     // Total Queries
	assert.Equal(t, "N/A", records[2][16])   // Dotcom
	assert.Equal(t, "true", records[2][17])  // DNSSEC
	assert.Equal(t, "N/A", records[2][18])   // NXDOMAIN
	assert.Equal(t, "false", records[2][19]) // Rebinding
	assert.Equal(t, "false", records[2][20]) // Accuracy

	// Row 3: 9.9.9.9
	assert.Equal(t, "tls://9.9.9.9:853", records[3][0])
	assert.Equal(t, "DoT", records[3][1])  // Protocol
	assert.Equal(t, "N/A", records[3][2])  // Avg Cached
	assert.Equal(t, "N/A", records[3][3])  // StdDev Cached
	assert.Equal(t, "N/A", records[3][4])  // Avg Uncached
	assert.Equal(t, "N/A", records[3][5])  // StdDev Uncached
	assert.Equal(t, "", records[3][6])     // Score (unrankable +Inf → empty)
	assert.Equal(t, "0.0", records[3][7])  // Reliability
	assert.Equal(t, "0", records[3][8])    // Success Cached
	assert.Equal(t, "0", records[3][9])    // Success Uncached
	assert.Equal(t, "4", records[3][10])   // Errors
	assert.Equal(t, "0", records[3][11])   // Timeout Errors
	assert.Equal(t, "0", records[3][12])   // Transport Errors
	assert.Equal(t, "0", records[3][13])   // DNS Failures
	assert.Equal(t, "0", records[3][14])   // Malformed Responses
	assert.Equal(t, "4", records[3][15])   // Total Queries
	assert.Equal(t, "N/A", records[3][16]) // Dotcom
	assert.Equal(t, "N/A", records[3][17]) // DNSSEC
	assert.Equal(t, "N/A", records[3][18]) // NXDOMAIN
	assert.Equal(t, "N/A", records[3][19]) // Rebinding
	assert.Equal(t, "N/A", records[3][20]) // Accuracy
}

func TestWriteJSONResults(t *testing.T) {
	results := createSampleResults()
	cfg := &config.Config{
		CheckDNSSEC:       true,
		CheckNXDOMAIN:     true,
		CheckRebinding:    true,
		AccuracyCheckFile: "dummy.txt",
		CheckDotcom:       true,
	}

	var buf bytes.Buffer
	err := WriteJSONResults(&buf, results, cfg)
	require.NoError(t, err)

	var report JSONReport
	var jsonOutput []JSONServerResult
	err = json.Unmarshal(buf.Bytes(), &report)
	require.NoError(t, err)

	jsonOutput = report.Results
	assert.Equal(t, "2", report.SchemaVersion)
	require.Len(t, jsonOutput, 3)

	// Check order (sorted)
	assert.Equal(t, "1.1.1.1:53", jsonOutput[0].ServerAddress)
	assert.Equal(t, "8.8.8.8:53", jsonOutput[1].ServerAddress)
	assert.Equal(t, "tls://9.9.9.9:853", jsonOutput[2].ServerAddress)

	// Check protocol labels
	assert.Equal(t, "UDP", jsonOutput[0].Protocol)
	assert.Equal(t, "UDP", jsonOutput[1].Protocol)
	assert.Equal(t, "DoT", jsonOutput[2].Protocol)

	// Check values for 1.1.1.1
	res1 := jsonOutput[0]
	assert.NotNil(t, res1.AvgCachedLatencyMs)
	assert.InDelta(t, 11.0, *res1.AvgCachedLatencyMs, 0.001)
	assert.NotNil(t, res1.StdDevCachedLatencyMs)
	assert.InDelta(t, 1.414, *res1.StdDevCachedLatencyMs, 0.001)
	assert.NotNil(t, res1.AvgUncachedLatencyMs)
	assert.InDelta(t, 25.0, *res1.AvgUncachedLatencyMs, 0.001)
	assert.NotNil(t, res1.StdDevUncachedLatencyMs)
	assert.InDelta(t, 5.0, *res1.StdDevUncachedLatencyMs, 0.001)
	assert.InDelta(t, 100.0, res1.ReliabilityPct, 0.01)
	assert.Equal(t, 2, res1.SuccessfulCachedQueries)
	assert.Equal(t, 3, res1.SuccessfulUncachedQueries)
	assert.Equal(t, 0, res1.FailedLatencyQueries)
	assert.Equal(t, 0, res1.Errors)
	assert.Equal(t, 5, res1.TotalLatencyQueries)
	assert.NotNil(t, res1.DotcomLatencyMs)
	assert.InDelta(t, 15.0, *res1.DotcomLatencyMs, 0.001)
	assert.NotNil(t, res1.SupportsDNSSEC)
	assert.True(t, *res1.SupportsDNSSEC)
	assert.NotNil(t, res1.HijacksNXDOMAIN)
	assert.False(t, *res1.HijacksNXDOMAIN)
	assert.NotNil(t, res1.BlocksRebinding)
	assert.True(t, *res1.BlocksRebinding)
	assert.NotNil(t, res1.IsAccurate)
	assert.True(t, *res1.IsAccurate)
	assert.NotNil(t, res1.Score)
	assert.InDelta(t, 26.7, *res1.Score, 1e-9)

	// Check values for 8.8.8.8
	res2 := jsonOutput[1]
	assert.NotNil(t, res2.AvgCachedLatencyMs)
	assert.InDelta(t, 15.0, *res2.AvgCachedLatencyMs, 0.001)
	assert.Nil(t, res2.StdDevCachedLatencyMs) // n=1
	assert.NotNil(t, res2.AvgUncachedLatencyMs)
	assert.InDelta(t, 35.0, *res2.AvgUncachedLatencyMs, 0.001)
	assert.Nil(t, res2.StdDevUncachedLatencyMs) // n=1
	assert.InDelta(t, 66.7, res2.ReliabilityPct, 0.1)
	assert.Equal(t, 1, res2.SuccessfulCachedQueries)
	assert.Equal(t, 1, res2.SuccessfulUncachedQueries)
	assert.Equal(t, 1, res2.FailedLatencyQueries)
	assert.Equal(t, 1, res2.Errors)
	assert.Equal(t, 3, res2.TotalLatencyQueries)
	assert.Nil(t, res2.DotcomLatencyMs)
	assert.NotNil(t, res2.SupportsDNSSEC)
	assert.True(t, *res2.SupportsDNSSEC)
	assert.Nil(t, res2.HijacksNXDOMAIN) // Check failed or not run
	assert.NotNil(t, res2.BlocksRebinding)
	assert.False(t, *res2.BlocksRebinding)
	assert.NotNil(t, res2.IsAccurate)
	assert.False(t, *res2.IsAccurate)
	assert.NotNil(t, res2.Score)
	assert.InDelta(t, 36.2, *res2.Score, 1e-9)

	// Check values for 9.9.9.9
	res3 := jsonOutput[2]
	assert.Nil(t, res3.AvgCachedLatencyMs)
	assert.Nil(t, res3.StdDevCachedLatencyMs)
	assert.Nil(t, res3.AvgUncachedLatencyMs)
	assert.Nil(t, res3.StdDevUncachedLatencyMs)
	assert.InDelta(t, 0.0, res3.ReliabilityPct, 0.01)
	assert.Equal(t, 0, res3.SuccessfulCachedQueries)
	assert.Equal(t, 0, res3.SuccessfulUncachedQueries)
	assert.Equal(t, 4, res3.FailedLatencyQueries)
	assert.Equal(t, 4, res3.Errors)
	assert.Equal(t, 4, res3.TotalLatencyQueries)
	assert.Nil(t, res3.DotcomLatencyMs)
	assert.Nil(t, res3.SupportsDNSSEC)
	assert.Nil(t, res3.HijacksNXDOMAIN)
	assert.Nil(t, res3.BlocksRebinding)
	assert.Nil(t, res3.IsAccurate)
	assert.Nil(t, res3.Score)
}

func TestBuildJSONResultScore(t *testing.T) {
	cfg := &config.Config{}

	finite := buildJSONResult(&analysis.ServerResult{ServerAddress: "1.1.1.1", Score: 12.5}, cfg)
	require.NotNil(t, finite.Score)
	assert.InDelta(t, 12.5, *finite.Score, 1e-9)

	unrankable := buildJSONResult(&analysis.ServerResult{ServerAddress: "2.2.2.2", Score: math.Inf(1)}, cfg)
	assert.Nil(t, unrankable.Score, "unrankable score must serialize as null")
}

func TestBuildRow_NeverAttemptedServerShowsNAReliability(t *testing.T) {
	cfg := &config.Config{}
	res := &analysis.ServerResult{
		ServerAddress: "1.1.1.1:53",
		Protocol:      "UDP",
		TotalQueries:  4,
		Skipped:       4, // interrupted before any probe was attempted
	}
	row := buildRow(res, cfg)
	assert.Equal(t, "N/A", row[7], "reliability must read N/A, not 0.0%%, when nothing was attempted")
}

func TestPrintServerWarnings_NoLowReliabilityWarningWhenNeverAttempted(t *testing.T) {
	var buf bytes.Buffer
	results := []*analysis.ServerResult{
		{ServerAddress: "skipped:53", TotalQueries: 4, Skipped: 4, Reliability: 0.0},
	}
	printServerWarnings(&buf, results, nil, &config.Config{})
	assert.NotContains(t, buf.String(), "Low reliability", "never-attempted servers must not be flagged as unreliable")
}

func TestBuildJSONResultSkippedQueries(t *testing.T) {
	cfg := &config.Config{}

	interrupted := buildJSONResult(&analysis.ServerResult{ServerAddress: "1.1.1.1", TotalQueries: 10, Skipped: 6}, cfg)
	assert.Equal(t, 6, interrupted.SkippedQueries, "skipped queries must be reported for interrupted runs")
	assert.Equal(t, 10, interrupted.TotalLatencyQueries)
}

// --- Additional tests ---

func TestSortServerResultsByScore(t *testing.T) {
	results := []*analysis.ServerResult{
		{ServerAddress: "slow", Score: 50.0},
		{ServerAddress: "fast", Score: 10.0},
		{ServerAddress: "unrankable", Score: math.Inf(1)},
		{ServerAddress: "mid", Score: 30.0},
	}
	sortServerResults(results)
	got := []string{results[0].ServerAddress, results[1].ServerAddress, results[2].ServerAddress, results[3].ServerAddress}
	want := []string{"fast", "mid", "slow", "unrankable"}
	assert.Equal(t, want, got)
}

func TestSortServerResultsTieBreakByAddress(t *testing.T) {
	results := []*analysis.ServerResult{
		{ServerAddress: "b", Score: 10.0},
		{ServerAddress: "a", Score: 10.0},
	}
	sortServerResults(results)
	assert.Equal(t, "a", results[0].ServerAddress)
	assert.Equal(t, "b", results[1].ServerAddress)
}

// TestSortServerResultsTieBreakByEndpointID checks that endpoints sharing a
// group, score and serverAddress (possible for IPv4 and IPv6 catalogue
// endpoints) are ordered by endpoint ID, so output order is deterministic.
func TestSortServerResultsTieBreakByEndpointID(t *testing.T) {
	results := []*analysis.ServerResult{
		{ServerAddress: "tls://one.one.one.one:853", Score: 10.0, Metadata: catalog.Metadata{EndpointID: "cf-b"}},
		{ServerAddress: "tls://one.one.one.one:853", Score: 10.0, Metadata: catalog.Metadata{EndpointID: "cf-a"}},
	}
	sortServerResults(results)
	assert.Equal(t, "cf-a", results[0].EndpointID)
	assert.Equal(t, "cf-b", results[1].EndpointID)
}

// TestCheckStateColumnsAndJSONChecks pins each check state to its own CSV
// column and JSON checks key. The two results use different state permutations
// so swapping any two columns or keys changes at least one value.
func TestCheckStateColumnsAndJSONChecks(t *testing.T) {
	pass, fail, inconclusive, na := analysis.Pass, analysis.Fail, analysis.Inconclusive, analysis.NotApplicable
	states := []map[string]analysis.CheckState{
		{"dnssec": pass, "nxdomain": fail, "rebinding": inconclusive, "accuracy": na, "filtering": pass, "dotcom": fail},
		{"dnssec": fail, "nxdomain": pass, "rebinding": na, "accuracy": inconclusive, "filtering": inconclusive, "dotcom": na},
	}
	columns := map[string]string{
		"DNSSECState": "dnssec", "NXDOMAINState": "nxdomain", "RebindingState": "rebinding",
		"AccuracyState": "accuracy", "FilteringState": "filtering", "DotcomState": "dotcom",
	}
	results := analysis.NewBenchmarkResults()
	for i, checks := range states {
		address := fmt.Sprintf("server-%d:53", i)
		results.Results[address] = &analysis.ServerResult{ServerAddress: address, Protocol: "UDP", Score: float64(i + 1), Checks: checks}
	}
	cfg := &config.Config{}

	var csvBuf bytes.Buffer
	require.NoError(t, WriteCSVResults(&csvBuf, results, cfg))
	records, err := csv.NewReader(&csvBuf).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 1+len(states))
	index := map[string]int{}
	for i, name := range records[0] {
		index[name] = i
	}
	for row, checks := range states {
		for column, check := range columns {
			require.Contains(t, index, column)
			assert.Equal(t, string(checks[check]), records[row+1][index[column]], "row %d column %s", row, column)
		}
	}

	var jsonBuf bytes.Buffer
	require.NoError(t, WriteJSONResults(&jsonBuf, results, cfg))
	var report struct {
		Results []struct {
			ServerAddress string                         `json:"serverAddress"`
			Checks        map[string]analysis.CheckState `json:"checks"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(jsonBuf.Bytes(), &report))
	require.Len(t, report.Results, len(states))
	for i, r := range report.Results {
		assert.Equal(t, fmt.Sprintf("server-%d:53", i), r.ServerAddress)
		assert.Equal(t, states[i], r.Checks)
	}
}

func TestFindBestServer(t *testing.T) {
	bp := func(b bool) *bool { return &b }
	slowDotcom := 80 * time.Millisecond

	tests := []struct {
		name     string
		results  []*analysis.ServerResult
		cfg      *config.Config
		wantAddr string // "" means expect nil
	}{
		{
			name: "lowest score wins when no accuracy check",
			results: []*analysis.ServerResult{
				{ServerAddress: "fast", Score: 10.0},
				{ServerAddress: "slow", Score: 40.0},
			},
			cfg:      &config.Config{},
			wantAddr: "fast",
		},
		{
			name: "unrankable servers are skipped",
			results: []*analysis.ServerResult{
				{ServerAddress: "dead", Score: math.Inf(1)},
				{ServerAddress: "ok", Score: 25.0},
			},
			cfg:      &config.Config{},
			wantAddr: "ok",
		},
		{
			name: "accuracy gate excludes faster-but-inaccurate server",
			results: []*analysis.ServerResult{
				{ServerAddress: "fast-wrong", Score: 5.0, IsAccurate: bp(false)},
				{ServerAddress: "slower-right", Score: 20.0, IsAccurate: bp(true)},
			},
			cfg:      &config.Config{AccuracyCheckFile: "accuracy.txt"},
			wantAddr: "slower-right",
		},
		{
			name: "accuracy gate treats nil accuracy as ineligible",
			results: []*analysis.ServerResult{
				{ServerAddress: "unknown", Score: 5.0, IsAccurate: nil},
			},
			cfg:      &config.Config{AccuracyCheckFile: "accuracy.txt"},
			wantAddr: "",
		},
		{
			// A failed .com probe drops out of Score, which would otherwise
			// let it beat a server that answered the probe slowly.
			name: ".com gate excludes server whose probe failed",
			results: []*analysis.ServerResult{
				{ServerAddress: "probe-failed", Score: 5.0},
				{ServerAddress: "probe-slow", Score: 20.0, DotcomLatency: &slowDotcom},
			},
			cfg:      &config.Config{CheckDotcom: true},
			wantAddr: "probe-slow",
		},
		{
			name:     "no servers yields nil",
			results:  []*analysis.ServerResult{},
			cfg:      &config.Config{},
			wantAddr: "",
		},
		{
			name: "all unrankable yields nil",
			results: []*analysis.ServerResult{
				{ServerAddress: "dead1", Score: math.Inf(1)},
				{ServerAddress: "dead2", Score: math.Inf(1)},
			},
			cfg:      &config.Config{},
			wantAddr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findBestServer(tt.results, tt.cfg)
			if tt.wantAddr == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantAddr, got.ServerAddress)
		})
	}
}

func TestPrintSummary(t *testing.T) {
	dotcomLatency := 15 * time.Millisecond

	tests := []struct {
		name         string
		results      *analysis.BenchmarkResults
		cfg          *config.Config
		wantContains []string
		wantAbsent   []string
	}{
		{
			name: "with best server",
			results: func() *analysis.BenchmarkResults {
				res := analysis.NewBenchmarkResults()
				res.Results["1.1.1.1:53"] = &analysis.ServerResult{
					ServerAddress:         "1.1.1.1:53",
					Protocol:              "UDP",
					CachedLatencies:       []time.Duration{10 * time.Millisecond},
					UncachedLatencies:     []time.Duration{20 * time.Millisecond},
					AvgCachedLatency:      10 * time.Millisecond,
					AvgUncachedLatency:    20 * time.Millisecond,
					StdDevCachedLatency:   1 * time.Millisecond,
					StdDevUncachedLatency: 2 * time.Millisecond,
					Reliability:           100.0,
					DotcomLatency:         &dotcomLatency,
					Score:                 18.0,
				}
				return res
			}(),
			cfg: &config.Config{CheckDotcom: true},
			wantContains: []string{
				"--- Conclusion ---",
				"Recommended server: 1.1.1.1:53 using UDP protocol",
				"1.1.1.1:53",
				"Composite Score:",
				"Avg Uncached Latency",
				"Avg Cached Latency",
				".com Latency",
				"Reliability: 100.0%",
			},
			wantAbsent: []string{
				"Fastest recommended server",
			},
		},
		{
			name: "no eligible servers",
			results: func() *analysis.BenchmarkResults {
				res := analysis.NewBenchmarkResults()
				res.Results["unrankable:53"] = &analysis.ServerResult{
					ServerAddress: "unrankable:53",
					Reliability:   50.0,
					Score:         math.Inf(1),
				}
				return res
			}(),
			cfg: &config.Config{},
			wantContains: []string{
				"--- Conclusion ---",
				"Could not determine a recommended server with a rankable composite score.",
			},
			wantAbsent: []string{
				"Recommended server",
			},
		},
		{
			name:    "empty results",
			results: analysis.NewBenchmarkResults(),
			cfg:     &config.Config{},
			wantAbsent: []string{
				"--- Conclusion ---",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			serverResults := getServerResultsSlice(tt.results)
			sortServerResults(serverResults)
			printSummary(&buf, serverResults, tt.cfg)
			output := buf.String()

			for _, want := range tt.wantContains {
				assert.Contains(t, output, want, "Expected output to contain: %s", want)
			}
			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, output, absent, "Expected output to not contain: %s", absent)
			}
		})
	}
}

func TestPrintServerWarnings(t *testing.T) {
	bTrue := true
	bFalse := false
	// The best server is identified by pointer, as findBestServer returns it.
	soleBest := &analysis.ServerResult{ServerAddress: "best:53", Reliability: 100.0}
	unreliableBest := &analysis.ServerResult{ServerAddress: "best:53", TotalQueries: 10, Reliability: 50.0}
	hijackingBest := &analysis.ServerResult{ServerAddress: "best:53", Reliability: 100.0, HijacksNXDOMAIN: &bTrue}

	tests := []struct {
		name         string
		results      []*analysis.ServerResult
		bestServer   *analysis.ServerResult
		cfg          *config.Config
		wantContains []string
		wantAbsent   []string
	}{
		{
			name: "warning for low reliability",
			results: []*analysis.ServerResult{
				{
					ServerAddress: "unreliable:53",
					TotalQueries:  4, // probes were attempted; low reliability is real
					Reliability:   50.0,
				},
			},
			bestServer: nil,
			cfg:        &config.Config{},
			wantContains: []string{
				"Warning (unreliable:53): Low reliability (50.0%)",
			},
		},
		{
			name: "warning for NXDOMAIN hijacking",
			results: []*analysis.ServerResult{
				{
					ServerAddress:   "hijacker:53",
					Reliability:     100.0,
					HijacksNXDOMAIN: &bTrue,
				},
			},
			bestServer: nil,
			cfg:        &config.Config{CheckNXDOMAIN: true},
			wantContains: []string{
				"Warning (hijacker:53): Appears to hijack NXDOMAIN responses",
			},
		},
		{
			name: "warning for rebinding vulnerability",
			results: []*analysis.ServerResult{
				{
					ServerAddress:   "vulnerable:53",
					Reliability:     100.0,
					BlocksRebinding: &bFalse,
				},
			},
			bestServer: nil,
			cfg:        &config.Config{CheckRebinding: true},
			wantContains: []string{
				"Warning (vulnerable:53): Allows responses with private IPs (rebinding risk)",
			},
		},
		{
			name: "warning for dns failures",
			results: []*analysis.ServerResult{
				{
					ServerAddress: "dnsfail:53",
					Reliability:   100.0,
					DNSFailures:   2,
				},
			},
			bestServer: nil,
			cfg:        &config.Config{},
			wantContains: []string{
				"Warning (dnsfail:53): Returned 2 unexpected DNS failure responses during latency probes.",
			},
		},
		{
			name: "warning for inaccurate results",
			results: []*analysis.ServerResult{
				{
					ServerAddress: "inaccurate:53",
					Reliability:   100.0,
					IsAccurate:    &bFalse,
				},
			},
			bestServer: nil,
			cfg:        &config.Config{AccuracyCheckFile: "enabled", AccuracyCheckDomain: "test.local."},
			wantContains: []string{
				"Warning (inaccurate:53): Returned inaccurate results for test.local.",
			},
		},
		{
			name: "warning for inconclusive accuracy",
			results: []*analysis.ServerResult{
				{
					ServerAddress: "unknown-accuracy:53",
					Reliability:   100.0,
					IsAccurate:    nil,
				},
			},
			bestServer: nil,
			cfg:        &config.Config{AccuracyCheckFile: "enabled", AccuracyCheckDomain: "test.local."},
			wantContains: []string{
				"Warning (unknown-accuracy:53): Accuracy check for test.local. was inconclusive.",
			},
		},
		{
			name:       "best server alone has no others to report",
			results:    []*analysis.ServerResult{soleBest},
			bestServer: soleBest,
			cfg:        &config.Config{},
			wantAbsent: []string{"Other tested servers"},
		},
		{
			name: "no issues besides best server",
			results: []*analysis.ServerResult{
				{
					ServerAddress: "good:53",
					Reliability:   100.0,
				},
			},
			bestServer: &analysis.ServerResult{ServerAddress: "best:53"},
			cfg:        &config.Config{},
			wantContains: []string{
				"Other tested servers performed reliably",
			},
		},
		{
			name:         "recommended server's own issues are reported",
			results:      []*analysis.ServerResult{unreliableBest},
			bestServer:   unreliableBest,
			cfg:          &config.Config{},
			wantContains: []string{"Warning (recommended, best:53): Low reliability (50.0%)"},
		},
		{
			name:         "recommended server that hijacks NXDOMAIN is flagged",
			results:      []*analysis.ServerResult{hijackingBest, {ServerAddress: "good:53", Reliability: 100.0}},
			bestServer:   hijackingBest,
			cfg:          &config.Config{CheckNXDOMAIN: true},
			wantContains: []string{"Warning (recommended, best:53): Appears to hijack NXDOMAIN responses", "Other tested servers performed reliably"},
		},
		{
			name:         "DNSSEC failure is warned",
			results:      []*analysis.ServerResult{{ServerAddress: "novalidate:53", Reliability: 100.0, Checks: map[string]analysis.CheckState{"dnssec": analysis.Fail}}},
			bestServer:   soleBest,
			cfg:          &config.Config{CheckDNSSEC: true},
			wantContains: []string{"Warning (novalidate:53): Does not validate DNSSEC"},
			wantAbsent:   []string{"without major issues"},
		},
		{
			name:         "filtering failure is warned",
			results:      []*analysis.ServerResult{{ServerAddress: "unfiltered:53", Reliability: 100.0, Checks: map[string]analysis.CheckState{"filtering": analysis.Fail}}},
			bestServer:   soleBest,
			cfg:          &config.Config{CheckFiltering: true},
			wantContains: []string{"Warning (unfiltered:53): Did not block the documented filtering probe domains"},
			wantAbsent:   []string{"without major issues"},
		},
		{
			name: "failed and inconclusive .com probes are warned",
			results: []*analysis.ServerResult{
				{ServerAddress: "servfail:53", Reliability: 100.0, Checks: map[string]analysis.CheckState{"dotcom": analysis.Fail}},
				{ServerAddress: "timeout:53", Reliability: 100.0, Checks: map[string]analysis.CheckState{"dotcom": analysis.Inconclusive}},
			},
			cfg: &config.Config{CheckDotcom: true},
			wantContains: []string{
				"Warning (servfail:53): .com probe did not return NXDOMAIN",
				"Warning (timeout:53): .com probe was inconclusive",
			},
		},
		{
			name: "inconclusive checks are warned",
			results: []*analysis.ServerResult{
				soleBest,
				{ServerAddress: "flaky:53", Reliability: 100.0, Checks: map[string]analysis.CheckState{
					"dnssec": analysis.Inconclusive, "nxdomain": analysis.Inconclusive,
					"filtering": analysis.Inconclusive, "rebinding": analysis.Inconclusive,
				}},
				{ServerAddress: "open:53", Reliability: 100.0, Checks: map[string]analysis.CheckState{"rebinding": analysis.Fail}},
			},
			bestServer: soleBest,
			cfg:        &config.Config{CheckDNSSEC: true, CheckNXDOMAIN: true, CheckFiltering: true, CheckRebinding: true, RebindingDomain: "rebind.example."},
			wantContains: []string{
				"Warning (flaky:53): DNSSEC check was inconclusive",
				"Warning (flaky:53): NXDOMAIN check was inconclusive",
				"Warning (flaky:53): Filtering check was inconclusive",
				"Warning (flaky:53): Rebinding check was inconclusive",
			},
			wantAbsent: []string{"without major issues"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printServerWarnings(&buf, tt.results, tt.bestServer, tt.cfg)
			output := buf.String()

			for _, want := range tt.wantContains {
				assert.Contains(t, output, want, "Expected output to contain: %s", want)
			}
			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, output, absent, "Expected output to not contain: %s", absent)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestPrintConsoleResultsReportsWriteError(t *testing.T) {
	err := PrintConsoleResults(failingWriter{}, createSampleResults(), &config.Config{})
	assert.EqualError(t, err, "disk full")
}

// TestJSONSchemaV2Keys pins the schema v2 key names. It decodes into generic
// maps, so renaming a json tag fails here even though a round-trip through
// JSONReport would still pass.
func TestJSONSchemaV2Keys(t *testing.T) {
	cfg := &config.Config{CheckDNSSEC: true, CheckNXDOMAIN: true, CheckRebinding: true, AccuracyCheckFile: "dummy.txt", CheckDotcom: true}
	var buf bytes.Buffer
	require.NoError(t, WriteJSONResults(&buf, createSampleResults(), cfg))

	var report map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	assert.Equal(t, JSONSchemaVersion, report["schemaVersion"])
	assert.Equal(t, "2", JSONSchemaVersion)

	metadata, ok := report["metadata"].(map[string]any)
	require.True(t, ok)
	for _, key := range []string{"startedAt", "queryCorpusId", "requestedQueryCount", "skippedCount", "warmupQueryCount", "interrupted"} {
		assert.Contains(t, metadata, key)
	}

	results, ok := report["results"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, results)
	for _, r := range results {
		result := r.(map[string]any)
		for _, key := range []string{
			"serverAddress", "protocol", "provider", "profile", "roles", "endpointId", "ipFamily", "transport",
			"tlsServerName", "catalogVersion", "filteringPolicy", "sourceURLs", "comparisonGroup", "checks",
			"truncatedResponses", "extendedDnsErrors", "policyResponses", "reliabilityPct", "score",
			"successfulCachedQueries", "successfulUncachedQueries", "timeoutErrors", "transportErrors",
			"dnsFailures", "malformedResponses",
		} {
			assert.Contains(t, result, key)
		}
		for _, key := range []string{"roles", "sourceURLs", "extendedDnsErrors"} {
			assert.IsType(t, []any{}, result[key], "%s must encode as an array, never null", key)
		}
		assert.IsType(t, map[string]any{}, result["checks"], "checks must encode as an object, never null")
	}
}

// TestUnverifiedRebindingNotePrintedOnce checks that when no server passed the
// rebinding domain's private answer through, the summary prints one run-level
// note across all ranking groups instead of a warning per server.
func TestUnverifiedRebindingNotePrintedOnce(t *testing.T) {
	cfg := &config.Config{CheckRebinding: true, RebindingDomain: "rebind.example."}
	inconclusive := map[string]analysis.CheckState{"rebinding": analysis.Inconclusive}
	results := []*analysis.ServerResult{
		{ServerAddress: "a:53", Protocol: "UDP", Reliability: 100, Score: 10, Checks: inconclusive, Metadata: catalog.Metadata{CatalogVersion: "v", Provider: "p1", Profile: "p1", Transport: "udp", IPFamily: "ipv4"}},
		{ServerAddress: "b:853", Protocol: "DoT", Reliability: 100, Score: 20, Checks: inconclusive, Metadata: catalog.Metadata{CatalogVersion: "v", Provider: "p2", Profile: "p2", Transport: "dot", IPFamily: "ipv4"}},
		{ServerAddress: "c:53", Protocol: "UDP", Reliability: 100, Score: 30, Checks: inconclusive},
	}
	var buf bytes.Buffer
	printSummary(&buf, results, cfg)
	output := buf.String()
	assert.Equal(t, 1, strings.Count(output, "test domain is unverified"), output)
	assert.NotContains(t, output, "Rebinding check was inconclusive")

	results[0].Checks = map[string]analysis.CheckState{"rebinding": analysis.Fail}
	buf.Reset()
	printSummary(&buf, results, cfg)
	assert.NotContains(t, buf.String(), "test domain is unverified")
	assert.Contains(t, buf.String(), "Rebinding check was inconclusive")
}

func TestFormatDotcomKeepsFailAndInconclusiveDistinct(t *testing.T) {
	latency := 15 * time.Millisecond
	tests := []struct {
		name string
		res  analysis.ServerResult
		want string
	}{
		{"passed shows latency", analysis.ServerResult{DotcomLatency: &latency, Checks: map[string]analysis.CheckState{"dotcom": analysis.Pass}}, "15.0 ms"},
		{"wrong rcode shows fail", analysis.ServerResult{Checks: map[string]analysis.CheckState{"dotcom": analysis.Fail}}, "Fail"},
		{"timeout shows inconclusive", analysis.ServerResult{Checks: map[string]analysis.CheckState{"dotcom": analysis.Inconclusive}}, "Inconclusive"},
		{"no state shows N/A", analysis.ServerResult{}, "N/A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatDotcom(&tt.res))
		})
	}
}

func TestFormatCheckState(t *testing.T) {
	tests := []struct {
		state analysis.CheckState
		want  string
	}{
		{analysis.Pass, "Pass"},
		{analysis.Fail, "Fail"},
		{analysis.Inconclusive, "Inconclusive"},
		{analysis.NotApplicable, "N/A"},
		{"", "N/A"},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			assert.Equal(t, tt.want, formatCheckState(tt.state))
		})
	}
}

func TestSkippedDotcomWarning(t *testing.T) {
	tests := []struct {
		name    string
		skipped bool
		want    string
	}{
		{"probe sent but inconclusive", false, ".com probe was inconclusive; excluded from recommendation."},
		{"probe never sent", true, ".com probe was not sent before the run was interrupted; excluded from recommendation."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &analysis.ServerResult{
				ServerAddress: "1.1.1.1:53",
				TotalQueries:  2,
				Checks:        map[string]analysis.CheckState{"dotcom": analysis.Inconclusive},
				DotcomSkipped: tt.skipped,
			}
			var buf bytes.Buffer
			printServerWarnings(&buf, []*analysis.ServerResult{res}, nil, &config.Config{CheckDotcom: true})
			assert.Contains(t, buf.String(), tt.want)
		})
	}
}

func TestFindBestServerSkipsUnsentDotcomProbe(t *testing.T) {
	latency := 20 * time.Millisecond
	skipped := &analysis.ServerResult{ServerAddress: "skipped", Score: 5, Checks: map[string]analysis.CheckState{"dotcom": analysis.Inconclusive}, DotcomSkipped: true}
	passed := &analysis.ServerResult{ServerAddress: "passed", Score: 30, DotcomLatency: &latency, Checks: map[string]analysis.CheckState{"dotcom": analysis.Pass}}
	tests := []struct {
		name    string
		results []*analysis.ServerResult
		want    *analysis.ServerResult
	}{
		{"faster skipped server is not recommended", []*analysis.ServerResult{skipped, passed}, passed},
		{"only skipped servers gives no recommendation", []*analysis.ServerResult{skipped}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Same(t, tt.want, findBestServer(tt.results, &config.Config{CheckDotcom: true}))
		})
	}
}
