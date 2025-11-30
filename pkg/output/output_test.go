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

// --- Tests for Main Output Functions ---

// Helper to create sample results
func createSampleResults() *analysis.BenchmarkResults {
	bTrue := true
	bFalse := false
	dotcomLatency := 15 * time.Millisecond
	res := analysis.NewBenchmarkResults()
	res.Results["1.1.1.1:53"] = &analysis.ServerResult{
		ServerAddress:         "1.1.1.1:53",
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
	}
	res.Results["8.8.8.8:53"] = &analysis.ServerResult{
		ServerAddress:         "8.8.8.8:53",
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
	}
	res.Results["tls://9.9.9.9:853"] = &analysis.ServerResult{
		ServerAddress:         "tls://9.9.9.9:853",
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
	PrintConsoleResults(&buf, results, cfg)
	output := buf.String()

	// Basic checks - presence of headers and server addresses
	assert.Contains(t, output, "DNS Server")
	assert.Contains(t, output, "Avg Cached")
	assert.Contains(t, output, "StdDev Cached")
	assert.Contains(t, output, "Avg Uncached")
	assert.Contains(t, output, "StdDev Uncached")
	assert.Contains(t, output, "Reliability")
	assert.Contains(t, output, ".com Latency")
	assert.Contains(t, output, "DNSSEC")
	assert.Contains(t, output, "NXDOMAIN Policy")
	assert.Contains(t, output, "Rebind Protect")
	assert.Contains(t, output, "Accuracy")

	// Check server order (sorted by uncached latency)
	assert.Regexp(t, `1\.1\.1\.1:53.*8\.8\.8\.8:53.*tls://9\.9\.9\.9:853`, strings.ReplaceAll(output, "\n", " "))

	// Check specific values for the best server (1.1.1.1)
	assert.Contains(t, output, "1.1.1.1:53")
	assert.Contains(t, output, "11.0 ms")   // Avg Cached
	assert.Contains(t, output, "1.4 ms")    // StdDev Cached
	assert.Contains(t, output, "25.0 ms")   // Avg Uncached
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
	// assert.Contains(t, output, "N/A")     // StdDev Uncached (n=1) - This might appear multiple times, check specific column context if needed
	assert.Contains(t, output, "66.7%") // Reliability
	// assert.Contains(t, output, "N/A")     // .com Latency
	assert.Contains(t, output, "Yes") // DNSSEC
	// assert.Contains(t, output, "N/A")     // NXDOMAIN
	assert.Contains(t, output, "Allows")   // Rebinding
	assert.Contains(t, output, "Mismatch") // Accuracy

	// Check that summary is NOT printed because the writer is not os.Stdout
	assert.NotContains(t, output, "--- Conclusion ---")
	assert.NotContains(t, output, "Fastest reliable server")
	assert.NotContains(t, output, "Warning (8.8.8.8:53):") // Specific warnings shouldn't be there either
	assert.NotContains(t, output, "Warning (tls://9.9.9.9:853):")

	// We cannot easily test the os.Stdout case here, so we only test the buffer case.
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
		"AvgCachedLatency(ms)", "StdDevCachedLatency(ms)",
		"AvgUncachedLatency(ms)", "StdDevUncachedLatency(ms)",
		"Reliability(%)",
		"SuccessfulCachedQueries", "SuccessfulUncachedQueries",
		"Errors", "TotalLatencyQueries",
		"DotcomLatency(ms)",
		"SupportsDNSSEC", "HijacksNXDOMAIN", "BlocksRebinding", "IsAccurate",
	}
	assert.Equal(t, expectedHeader, records[0])

	// Check Data Rows (order is sorted: 1.1.1.1, 8.8.8.8, 9.9.9.9)
	// Row 1: 1.1.1.1
	assert.Equal(t, "1.1.1.1:53", records[1][0])
	assert.Equal(t, "11.000", records[1][1])  // Avg Cached
	assert.Equal(t, "1.414", records[1][2])   // StdDev Cached
	assert.Equal(t, "25.000", records[1][3])  // Avg Uncached
	assert.Equal(t, "5.000", records[1][4])   // StdDev Uncached
	assert.Equal(t, "100.0", records[1][5])   // Reliability
	assert.Equal(t, "2", records[1][6])       // Success Cached
	assert.Equal(t, "3", records[1][7])       // Success Uncached
	assert.Equal(t, "0", records[1][8])       // Errors
	assert.Equal(t, "5", records[1][9])       // Total Queries
	assert.Equal(t, "15.000", records[1][10]) // Dotcom
	assert.Equal(t, "true", records[1][11])   // DNSSEC
	assert.Equal(t, "false", records[1][12])  // NXDOMAIN
	assert.Equal(t, "true", records[1][13])   // Rebinding
	assert.Equal(t, "true", records[1][14])   // Accuracy

	// Row 2: 8.8.8.8
	assert.Equal(t, "8.8.8.8:53", records[2][0])
	assert.Equal(t, "15.000", records[2][1]) // Avg Cached
	assert.Equal(t, "N/A", records[2][2])    // StdDev Cached (n=1)
	assert.Equal(t, "35.000", records[2][3]) // Avg Uncached
	assert.Equal(t, "N/A", records[2][4])    // StdDev Uncached (n=1)
	assert.Equal(t, "66.7", records[2][5])   // Reliability
	assert.Equal(t, "1", records[2][6])      // Success Cached
	assert.Equal(t, "1", records[2][7])      // Success Uncached
	assert.Equal(t, "1", records[2][8])      // Errors
	assert.Equal(t, "3", records[2][9])      // Total Queries
	assert.Equal(t, "N/A", records[2][10])   // Dotcom
	assert.Equal(t, "true", records[2][11])  // DNSSEC
	assert.Equal(t, "N/A", records[2][12])   // NXDOMAIN
	assert.Equal(t, "false", records[2][13]) // Rebinding
	assert.Equal(t, "false", records[2][14]) // Accuracy

	// Row 3: 9.9.9.9
	assert.Equal(t, "tls://9.9.9.9:853", records[3][0])
	assert.Equal(t, "N/A", records[3][1])  // Avg Cached
	assert.Equal(t, "N/A", records[3][2])  // StdDev Cached
	assert.Equal(t, "N/A", records[3][3])  // Avg Uncached
	assert.Equal(t, "N/A", records[3][4])  // StdDev Uncached
	assert.Equal(t, "0.0", records[3][5])  // Reliability
	assert.Equal(t, "0", records[3][6])    // Success Cached
	assert.Equal(t, "0", records[3][7])    // Success Uncached
	assert.Equal(t, "4", records[3][8])    // Errors
	assert.Equal(t, "4", records[3][9])    // Total Queries
	assert.Equal(t, "N/A", records[3][10]) // Dotcom
	assert.Equal(t, "N/A", records[3][11]) // DNSSEC
	assert.Equal(t, "N/A", records[3][12]) // NXDOMAIN
	assert.Equal(t, "N/A", records[3][13]) // Rebinding
	assert.Equal(t, "N/A", records[3][14]) // Accuracy
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

	var jsonOutput []JSONServerResult
	err = json.Unmarshal(buf.Bytes(), &jsonOutput)
	require.NoError(t, err)

	require.Len(t, jsonOutput, 3)

	// Check order (sorted)
	assert.Equal(t, "1.1.1.1:53", jsonOutput[0].ServerAddress)
	assert.Equal(t, "8.8.8.8:53", jsonOutput[1].ServerAddress)
	assert.Equal(t, "tls://9.9.9.9:853", jsonOutput[2].ServerAddress)

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

	// Check values for 9.9.9.9
	res3 := jsonOutput[2]
	assert.Nil(t, res3.AvgCachedLatencyMs)
	assert.Nil(t, res3.StdDevCachedLatencyMs)
	assert.Nil(t, res3.AvgUncachedLatencyMs)
	assert.Nil(t, res3.StdDevUncachedLatencyMs)
	assert.InDelta(t, 0.0, res3.ReliabilityPct, 0.01)
	assert.Equal(t, 0, res3.SuccessfulCachedQueries)
	assert.Equal(t, 0, res3.SuccessfulUncachedQueries)
	assert.Equal(t, 4, res3.Errors)
	assert.Equal(t, 4, res3.TotalLatencyQueries)
	assert.Nil(t, res3.DotcomLatencyMs)
	assert.Nil(t, res3.SupportsDNSSEC)
	assert.Nil(t, res3.HijacksNXDOMAIN)
	assert.Nil(t, res3.BlocksRebinding)
	assert.Nil(t, res3.IsAccurate)
}

// --- Additional tests ---

func TestFindBestServer(t *testing.T) {
	bTrue := true
	bFalse := false

	tests := []struct {
		name           string
		results        []*analysis.ServerResult
		cfg            *config.Config
		wantServerAddr string
	}{
		{
			name:           "no results",
			results:        []*analysis.ServerResult{},
			cfg:            &config.Config{},
			wantServerAddr: "",
		},
		{
			name: "single reliable server",
			results: []*analysis.ServerResult{
				{
					ServerAddress:      "1.1.1.1:53",
					UncachedLatencies:  []time.Duration{20 * time.Millisecond},
					AvgUncachedLatency: 20 * time.Millisecond,
					Reliability:        100.0,
				},
			},
			cfg:            &config.Config{},
			wantServerAddr: "1.1.1.1:53",
		},
		{
			name: "skip unreliable server",
			results: []*analysis.ServerResult{
				{
					ServerAddress:      "unreliable.server:53",
					UncachedLatencies:  []time.Duration{10 * time.Millisecond},
					AvgUncachedLatency: 10 * time.Millisecond,
					Reliability:        50.0, // Below 99% threshold
				},
				{
					ServerAddress:      "reliable.server:53",
					UncachedLatencies:  []time.Duration{20 * time.Millisecond},
					AvgUncachedLatency: 20 * time.Millisecond,
					Reliability:        100.0,
				},
			},
			cfg:            &config.Config{},
			wantServerAddr: "reliable.server:53",
		},
		{
			name: "skip inaccurate server",
			results: []*analysis.ServerResult{
				{
					ServerAddress:      "inaccurate.server:53",
					UncachedLatencies:  []time.Duration{10 * time.Millisecond},
					AvgUncachedLatency: 10 * time.Millisecond,
					Reliability:        100.0,
					IsAccurate:         &bFalse,
				},
				{
					ServerAddress:      "accurate.server:53",
					UncachedLatencies:  []time.Duration{20 * time.Millisecond},
					AvgUncachedLatency: 20 * time.Millisecond,
					Reliability:        100.0,
					IsAccurate:         &bTrue,
				},
			},
			cfg:            &config.Config{AccuracyCheckFile: "enabled"},
			wantServerAddr: "accurate.server:53",
		},
		{
			name: "prefer faster uncached latency",
			results: []*analysis.ServerResult{
				{
					ServerAddress:      "slower.server:53",
					UncachedLatencies:  []time.Duration{50 * time.Millisecond},
					AvgUncachedLatency: 50 * time.Millisecond,
					Reliability:        100.0,
				},
				{
					ServerAddress:      "faster.server:53",
					UncachedLatencies:  []time.Duration{20 * time.Millisecond},
					AvgUncachedLatency: 20 * time.Millisecond,
					Reliability:        100.0,
				},
			},
			cfg:            &config.Config{},
			wantServerAddr: "faster.server:53",
		},
		{
			name: "fallback to cached latency when uncached equal",
			results: []*analysis.ServerResult{
				{
					ServerAddress:      "slower-cached.server:53",
					CachedLatencies:    []time.Duration{30 * time.Millisecond},
					UncachedLatencies:  []time.Duration{20 * time.Millisecond},
					AvgCachedLatency:   30 * time.Millisecond,
					AvgUncachedLatency: 20 * time.Millisecond,
					Reliability:        100.0,
				},
				{
					ServerAddress:      "faster-cached.server:53",
					CachedLatencies:    []time.Duration{10 * time.Millisecond},
					UncachedLatencies:  []time.Duration{20 * time.Millisecond},
					AvgCachedLatency:   10 * time.Millisecond,
					AvgUncachedLatency: 20 * time.Millisecond,
					Reliability:        100.0,
				},
			},
			cfg:            &config.Config{},
			wantServerAddr: "faster-cached.server:53",
		},
		{
			name: "all unreliable returns nil",
			results: []*analysis.ServerResult{
				{
					ServerAddress: "unreliable1:53",
					Reliability:   50.0,
				},
				{
					ServerAddress: "unreliable2:53",
					Reliability:   80.0,
				},
			},
			cfg:            &config.Config{},
			wantServerAddr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findBestServer(tt.results, tt.cfg)
			if tt.wantServerAddr == "" {
				assert.Nil(t, result, "Expected no best server")
			} else {
				require.NotNil(t, result, "Expected a best server")
				assert.Equal(t, tt.wantServerAddr, result.ServerAddress)
			}
		})
	}
}

func TestCompareUncachedLatency(t *testing.T) {
	tests := []struct {
		name           string
		current        *analysis.ServerResult
		best           *analysis.ServerResult
		lowestUncached time.Duration
		want           bool
	}{
		{
			name: "current has uncached, best doesn't",
			current: &analysis.ServerResult{
				UncachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgUncachedLatency: 10 * time.Millisecond,
			},
			best: &analysis.ServerResult{
				UncachedLatencies: []time.Duration{},
			},
			lowestUncached: time.Duration(1<<63 - 1),
			want:           true,
		},
		{
			name: "best has uncached, current doesn't",
			current: &analysis.ServerResult{
				UncachedLatencies: []time.Duration{},
			},
			best: &analysis.ServerResult{
				UncachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgUncachedLatency: 10 * time.Millisecond,
			},
			lowestUncached: 10 * time.Millisecond,
			want:           false,
		},
		{
			name: "current faster than best",
			current: &analysis.ServerResult{
				UncachedLatencies:  []time.Duration{5 * time.Millisecond},
				AvgUncachedLatency: 5 * time.Millisecond,
			},
			best: &analysis.ServerResult{
				UncachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgUncachedLatency: 10 * time.Millisecond,
			},
			lowestUncached: 10 * time.Millisecond,
			want:           true,
		},
		{
			name: "current slower than best",
			current: &analysis.ServerResult{
				UncachedLatencies:  []time.Duration{15 * time.Millisecond},
				AvgUncachedLatency: 15 * time.Millisecond,
			},
			best: &analysis.ServerResult{
				UncachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgUncachedLatency: 10 * time.Millisecond,
			},
			lowestUncached: 10 * time.Millisecond,
			want:           false,
		},
		{
			name: "neither has uncached",
			current: &analysis.ServerResult{
				UncachedLatencies: []time.Duration{},
			},
			best: &analysis.ServerResult{
				UncachedLatencies: []time.Duration{},
			},
			lowestUncached: time.Duration(1<<63 - 1),
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareUncachedLatency(tt.current, tt.best, tt.lowestUncached)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCompareCachedLatency(t *testing.T) {
	tests := []struct {
		name    string
		current *analysis.ServerResult
		best    *analysis.ServerResult
		want    bool
	}{
		{
			name: "current has cached, best doesn't",
			current: &analysis.ServerResult{
				CachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgCachedLatency: 10 * time.Millisecond,
			},
			best: &analysis.ServerResult{
				CachedLatencies: []time.Duration{},
			},
			want: true,
		},
		{
			name: "best has cached, current doesn't",
			current: &analysis.ServerResult{
				CachedLatencies: []time.Duration{},
			},
			best: &analysis.ServerResult{
				CachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgCachedLatency: 10 * time.Millisecond,
			},
			want: false,
		},
		{
			name: "current faster cached",
			current: &analysis.ServerResult{
				CachedLatencies:  []time.Duration{5 * time.Millisecond},
				AvgCachedLatency: 5 * time.Millisecond,
			},
			best: &analysis.ServerResult{
				CachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgCachedLatency: 10 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "current slower cached",
			current: &analysis.ServerResult{
				CachedLatencies:  []time.Duration{15 * time.Millisecond},
				AvgCachedLatency: 15 * time.Millisecond,
			},
			best: &analysis.ServerResult{
				CachedLatencies:  []time.Duration{10 * time.Millisecond},
				AvgCachedLatency: 10 * time.Millisecond,
			},
			want: false,
		},
		{
			name: "neither has cached",
			current: &analysis.ServerResult{
				CachedLatencies: []time.Duration{},
			},
			best: &analysis.ServerResult{
				CachedLatencies: []time.Duration{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareCachedLatency(tt.current, tt.best)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPrintSummary(t *testing.T) {
	bTrue := true
	bFalse := false
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
					CachedLatencies:       []time.Duration{10 * time.Millisecond},
					UncachedLatencies:     []time.Duration{20 * time.Millisecond},
					AvgCachedLatency:      10 * time.Millisecond,
					AvgUncachedLatency:    20 * time.Millisecond,
					StdDevCachedLatency:   1 * time.Millisecond,
					StdDevUncachedLatency: 2 * time.Millisecond,
					Reliability:           100.0,
					DotcomLatency:         &dotcomLatency,
				}
				return res
			}(),
			cfg: &config.Config{CheckDotcom: true},
			wantContains: []string{
				"--- Conclusion ---",
				"Fastest reliable server",
				"1.1.1.1:53",
				"Avg Uncached Latency",
				"Avg Cached Latency",
				".com Latency",
				"Reliability: 100.0%",
			},
		},
		{
			name: "no reliable servers",
			results: func() *analysis.BenchmarkResults {
				res := analysis.NewBenchmarkResults()
				res.Results["unreliable:53"] = &analysis.ServerResult{
					ServerAddress: "unreliable:53",
					Reliability:   50.0,
				}
				return res
			}(),
			cfg: &config.Config{},
			wantContains: []string{
				"--- Conclusion ---",
				"Could not determine a best server",
			},
			wantAbsent: []string{
				"Fastest reliable server",
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
	// Use variables to avoid unused warnings
	_ = bTrue
	_ = bFalse
}

func TestPrintServerWarnings(t *testing.T) {
	bTrue := true
	bFalse := false

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
			name: "skip best server in warnings",
			results: []*analysis.ServerResult{
				{
					ServerAddress: "best:53",
					Reliability:   100.0,
				},
			},
			bestServer: &analysis.ServerResult{ServerAddress: "best:53"},
			cfg:        &config.Config{},
			wantAbsent: []string{
				"Warning (best:53)",
			},
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
