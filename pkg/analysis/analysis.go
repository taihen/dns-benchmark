package analysis

import (
	"math"
	"time"
)

// QueryType indicates the type of benchmark query (cached or uncached).
type QueryType int

const (
	Cached QueryType = iota
	Uncached
)

// String representation for QueryType.
func (qt QueryType) String() string {
	if qt == Cached {
		return "Cached"
	}
	return "Uncached"
}

// ServerResult holds the benchmark results and calculated metrics for a single DNS server.
type ServerResult struct {
	ServerAddress     string          // Includes protocol prefix where applicable (e.g., tls://1.1.1.1:853)
	CachedLatencies   []time.Duration
	UncachedLatencies []time.Duration
	Errors            int // Count of errors during latency queries
	TotalQueries      int // Total number of latency queries attempted

	// Check Results (pointers allow nil state for unchecked/error)
	SupportsDNSSEC    *bool
	HijacksNXDOMAIN   *bool
	BlocksRebinding   *bool
	IsAccurate        *bool
	DotcomLatency     *time.Duration

	// Calculated Metrics
	AvgCachedLatency      time.Duration
	StdDevCachedLatency   time.Duration
	AvgUncachedLatency    time.Duration
	StdDevUncachedLatency time.Duration
	Reliability           float64 // Based on latency query success rate
	// TODO: Add fields for min/max latency if desired.
	// TODO: Consider separate error counts per check type (DNSSEC, NXDOMAIN etc.) for more granular reporting.
}

// BenchmarkResults holds the results for all tested servers.
type BenchmarkResults struct {
	Results map[string]*ServerResult // Map key is ServerResult.ServerAddress
	// TODO: Add overall benchmark metadata (e.g., start/end time, total errors across all types).
}

// NewBenchmarkResults creates an initialized BenchmarkResults map.
func NewBenchmarkResults() *BenchmarkResults {
	return &BenchmarkResults{
		Results: make(map[string]*ServerResult),
	}
}

// CalculateMetrics computes derived metrics for a ServerResult.
func (sr *ServerResult) CalculateMetrics() {
	// Calculate overall Reliability based on latency queries
	totalLatencyQueriesAttempted := sr.TotalQueries
	successfulLatencyQueries := len(sr.CachedLatencies) + len(sr.UncachedLatencies)
	failedLatencyQueries := totalLatencyQueriesAttempted - successfulLatencyQueries
	if totalLatencyQueriesAttempted > 0 {
		sr.Reliability = (float64(successfulLatencyQueries) / float64(totalLatencyQueriesAttempted)) * 100.0
		sr.Errors = failedLatencyQueries // Store latency-specific errors
	} else {
		sr.Reliability = 0.0
		sr.Errors = 0
	}

	// Calculate Cached Latency Metrics
	if len(sr.CachedLatencies) > 0 {
		sr.AvgCachedLatency = calculateAverage(sr.CachedLatencies)
		sr.StdDevCachedLatency = calculateStdDev(sr.CachedLatencies, sr.AvgCachedLatency)
	} else {
		sr.AvgCachedLatency = 0
		sr.StdDevCachedLatency = 0
	}

	// Calculate Uncached Latency Metrics
	if len(sr.UncachedLatencies) > 0 {
		sr.AvgUncachedLatency = calculateAverage(sr.UncachedLatencies)
		sr.StdDevUncachedLatency = calculateStdDev(sr.UncachedLatencies, sr.AvgUncachedLatency)
	} else {
		sr.AvgUncachedLatency = 0
		sr.StdDevUncachedLatency = 0
	}
}

// calculateAverage computes the average for a slice of durations.
func calculateAverage(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 { return 0 }
	var totalLatency time.Duration
	for _, l := range latencies { totalLatency += l }
	avgNano := float64(totalLatency.Nanoseconds()) / float64(len(latencies))
	return time.Duration(math.Round(avgNano))
}

// calculateStdDev computes the standard deviation for a slice of durations.
func calculateStdDev(latencies []time.Duration, average time.Duration) time.Duration {
	if len(latencies) < 2 { return 0 } // StdDev requires at least 2 points

	avgNano := float64(average.Nanoseconds())
	var sumOfSquares float64
	for _, l := range latencies {
		diff := float64(l.Nanoseconds()) - avgNano
		sumOfSquares += diff * diff
	}
	// Use sample standard deviation (n-1 denominator)
	variance := sumOfSquares / float64(len(latencies)-1)
	stdDevNano := math.Sqrt(variance)
	return time.Duration(math.Round(stdDevNano))
}

// Analyze computes metrics for all server results within BenchmarkResults.
func (br *BenchmarkResults) Analyze() {
	for _, serverResult := range br.Results {
		serverResult.CalculateMetrics()
	}
	// TODO: Add logic to sort results here instead of in output package?
	// TODO: Implement comparative analysis (e.g., statistical significance tests).
}
