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

// Composite-score weights (modern-web bias): uncached dominates because the
// modern web assembles pages from many uncached third-party domains. When a
// metric has no data (dotcom is off by default), the present weights are
// renormalized to sum to 1, keeping the score magnitude comparable.
const (
	weightUncached = 0.50
	weightCached   = 0.25
	weightDotcom   = 0.25
)

// Holds benchmark results and metrics for a single DNS server.
type ServerResult struct {
	ServerAddress      string // Includes protocol prefix where applicable (e.g., tls://1.1.1.1:853)
	CachedLatencies    []time.Duration
	UncachedLatencies  []time.Duration
	Errors             int // Latency probes that failed before a structurally valid DNS response was received
	TotalQueries       int // Total number of latency queries attempted
	TimeoutErrors      int
	TransportErrors    int
	DNSFailures        int
	MalformedResponses int

	// Check Results (pointers allow nil state for unchecked/error)
	SupportsDNSSEC  *bool
	HijacksNXDOMAIN *bool
	BlocksRebinding *bool
	IsAccurate      *bool
	DotcomLatency   *time.Duration

	// Calculated Metrics
	AvgCachedLatency      time.Duration
	StdDevCachedLatency   time.Duration
	AvgUncachedLatency    time.Duration
	StdDevUncachedLatency time.Duration
	Reliability           float64 // Based on latency query success rate
	Score                 float64 // Composite performance score in ms (lower is better); +Inf if unrankable
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
	// Calculate overall Reliability based on latency queries.
	// sr.Errors is already accumulated by processLatencyResult; don't overwrite it.
	totalLatencyQueriesAttempted := sr.TotalQueries
	successfulLatencyQueries := len(sr.CachedLatencies) + len(sr.UncachedLatencies)
	if totalLatencyQueriesAttempted > 0 {
		sr.Reliability = (float64(successfulLatencyQueries) / float64(totalLatencyQueriesAttempted)) * 100.0
	} else {
		sr.Reliability = 0.0
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

	// Composite performance score (depends on the averages computed above).
	sr.Score = computeScore(sr)
}

// calculateAverage computes the average duration from a slice of time.Duration values.
// It returns a zero duration if the input slice is empty.
func calculateAverage(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	var totalLatency time.Duration
	for _, l := range latencies {
		totalLatency += l
	}
	avgNano := float64(totalLatency.Nanoseconds()) / float64(len(latencies))
	return time.Duration(math.Round(avgNano))
}

// calculateStdDev computes the standard deviation of durations in a slice.
// It requires at least two data points to calculate a meaningful standard deviation,
// returning a zero duration if the slice has fewer than 2 elements.
// It uses the sample standard deviation formula (dividing by n-1).
func calculateStdDev(latencies []time.Duration, average time.Duration) time.Duration {
	if len(latencies) < 2 {
		return 0
	} // StdDev requires at least 2 points

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

// durationMs converts a duration to milliseconds as a float. It divides
// microseconds rather than calling d.Milliseconds(), which would truncate
// sub-millisecond latencies to zero.
func durationMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// computeScore returns the composite performance score in milliseconds (lower
// is better). It blends the present latency metrics with modern-web weights,
// renormalizing over whichever metrics have data, then divides by the effective
// reliability (probe success rate minus the wrong-rcode DNS-failure rate).
// It returns math.Inf(1) when the server cannot be ranked: no latency samples,
// no queries attempted, or zero effective reliability.
func computeScore(sr *ServerResult) float64 {
	var weightedSum, weightTotal float64
	if len(sr.UncachedLatencies) > 0 {
		weightedSum += weightUncached * durationMs(sr.AvgUncachedLatency)
		weightTotal += weightUncached
	}
	if len(sr.CachedLatencies) > 0 {
		weightedSum += weightCached * durationMs(sr.AvgCachedLatency)
		weightTotal += weightCached
	}
	if sr.DotcomLatency != nil {
		weightedSum += weightDotcom * durationMs(*sr.DotcomLatency)
		weightTotal += weightDotcom
	}
	if weightTotal == 0 {
		return math.Inf(1) // no latency data to rank on
	}
	base := weightedSum / weightTotal

	if sr.TotalQueries <= 0 {
		return math.Inf(1)
	}
	successful := len(sr.CachedLatencies) + len(sr.UncachedLatencies)
	usable := successful - sr.DNSFailures
	if usable < 0 {
		usable = 0
	}
	effRel := float64(usable) / float64(sr.TotalQueries)
	if effRel <= 0 {
		return math.Inf(1)
	}
	return base / effRel
}

// Analyze computes metrics for all server results within BenchmarkResults.
func (br *BenchmarkResults) Analyze() {
	for _, serverResult := range br.Results {
		serverResult.CalculateMetrics()
	}
}
