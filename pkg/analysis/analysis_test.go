package analysis

import (
	"math"
	"testing"
	"time"
)

func TestCalculateAverage(t *testing.T) {
	tests := []struct {
		name      string
		latencies []time.Duration
		want      time.Duration
	}{
		{"empty slice", []time.Duration{}, 0},
		{"single element", []time.Duration{100 * time.Millisecond}, 100 * time.Millisecond},
		{"multiple elements", []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond}, 200 * time.Millisecond},
		{"zero duration", []time.Duration{0, 100 * time.Millisecond}, 50 * time.Millisecond},
		{"large durations", []time.Duration{time.Second, 2 * time.Second}, 1500 * time.Millisecond},
		{"mixed durations", []time.Duration{50 * time.Millisecond, 150 * time.Millisecond, 1 * time.Second}, 400 * time.Millisecond}, // (50+150+1000)/3 = 400
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateAverage(tt.latencies); got != tt.want {
				t.Errorf("calculateAverage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateStdDev(t *testing.T) {
	tests := []struct {
		name      string
		latencies []time.Duration
		average   time.Duration // Pre-calculated average for simplicity
		want      time.Duration // Expected standard deviation
	}{
		{"empty slice", []time.Duration{}, 0, 0},
		{"single element", []time.Duration{100 * time.Millisecond}, 100 * time.Millisecond, 0}, // StdDev undefined for n=1
		{"two identical elements", []time.Duration{100 * time.Millisecond, 100 * time.Millisecond}, 100 * time.Millisecond, 0},
		{"two different elements", []time.Duration{100 * time.Millisecond, 300 * time.Millisecond}, 200 * time.Millisecond, time.Duration(math.Round(math.Sqrt(float64(100*100*1e6*1e6*2) / 1.0)))},                 // sqrt(((100-200)^2 + (300-200)^2) / (2-1)) = sqrt(10000+10000) = sqrt(20000) = 141.42... ms
		{"three elements", []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond}, 200 * time.Millisecond, time.Duration(math.Round(math.Sqrt(float64(100*100*1e6*1e6*2) / 2.0)))}, // sqrt(((100-200)^2 + (200-200)^2 + (300-200)^2) / (3-1)) = sqrt((10000+0+10000)/2) = sqrt(10000) = 100 ms
		{"zero durations", []time.Duration{0, 0, 0}, 0, 0},
	}

	// Helper to compare durations within a small tolerance due to float rounding
	tolerance := time.Nanosecond

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateStdDev(tt.latencies, tt.average)
			diff := got - tt.want
			if diff < -tolerance || diff > tolerance {
				t.Errorf("calculateStdDev() = %v, want %v (difference: %v)", got, tt.want, diff)
			}
		})
	}
}

func TestServerResult_CalculateMetrics(t *testing.T) {
	tests := []struct {
		name                   string
		inputResult            *ServerResult
		expectedAvgCached      time.Duration
		expectedStdDevCached   time.Duration
		expectedAvgUncached    time.Duration
		expectedStdDevUncached time.Duration
		expectedReliability    float64
		expectedErrors         int
	}{
		{
			name: "no queries",
			inputResult: &ServerResult{
				TotalQueries: 0,
			},
			expectedAvgCached:      0,
			expectedStdDevCached:   0,
			expectedAvgUncached:    0,
			expectedStdDevUncached: 0,
			expectedReliability:    0.0,
			expectedErrors:         0,
		},
		{
			name: "all successful cached",
			inputResult: &ServerResult{
				TotalQueries:      3,
				CachedLatencies:   []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond},
				UncachedLatencies: []time.Duration{},
			},
			expectedAvgCached:      200 * time.Millisecond,
			expectedStdDevCached:   time.Duration(math.Round(math.Sqrt(float64(100*100*1e6*1e6*2) / 2.0))), // 100ms
			expectedAvgUncached:    0,
			expectedStdDevUncached: 0,
			expectedReliability:    100.0,
			expectedErrors:         0,
		},
		{
			name: "all successful uncached",
			inputResult: &ServerResult{
				TotalQueries:      2,
				CachedLatencies:   []time.Duration{},
				UncachedLatencies: []time.Duration{100 * time.Millisecond, 300 * time.Millisecond},
			},
			expectedAvgCached:      0,
			expectedStdDevCached:   0,
			expectedAvgUncached:    200 * time.Millisecond,
			expectedStdDevUncached: time.Duration(math.Round(math.Sqrt(float64(100*100*1e6*1e6*2) / 1.0))), // 141ms
			expectedReliability:    100.0,
			expectedErrors:         0,
		},
		{
			name: "mixed successful",
			inputResult: &ServerResult{
				TotalQueries:      4,
				CachedLatencies:   []time.Duration{50 * time.Millisecond},
				UncachedLatencies: []time.Duration{150 * time.Millisecond, 250 * time.Millisecond},
				// Implicitly 1 error
			},
			expectedAvgCached:      50 * time.Millisecond,
			expectedStdDevCached:   0, // n=1
			expectedAvgUncached:    200 * time.Millisecond,
			expectedStdDevUncached: time.Duration(math.Round(math.Sqrt(float64(50*50*1e6*1e6*2) / 1.0))), // 71ms
			expectedReliability:    75.0,                                                                 // 3 successes / 4 attempts
			expectedErrors:         1,
		},
		{
			name: "all errors",
			inputResult: &ServerResult{
				TotalQueries:      5,
				CachedLatencies:   []time.Duration{},
				UncachedLatencies: []time.Duration{},
			},
			expectedAvgCached:      0,
			expectedStdDevCached:   0,
			expectedAvgUncached:    0,
			expectedStdDevUncached: 0,
			expectedReliability:    0.0,
			expectedErrors:         5,
		},
	}

	tolerance := time.Nanosecond

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.inputResult.CalculateMetrics()

			// Check Avg Cached
			diffAvgCached := tt.inputResult.AvgCachedLatency - tt.expectedAvgCached
			if diffAvgCached < -tolerance || diffAvgCached > tolerance {
				t.Errorf("CalculateMetrics() AvgCachedLatency = %v, want %v", tt.inputResult.AvgCachedLatency, tt.expectedAvgCached)
			}
			// Check StdDev Cached
			diffStdDevCached := tt.inputResult.StdDevCachedLatency - tt.expectedStdDevCached
			if diffStdDevCached < -tolerance || diffStdDevCached > tolerance {
				t.Errorf("CalculateMetrics() StdDevCachedLatency = %v, want %v", tt.inputResult.StdDevCachedLatency, tt.expectedStdDevCached)
			}
			// Check Avg Uncached
			diffAvgUncached := tt.inputResult.AvgUncachedLatency - tt.expectedAvgUncached
			if diffAvgUncached < -tolerance || diffAvgUncached > tolerance {
				t.Errorf("CalculateMetrics() AvgUncachedLatency = %v, want %v", tt.inputResult.AvgUncachedLatency, tt.expectedAvgUncached)
			}
			// Check StdDev Uncached
			diffStdDevUncached := tt.inputResult.StdDevUncachedLatency - tt.expectedStdDevUncached
			if diffStdDevUncached < -tolerance || diffStdDevUncached > tolerance {
				t.Errorf("CalculateMetrics() StdDevUncachedLatency = %v, want %v", tt.inputResult.StdDevUncachedLatency, tt.expectedStdDevUncached)
			}
			// Check Reliability
			if math.Abs(tt.inputResult.Reliability-tt.expectedReliability) > 0.01 { // Tolerance for float comparison
				t.Errorf("CalculateMetrics() Reliability = %v, want %v", tt.inputResult.Reliability, tt.expectedReliability)
			}
			// Check Errors
			if tt.inputResult.Errors != tt.expectedErrors {
				t.Errorf("CalculateMetrics() Errors = %v, want %v", tt.inputResult.Errors, tt.expectedErrors)
			}
		})
	}
}

func TestQueryTypeString(t *testing.T) {
	tests := []struct {
		input QueryType
		want  string
	}{
		{Cached, "Cached"},
		{Uncached, "Uncached"},
		{QueryType(99), "Uncached"}, // Test default case
	}
	for _, tt := range tests {
		if got := tt.input.String(); got != tt.want {
			t.Errorf("QueryType(%d).String() = %q, want %q", tt.input, got, tt.want)
		}
	}
}
