package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/config"
)

// Formats and prints benchmark results to the console.
// PrintConsoleResults formats and prints the benchmark results to the given writer.
func PrintConsoleResults(writer io.Writer, results *analysis.BenchmarkResults, cfg *config.Config) {
	serverResults := getServerResultsSlice(results)
	sortServerResults(serverResults)

	w := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)

	header := buildHeader(cfg)
	_, _ = fmt.Fprintln(w, strings.Join(header, "\t"))
	_, _ = fmt.Fprintln(w, strings.Repeat("-\t", len(header)))

	for _, res := range serverResults {
		row := buildRow(res, cfg)
		_, _ = fmt.Fprintln(w, strings.Join(row, "\t"))
	}

	_ = w.Flush()

	if writer == os.Stdout {
		printSummary(writer, serverResults, cfg)
	}
}

// WriteCSVResults formats and writes the benchmark results to the given writer in CSV format.
func WriteCSVResults(writer io.Writer, results *analysis.BenchmarkResults, cfg *config.Config) error {
	serverResults := getServerResultsSlice(results)
	sortServerResults(serverResults)

	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	header := buildCSVHeader(cfg)
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, res := range serverResults {
		row := buildCSVRow(res, cfg)
		if err := csvWriter.Write(row); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to write CSV row for server %s: %v\n", res.ServerAddress, err)
		}
	}
	return csvWriter.Error()
}

// WriteJSONResults formats and writes the benchmark results to the given writer in JSON format.
func WriteJSONResults(writer io.Writer, results *analysis.BenchmarkResults, cfg *config.Config) error {
	serverResults := getServerResultsSlice(results)
	sortServerResults(serverResults)

	outputResults := make([]JSONServerResult, 0, len(serverResults))
	for _, res := range serverResults {
		outputResults = append(outputResults, buildJSONResult(res, cfg))
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ") // Pretty print
	if err := encoder.Encode(outputResults); err != nil {
		return fmt.Errorf("failed to encode JSON results: %w", err)
	}
	return nil
}

// --- Helper Functions ---

// getServerResultsSlice extracts the ServerResult slice from the BenchmarkResults map.
// It converts the map of server results into a slice for easier iteration and sorting.
func getServerResultsSlice(results *analysis.BenchmarkResults) []*analysis.ServerResult {
	slice := make([]*analysis.ServerResult, 0, len(results.Results))
	for _, res := range results.Results {
		slice = append(slice, res)
	}
	return slice
}

// sortServerResults sorts results by composite Score ascending (lower is
// better). Unrankable servers (+Inf) sort last; ties break by ServerAddress for
// deterministic output.
func sortServerResults(results []*analysis.ServerResult) {
	sort.SliceStable(results, func(i, j int) bool {
		si, sj := results[i].Score, results[j].Score
		if si != sj {
			return si < sj
		}
		return results[i].ServerAddress < results[j].ServerAddress
	})
}

// buildHeader constructs the header row for console output.
// It includes columns for server address, latency metrics, reliability, and optional checks.
func buildHeader(cfg *config.Config) []string {
	header := []string{"DNS Server", "Protocol", "Avg Cached", "StdDev Cached", "Avg Uncached", "StdDev Uncached", "Score", "Reliability"}
	if cfg.CheckDotcom {
		header = append(header, ".com Latency")
	}
	if cfg.CheckDNSSEC {
		header = append(header, "DNSSEC")
	}
	if cfg.CheckNXDOMAIN {
		header = append(header, "NXDOMAIN Policy")
	}
	if cfg.CheckRebinding {
		header = append(header, "Rebind Protect")
	}
	if cfg.AccuracyCheckFile != "" {
		header = append(header, "Accuracy")
	}
	return header
}

// buildRow constructs a data row for console output for a single server result.
// It formats the ServerResult data into a string slice based on the configured checks.
func buildRow(res *analysis.ServerResult, cfg *config.Config) []string {
	row := []string{
		res.ServerAddress,
		res.Protocol,
		formatLatency(res.AvgCachedLatency, len(res.CachedLatencies) > 0),
		formatStdDev(res.StdDevCachedLatency, len(res.CachedLatencies) > 1),
		formatLatency(res.AvgUncachedLatency, len(res.UncachedLatencies) > 0),
		formatStdDev(res.StdDevUncachedLatency, len(res.UncachedLatencies) > 1),
		formatScore(res.Score),
		fmt.Sprintf("%.1f%%", res.Reliability),
	}
	if cfg.CheckDotcom {
		row = append(row, formatDurationPointer(res.DotcomLatency))
	}
	if cfg.CheckDNSSEC {
		row = append(row, formatBoolPointer(res.SupportsDNSSEC, "Yes", "No", "N/A"))
	}
	if cfg.CheckNXDOMAIN {
		row = append(row, formatBoolPointer(res.HijacksNXDOMAIN, "Hijacks", "No Hijack", "N/A"))
	}
	if cfg.CheckRebinding {
		row = append(row, formatBoolPointer(res.BlocksRebinding, "Blocks", "Allows", "N/A"))
	}
	if cfg.AccuracyCheckFile != "" {
		row = append(row, formatBoolPointer(res.IsAccurate, "Accurate", "Mismatch", "N/A"))
	}
	return row
}

// buildCSVHeader constructs the header row for CSV output.
// It includes all possible fields for benchmark results in CSV format.
func buildCSVHeader(cfg *config.Config) []string {
	header := []string{
		"ServerAddress",
		"Protocol",
		"AvgCachedLatency(ms)", "StdDevCachedLatency(ms)",
		"AvgUncachedLatency(ms)", "StdDevUncachedLatency(ms)",
		"Score(ms)",
		"Reliability(%)",
		"SuccessfulCachedQueries", "SuccessfulUncachedQueries",
		"FailedLatencyQueries", "TimeoutErrors", "TransportErrors", "DNSFailures", "MalformedResponses", "TotalLatencyQueries",
	}
	if cfg.CheckDotcom {
		header = append(header, "DotcomLatency(ms)")
	}
	if cfg.CheckDNSSEC {
		header = append(header, "SupportsDNSSEC")
	}
	if cfg.CheckNXDOMAIN {
		header = append(header, "HijacksNXDOMAIN")
	}
	if cfg.CheckRebinding {
		header = append(header, "BlocksRebinding")
	}
	if cfg.AccuracyCheckFile != "" {
		header = append(header, "IsAccurate")
	}
	return header
}

// buildCSVRow constructs a data row for CSV output for a single server result.
// It formats the ServerResult data into a string slice for CSV, including all relevant fields.
func buildCSVRow(res *analysis.ServerResult, cfg *config.Config) []string {
	row := []string{
		res.ServerAddress,
		res.Protocol,
		formatMillisFloat(res.AvgCachedLatency, len(res.CachedLatencies) > 0),
		formatMillisFloat(res.StdDevCachedLatency, len(res.CachedLatencies) > 1),
		formatMillisFloat(res.AvgUncachedLatency, len(res.UncachedLatencies) > 0),
		formatMillisFloat(res.StdDevUncachedLatency, len(res.UncachedLatencies) > 1),
		formatScoreCSV(res.Score),
		fmt.Sprintf("%.1f", res.Reliability),
		strconv.Itoa(len(res.CachedLatencies)),
		strconv.Itoa(len(res.UncachedLatencies)),
		strconv.Itoa(res.Errors),
		strconv.Itoa(res.TimeoutErrors),
		strconv.Itoa(res.TransportErrors),
		strconv.Itoa(res.DNSFailures),
		strconv.Itoa(res.MalformedResponses),
		strconv.Itoa(res.TotalQueries),
	}
	if cfg.CheckDotcom {
		row = append(row, formatMillisFloatPointer(res.DotcomLatency))
	}
	if cfg.CheckDNSSEC {
		row = append(row, formatBoolPointerCSV(res.SupportsDNSSEC))
	}
	if cfg.CheckNXDOMAIN {
		row = append(row, formatBoolPointerCSV(res.HijacksNXDOMAIN))
	}
	if cfg.CheckRebinding {
		row = append(row, formatBoolPointerCSV(res.BlocksRebinding))
	}
	if cfg.AccuracyCheckFile != "" {
		row = append(row, formatBoolPointerCSV(res.IsAccurate))
	}
	return row
}

// JSONServerResult defines the structure for JSON output.
// It specifies how ServerResult data is serialized into JSON format.
type JSONServerResult struct {
	ServerAddress             string   `json:"serverAddress"`
	Protocol                  string   `json:"protocol"`
	AvgCachedLatencyMs        *float64 `json:"avgCachedLatencyMs,omitempty"`
	StdDevCachedLatencyMs     *float64 `json:"stdDevCachedLatencyMs,omitempty"`
	AvgUncachedLatencyMs      *float64 `json:"avgUncachedLatencyMs,omitempty"`
	StdDevUncachedLatencyMs   *float64 `json:"stdDevUncachedLatencyMs,omitempty"`
	DotcomLatencyMs           *float64 `json:"dotcomLatencyMs,omitempty"`
	ReliabilityPct            float64  `json:"reliabilityPct"`
	Score                     *float64 `json:"score"`
	SuccessfulCachedQueries   int      `json:"successfulCachedQueries"`
	SuccessfulUncachedQueries int      `json:"successfulUncachedQueries"`
	FailedLatencyQueries      int      `json:"failedLatencyQueries"`
	Errors                    int      `json:"errors"` // Deprecated alias for compatibility
	TimeoutErrors             int      `json:"timeoutErrors"`
	TransportErrors           int      `json:"transportErrors"`
	DNSFailures               int      `json:"dnsFailures"`
	MalformedResponses        int      `json:"malformedResponses"`
	TotalLatencyQueries       int      `json:"totalLatencyQueries"`
	SupportsDNSSEC            *bool    `json:"supportsDnssec,omitempty"`
	HijacksNXDOMAIN           *bool    `json:"hijacksNxdomain,omitempty"`
	BlocksRebinding           *bool    `json:"blocksRebinding,omitempty"`
	IsAccurate                *bool    `json:"isAccurate,omitempty"`
}

// buildJSONResult transforms a ServerResult into a JSONServerResult.
// It prepares the data for JSON output, converting relevant fields to the JSONServerResult structure.
func buildJSONResult(res *analysis.ServerResult, cfg *config.Config) JSONServerResult {
	jsonRes := JSONServerResult{
		ServerAddress:             res.ServerAddress,
		Protocol:                  res.Protocol,
		ReliabilityPct:            res.Reliability,
		SuccessfulCachedQueries:   len(res.CachedLatencies),
		SuccessfulUncachedQueries: len(res.UncachedLatencies),
		FailedLatencyQueries:      res.Errors,
		Errors:                    res.Errors,
		TimeoutErrors:             res.TimeoutErrors,
		TransportErrors:           res.TransportErrors,
		DNSFailures:               res.DNSFailures,
		MalformedResponses:        res.MalformedResponses,
		TotalLatencyQueries:       res.TotalQueries,
		SupportsDNSSEC:            res.SupportsDNSSEC,
		HijacksNXDOMAIN:           res.HijacksNXDOMAIN,
		BlocksRebinding:           res.BlocksRebinding,
		IsAccurate:                res.IsAccurate,
	}
	if len(res.CachedLatencies) > 0 {
		avgMs := float64(res.AvgCachedLatency.Microseconds()) / 1000.0
		jsonRes.AvgCachedLatencyMs = &avgMs
	}
	if len(res.CachedLatencies) > 1 {
		stdDevMs := float64(res.StdDevCachedLatency.Microseconds()) / 1000.0
		jsonRes.StdDevCachedLatencyMs = &stdDevMs
	}
	if len(res.UncachedLatencies) > 0 {
		avgMs := float64(res.AvgUncachedLatency.Microseconds()) / 1000.0
		jsonRes.AvgUncachedLatencyMs = &avgMs
	}
	if len(res.UncachedLatencies) > 1 {
		stdDevMs := float64(res.StdDevUncachedLatency.Microseconds()) / 1000.0
		jsonRes.StdDevUncachedLatencyMs = &stdDevMs
	}
	if res.DotcomLatency != nil {
		dotcomMs := float64(res.DotcomLatency.Microseconds()) / 1000.0
		jsonRes.DotcomLatencyMs = &dotcomMs
	}
	if !math.IsInf(res.Score, 1) {
		score := res.Score
		jsonRes.Score = &score
	}
	return jsonRes
}

// printSummary adds a concluding recommendation based on the results.
func printSummary(writer io.Writer, results []*analysis.ServerResult, cfg *config.Config) {
	if len(results) == 0 {
		return
	}

	_, _ = fmt.Fprintln(writer, "\n--- Conclusion ---")

	bestServer := findBestServer(results, cfg)

	// Report best server results
	if bestServer != nil {
		if bestServer.Protocol != "" {
			_, _ = fmt.Fprintf(writer, "Recommended server: %s using %s protocol\n", bestServer.ServerAddress, bestServer.Protocol)
		} else {
			_, _ = fmt.Fprintf(writer, "Recommended server: %s\n", bestServer.ServerAddress)
		}
		_, _ = fmt.Fprintf(writer, "  Composite Score:      %s\n", formatScore(bestServer.Score))
		_, _ = fmt.Fprintf(writer, "  Avg Uncached Latency: %s (StdDev: %s)\n",
			formatLatency(bestServer.AvgUncachedLatency, len(bestServer.UncachedLatencies) > 0),
			formatStdDev(bestServer.StdDevUncachedLatency, len(bestServer.UncachedLatencies) > 1))
		_, _ = fmt.Fprintf(writer, "  Avg Cached Latency:   %s (StdDev: %s)\n",
			formatLatency(bestServer.AvgCachedLatency, len(bestServer.CachedLatencies) > 0),
			formatStdDev(bestServer.StdDevCachedLatency, len(bestServer.CachedLatencies) > 1))
		if cfg.CheckDotcom && bestServer.DotcomLatency != nil {
			_, _ = fmt.Fprintf(writer, "  .com Latency:         %s\n", formatDurationPointer(bestServer.DotcomLatency))
		}
		_, _ = fmt.Fprintf(writer, "  Reliability: %.1f%%\n", bestServer.Reliability)
	} else {
		_, _ = fmt.Fprintln(writer, "Could not determine a recommended server with a rankable composite score.")
		// TODO: Optionally report the most reliable server regardless of other criteria if no 'best' is found.
	}

	// Report warnings for other servers
	printServerWarnings(writer, results, bestServer, cfg)

	_, _ = fmt.Fprintln(writer, "Note: Results are based on a snapshot in time and your current network conditions.")
}

// findBestServer returns the recommended server: the accuracy-eligible server
// with the lowest composite Score. Reliability and DNS-failure rate are already
// folded into Score, so the only hard gate here is accuracy (applied when
// -accuracy-file is set). Unrankable servers (+Inf score) are skipped.
// Returns nil if no eligible server exists.
func findBestServer(results []*analysis.ServerResult, cfg *config.Config) *analysis.ServerResult {
	var bestServer *analysis.ServerResult
	for _, res := range results {
		if cfg.AccuracyCheckFile != "" && (res.IsAccurate == nil || !*res.IsAccurate) {
			continue // accuracy gate: skip inaccurate/inconclusive
		}
		if math.IsInf(res.Score, 1) {
			continue // unrankable
		}
		if bestServer == nil || res.Score < bestServer.Score {
			bestServer = res
		}
	}
	return bestServer
}

func printServerWarnings(writer io.Writer, results []*analysis.ServerResult, bestServer *analysis.ServerResult, cfg *config.Config) {
	const reliabilityThreshold = 99.0
	issuesFound := false
	for _, res := range results {
		if bestServer != nil && res.ServerAddress == bestServer.ServerAddress {
			continue
		}

		warningPrefix := fmt.Sprintf("Warning (%s):", res.ServerAddress)
		serverIssues := false
		if res.Reliability < reliabilityThreshold {
			_, _ = fmt.Fprintf(writer, "%s Low reliability (%.1f%%).\n", warningPrefix, res.Reliability)
			serverIssues = true
		}
		if res.DNSFailures > 0 {
			_, _ = fmt.Fprintf(writer, "%s Returned %d unexpected DNS failure responses during latency probes.\n", warningPrefix, res.DNSFailures)
			serverIssues = true
		}
		if cfg.CheckNXDOMAIN && res.HijacksNXDOMAIN != nil && *res.HijacksNXDOMAIN {
			_, _ = fmt.Fprintf(writer, "%s Appears to hijack NXDOMAIN responses.\n", warningPrefix)
			serverIssues = true
		}
		if cfg.CheckRebinding && res.BlocksRebinding != nil && !*res.BlocksRebinding {
			_, _ = fmt.Fprintf(writer, "%s Allows responses with private IPs (rebinding risk).\n", warningPrefix)
			serverIssues = true
		}
		if cfg.AccuracyCheckFile != "" && res.IsAccurate != nil && !*res.IsAccurate {
			_, _ = fmt.Fprintf(writer, "%s Returned inaccurate results for %s.\n", warningPrefix, cfg.AccuracyCheckDomain)
			serverIssues = true
		}
		if cfg.AccuracyCheckFile != "" && res.IsAccurate == nil {
			_, _ = fmt.Fprintf(writer, "%s Accuracy check for %s was inconclusive.\n", warningPrefix, cfg.AccuracyCheckDomain)
			serverIssues = true
		}
		if serverIssues {
			issuesFound = true
		}
	}

	if !issuesFound && bestServer != nil {
		_, _ = fmt.Fprintln(writer, "Other tested servers performed reliably without major issues detected.")
	}
}

// --- Formatting Helpers ---

// formatLatency formats a latency duration for console output.
// It returns "N/A" if there were no successful queries, or the latency in milliseconds with one decimal place.
func formatLatency(latency time.Duration, hasSuccess bool) string {
	if !hasSuccess {
		return "N/A"
	}
	return fmt.Sprintf("%.1f ms", float64(latency.Microseconds())/1000.0)
}

// formatStdDev formats a standard deviation duration for console output.
// It returns "N/A" if there's not enough data (less than 2 data points), or the std dev in milliseconds.
func formatStdDev(stdDev time.Duration, hasEnoughData bool) string {
	if !hasEnoughData {
		return "N/A"
	}
	return fmt.Sprintf("%.1f ms", float64(stdDev.Microseconds())/1000.0)
}

// formatScoreCSV formats a composite score for CSV output.
// It returns an empty cell for an unrankable (+Inf) score, otherwise the score
// in milliseconds with three decimal places.
func formatScoreCSV(score float64) string {
	if math.IsInf(score, 1) {
		return ""
	}
	return fmt.Sprintf("%.3f", score)
}

// formatScore formats a composite score for console output.
// It returns "N/A" for an unrankable (+Inf) score, otherwise the score in
// milliseconds with one decimal place.
func formatScore(score float64) string {
	if math.IsInf(score, 1) {
		return "N/A"
	}
	return fmt.Sprintf("%.1f ms", score)
}

// formatDurationPointer formats a duration pointer for console output.
// It handles nil pointers by returning "N/A", otherwise formats the duration in milliseconds.
func formatDurationPointer(d *time.Duration) string {
	if d == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000.0)
}

// formatBoolPointer formats a boolean pointer for console output.
// It returns trueStr, falseStr, or nilStr based on the boolean pointer's value or nil-ness.
func formatBoolPointer(val *bool, trueStr, falseStr, nilStr string) string {
	if val == nil {
		return nilStr
	}
	if *val {
		return trueStr
	}
	return falseStr
}

// formatMillisFloat formats a duration to milliseconds as a float string for CSV.
// It returns "N/A" if not applicable, otherwise milliseconds with 3 decimal places.
func formatMillisFloat(d time.Duration, applicable bool) string {
	if !applicable { // Allow 0.000 ms if applicable
		return "N/A"
	}
	return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000.0)
}

// formatMillisFloatPointer formats a duration pointer to milliseconds as a float string for CSV.
// It handles nil duration pointers by returning "N/A", otherwise formats to milliseconds.
func formatMillisFloatPointer(d *time.Duration) string {
	if d == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000.0)
}

// formatBoolPointerCSV formats a boolean pointer for CSV output.
// It returns "N/A" for nil, and "true" or "false" strings for boolean values.
func formatBoolPointerCSV(val *bool) string {
	if val == nil {
		return "N/A"
	}
	return strconv.FormatBool(*val)
}
