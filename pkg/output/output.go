package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/catalog"
	"github.com/taihen/dns-benchmark/pkg/config"
)

// errWriter remembers the first write error so that console output, which is
// written through many Fprintf calls, can report a failure once at the end.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// PrintConsoleResults formats and prints the benchmark results to the given
// writer. It returns the first write error, so a full disk or failed file
// system does not silently produce a truncated report.
func PrintConsoleResults(writer io.Writer, results *analysis.BenchmarkResults, cfg *config.Config) error {
	serverResults := getServerResultsSlice(results)
	sortServerResults(serverResults)

	out := &errWriter{w: writer}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)

	if version := catalogVersion(results); version != "" {
		_, _ = fmt.Fprintf(out, "Catalogue: %s; corpus: %s\n", version, results.Metadata.CorpusID)
	}
	header := buildHeader(cfg)
	_, _ = fmt.Fprintln(w, strings.Join(header, "\t"))
	_, _ = fmt.Fprintln(w, strings.Repeat("-\t", len(header)))

	for _, res := range serverResults {
		row := buildRow(res, cfg)
		_, _ = fmt.Fprintln(w, strings.Join(row, "\t"))
	}

	if err := w.Flush(); err != nil {
		return err
	}

	// The summary carries the recommendation and the inconclusive/excluded
	// warnings, so it is written wherever the table goes.
	printSummary(out, serverResults, cfg)
	return out.err
}

// WriteCSVResults formats and writes the benchmark results to the given writer in CSV format.
func WriteCSVResults(writer io.Writer, results *analysis.BenchmarkResults, cfg *config.Config) error {
	serverResults := getServerResultsSlice(results)
	sortServerResults(serverResults)

	csvWriter := csv.NewWriter(writer)

	header := buildCSVHeader(cfg)
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, res := range serverResults {
		row := buildCSVRow(res, cfg)
		if err := csvWriter.Write(row); err != nil {
			return fmt.Errorf("write CSV row for %s: %w", res.ServerAddress, err)
		}
	}
	csvWriter.Flush()
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
	if err := encoder.Encode(JSONReport{SchemaVersion: JSONSchemaVersion, Metadata: results.Metadata, Results: outputResults}); err != nil {
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

// sortServerResults sorts catalogue results by ranking group (transport and IP
// family), then by composite Score ascending within each group (lower is
// better). Endpoints without catalogue metadata keep the original score-only
// ordering and sort ahead of catalogue groups. Unrankable servers (+Inf) sort
// last in their group; ties break by ServerAddress, then EndpointID, for
// deterministic output.
func sortServerResults(results []*analysis.ServerResult) {
	sort.SliceStable(results, func(i, j int) bool {
		if gi, gj := sortGroup(results[i]), sortGroup(results[j]); gi != gj {
			return gi < gj
		}
		si, sj := results[i].Score, results[j].Score
		if si != sj {
			return si < sj
		}
		if results[i].ServerAddress != results[j].ServerAddress {
			return results[i].ServerAddress < results[j].ServerAddress
		}
		return results[i].EndpointID < results[j].EndpointID
	})
}

func sortGroup(res *analysis.ServerResult) string {
	if res.CatalogVersion == "" {
		return ""
	}
	return res.RankingGroup()
}

// buildHeader constructs the header row for console output.
// It includes columns for server address, latency metrics, reliability, and optional checks.
func buildHeader(cfg *config.Config) []string {
	header := []string{"DNS Server", "Protocol", "Avg Cached", "StdDev Cached", "Avg Uncached", "StdDev Uncached", "Score", "Reliability"}
	if cfg.CheckFiltering {
		header = append(header, "Filtering")
	}
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
	return append(header, "Provider", "Profile", "Roles", "IPFamily", "TLSServerName", "FilteringPolicy", "Truncated")
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
		formatReliability(res),
	}
	if cfg.CheckFiltering {
		row = append(row, formatCheckState(res.Checks["filtering"]))
	}
	if cfg.CheckDotcom {
		row = append(row, formatDotcom(res))
	}
	if cfg.CheckDNSSEC {
		row = append(row, formatBoolPointer(res.SupportsDNSSEC, "Yes", "No", "Inconclusive"))
	}
	if cfg.CheckNXDOMAIN {
		row = append(row, formatBoolPointer(res.HijacksNXDOMAIN, "Hijacks", "No Hijack", "Inconclusive"))
	}
	if cfg.CheckRebinding {
		row = append(row, formatBoolPointer(res.BlocksRebinding, "Blocks", "Allows", "Inconclusive"))
	}
	if cfg.AccuracyCheckFile != "" {
		row = append(row, formatBoolPointer(res.IsAccurate, "Accurate", "Mismatch", "Inconclusive"))
	}
	return append(row, res.Provider, res.Profile, strings.Join(res.Roles, ";"), res.IPFamily, res.TLSServerName, res.FilteringPolicy, strconv.Itoa(res.TruncatedResponses))
}

// buildCSVHeader constructs the header row for CSV output: the fixed metric
// columns, columns for the enabled checks, then the identity and probe-state
// columns.
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
	return append(header, "Provider", "Profile", "Roles", "EndpointID", "IPFamily", "Transport", "TLSServerName", "CatalogVersion", "FilteringPolicy", "ComparisonGroup", "TruncatedResponses", "PolicyResponses", "DNSSECState", "NXDOMAINState", "RebindingState", "AccuracyState", "FilteringState", "DotcomState", "SkippedQueries")
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
	return append(row, res.Provider, res.Profile, strings.Join(res.Roles, ";"), res.EndpointID, res.IPFamily, res.Transport, res.TLSServerName, res.CatalogVersion, res.FilteringPolicy, res.ComparisonGroup(), strconv.Itoa(res.TruncatedResponses), strconv.Itoa(res.PolicyResponses), string(res.Checks["dnssec"]), string(res.Checks["nxdomain"]), string(res.Checks["rebinding"]), string(res.Checks["accuracy"]), string(res.Checks["filtering"]), string(res.Checks["dotcom"]), strconv.Itoa(res.Skipped))
}

// JSONServerResult defines the structure for JSON output.
// It specifies how ServerResult data is serialized into JSON format.
type JSONServerResult struct {
	ExtendedDNSErrors []uint16 `json:"extendedDnsErrors"`
	PolicyResponses   int      `json:"policyResponses"`
	catalog.Metadata
	ComparisonGroup           string                         `json:"comparisonGroup"`
	Checks                    map[string]analysis.CheckState `json:"checks"`
	TruncatedResponses        int                            `json:"truncatedResponses"`
	ServerAddress             string                         `json:"serverAddress"`
	Protocol                  string                         `json:"protocol"`
	AvgCachedLatencyMs        *float64                       `json:"avgCachedLatencyMs,omitempty"`
	StdDevCachedLatencyMs     *float64                       `json:"stdDevCachedLatencyMs,omitempty"`
	AvgUncachedLatencyMs      *float64                       `json:"avgUncachedLatencyMs,omitempty"`
	StdDevUncachedLatencyMs   *float64                       `json:"stdDevUncachedLatencyMs,omitempty"`
	DotcomLatencyMs           *float64                       `json:"dotcomLatencyMs,omitempty"`
	ReliabilityPct            float64                        `json:"reliabilityPct"`
	Score                     *float64                       `json:"score"`
	SuccessfulCachedQueries   int                            `json:"successfulCachedQueries"`
	SuccessfulUncachedQueries int                            `json:"successfulUncachedQueries"`
	FailedLatencyQueries      int                            `json:"failedLatencyQueries"`
	Errors                    int                            `json:"errors"` // Deprecated alias for compatibility
	TimeoutErrors             int                            `json:"timeoutErrors"`
	TransportErrors           int                            `json:"transportErrors"`
	DNSFailures               int                            `json:"dnsFailures"`
	MalformedResponses        int                            `json:"malformedResponses"`
	TotalLatencyQueries       int                            `json:"totalLatencyQueries"`
	SkippedQueries            int                            `json:"skippedQueries,omitempty"` // Queries not attempted due to interruption
	SupportsDNSSEC            *bool                          `json:"supportsDnssec,omitempty"`
	HijacksNXDOMAIN           *bool                          `json:"hijacksNxdomain,omitempty"`
	BlocksRebinding           *bool                          `json:"blocksRebinding,omitempty"`
	IsAccurate                *bool                          `json:"isAccurate,omitempty"`
}

// buildJSONResult transforms a ServerResult into a JSONServerResult.
// It prepares the data for JSON output, converting relevant fields to the JSONServerResult structure.
func buildJSONResult(res *analysis.ServerResult, cfg *config.Config) JSONServerResult {
	jsonRes := JSONServerResult{
		ExtendedDNSErrors: res.ExtendedDNSErrors, PolicyResponses: res.PolicyResponses,
		Metadata: res.Metadata, ComparisonGroup: res.ComparisonGroup(), Checks: res.Checks, TruncatedResponses: res.TruncatedResponses,
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
		SkippedQueries:            res.Skipped,
		SupportsDNSSEC:            res.SupportsDNSSEC,
		HijacksNXDOMAIN:           res.HijacksNXDOMAIN,
		BlocksRebinding:           res.BlocksRebinding,
		IsAccurate:                res.IsAccurate,
	}
	// Arrays and the checks object are never null in schema v2.
	jsonRes.ExtendedDNSErrors = nonNil(jsonRes.ExtendedDNSErrors)
	jsonRes.Roles = nonNil(jsonRes.Roles)
	jsonRes.SourceURLs = nonNil(jsonRes.SourceURLs)
	if jsonRes.Checks == nil {
		jsonRes.Checks = map[string]analysis.CheckState{}
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

// nonNil returns s, or an empty slice when s is nil, so it encodes as [].
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// printSingleGroupSummary prints a concluding recommendation across results.
func printSingleGroupSummary(writer io.Writer, results []*analysis.ServerResult, cfg *config.Config) {
	printConclusion(writer, "\n--- Conclusion ---", results, cfg)
}

// printConclusion prints the recommendation block under the given heading.
func printConclusion(writer io.Writer, heading string, results []*analysis.ServerResult, cfg *config.Config) {
	if len(results) == 0 {
		return
	}

	_, _ = fmt.Fprintln(writer, heading)

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

// findBestServer returns the recommended server: the eligible server with the
// lowest composite Score. Reliability and DNS-failure rate are already folded
// into Score. Two hard gates apply: accuracy (when -accuracy-file is set) and
// the .com probe (when -dotcom is set). A failed or inconclusive .com probe
// already makes Score +Inf, but a probe skipped by cancellation is left out of
// Score, so the gate is what keeps an unverified server from being
// recommended. Unrankable servers (+Inf score) are skipped. Returns nil if no
// eligible server exists.
func findBestServer(results []*analysis.ServerResult, cfg *config.Config) *analysis.ServerResult {
	var bestServer *analysis.ServerResult
	for _, res := range results {
		if cfg.AccuracyCheckFile != "" && (res.IsAccurate == nil || !*res.IsAccurate) {
			continue // accuracy gate: skip inaccurate/inconclusive
		}
		if cfg.CheckDotcom && res.DotcomLatency == nil {
			continue // .com gate: skip failed/inconclusive
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
	otherIssues := false
	others := 0
	for _, res := range results {
		isBest := res == bestServer
		if !isBest {
			others++
		}

		warningPrefix := fmt.Sprintf("Warning (%s):", res.ServerAddress)
		if isBest {
			warningPrefix = fmt.Sprintf("Warning (recommended, %s):", res.ServerAddress)
		}
		warn := func(format string, args ...any) {
			_, _ = fmt.Fprintf(writer, "%s "+format+"\n", append([]any{warningPrefix}, args...)...)
			if !isBest {
				otherIssues = true
			}
		}
		attempted := res.TotalQueries - res.Skipped
		if attempted > 0 && res.Reliability < reliabilityThreshold {
			warn("Low reliability (%.1f%%).", res.Reliability)
		}
		if res.DNSFailures > 0 {
			warn("Returned %d unexpected DNS failure responses during latency probes.", res.DNSFailures)
		}
		if cfg.CheckNXDOMAIN && res.HijacksNXDOMAIN != nil && *res.HijacksNXDOMAIN {
			warn("Appears to hijack NXDOMAIN responses.")
		}
		if cfg.CheckNXDOMAIN && res.Checks["nxdomain"] == analysis.Inconclusive {
			warn("NXDOMAIN check was inconclusive.")
		}
		if cfg.CheckRebinding && res.BlocksRebinding != nil && !*res.BlocksRebinding {
			warn("Allows responses with private IPs (rebinding risk).")
		}
		if cfg.CheckRebinding && res.Checks["rebinding"] == analysis.Inconclusive {
			warn("Rebinding check was inconclusive.")
		}
		if cfg.CheckDNSSEC && res.Checks["dnssec"] == analysis.Fail {
			warn("Does not validate DNSSEC (accepted a deliberately broken signature).")
		}
		if cfg.CheckDNSSEC && res.Checks["dnssec"] == analysis.Inconclusive {
			warn("DNSSEC check was inconclusive.")
		}
		if cfg.CheckFiltering && res.Checks["filtering"] == analysis.Fail {
			warn("Did not block the documented filtering probe domains.")
		}
		if cfg.CheckFiltering && res.Checks["filtering"] == analysis.Inconclusive {
			warn("Filtering check was inconclusive.")
		}
		if cfg.AccuracyCheckFile != "" && res.IsAccurate != nil && !*res.IsAccurate {
			warn("Returned inaccurate results for %s.", cfg.AccuracyCheckDomain)
		}
		if cfg.AccuracyCheckFile != "" && res.IsAccurate == nil {
			warn("Accuracy check for %s was inconclusive.", cfg.AccuracyCheckDomain)
		}
		if cfg.CheckDotcom && res.Checks["dotcom"] == analysis.Fail {
			warn(".com probe did not return NXDOMAIN; excluded from recommendation.")
		}
		if cfg.CheckDotcom && res.Checks["dotcom"] == analysis.Inconclusive {
			if res.DotcomSkipped {
				warn(".com probe was not sent before the run was interrupted; excluded from recommendation.")
			} else {
				warn(".com probe was inconclusive; excluded from recommendation.")
			}
		}
	}

	if !otherIssues && bestServer != nil && others > 0 {
		_, _ = fmt.Fprintln(writer, "Other tested servers performed reliably without major issues detected.")
	}
}

// --- Formatting Helpers ---

// formatReliability formats the reliability percentage for console output.
// A server with no attempted probes (e.g. interrupted before its turn) reads
// "N/A" rather than a misleading 0.0%.
func formatReliability(res *analysis.ServerResult) string {
	if res.TotalQueries-res.Skipped <= 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.1f%%", res.Reliability)
}

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

// formatDotcom formats the .com probe column: the latency when the probe
// passed, otherwise the check state, so Fail and Inconclusive stay distinct.
func formatDotcom(res *analysis.ServerResult) string {
	if res.DotcomLatency != nil {
		return formatDurationPointer(res.DotcomLatency)
	}
	return formatCheckState(res.Checks["dotcom"])
}

// formatCheckState formats a check state for console output, using the same
// words as the other check columns.
func formatCheckState(state analysis.CheckState) string {
	switch state {
	case analysis.Pass:
		return "Pass"
	case analysis.Fail:
		return "Fail"
	case analysis.Inconclusive:
		return "Inconclusive"
	default:
		return "N/A"
	}
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

// JSONSchemaVersion is the schemaVersion written by WriteJSONResults. Bump it
// whenever a JSON key is renamed, removed or changes type.
const JSONSchemaVersion = "2"

// JSONReport is the version 2 JSON envelope, including workload metadata.
type JSONReport struct {
	SchemaVersion string               `json:"schemaVersion"`
	Metadata      analysis.RunMetadata `json:"metadata"`
	Results       []JSONServerResult   `json:"results"`
}

// printSummary prints recommendations. Catalogue endpoints are ranked across
// providers within each RankingGroup (transport and IP family), and each line
// names the winner's filtering policy so the trade-off stays visible. Where at
// least two catalogue endpoints share a ComparisonGroup (matching policy, roles,
// ECS, transport and IP family), the fastest like-for-like endpoint is also
// reported; single-member policy groups are omitted because they compare
// nothing. Endpoints without catalogue metadata (-f entries and system DNS) are
// summarised together with the original single "Conclusion"; a run made only of
// such endpoints prints exactly that.
func printSummary(writer io.Writer, results []*analysis.ServerResult, cfg *config.Config) {
	// Printed once, after every group's warnings. cfg is read when the
	// deferred call runs, so a rebinding check suppressed below is ignored.
	defer func() {
		if !cfg.Verbose && anyInconclusive(results, cfg) {
			_, _ = fmt.Fprintln(writer, "Note: inconclusive checks got no usable answer (timeout, SERVFAIL, REFUSED, truncation or an interrupted run); run with -v for per-probe details.")
		}
	}()
	if rebindingUnverified(results, cfg) {
		// Every server is inconclusive for the same run-level reason, so one
		// note replaces a rebinding warning per server in every group.
		defer func() {
			_, _ = fmt.Fprintf(writer, "Note: no tested server passed the private answer for %s through, so the test domain is unverified and rebinding protection is inconclusive for every server. Include a resolver without rebinding protection to confirm it.\n", cfg.RebindingDomain)
		}()
		withoutRebinding := *cfg
		withoutRebinding.CheckRebinding = false
		cfg = &withoutRebinding
	}
	rankingGroups := map[string][]*analysis.ServerResult{}
	policyGroups := map[string][]*analysis.ServerResult{}
	var uncatalogued []*analysis.ServerResult
	for _, res := range results {
		if res.CatalogVersion == "" {
			uncatalogued = append(uncatalogued, res)
			continue
		}
		rankingGroups[res.RankingGroup()] = append(rankingGroups[res.RankingGroup()], res)
		policyGroups[res.ComparisonGroup()] = append(policyGroups[res.ComparisonGroup()], res)
	}
	if len(rankingGroups) == 0 {
		printSingleGroupSummary(writer, uncatalogued, cfg)
		return
	}

	_, _ = fmt.Fprintln(writer, "\n--- Recommendations by transport and IP family ---")
	for _, key := range sortedKeys(rankingGroups) {
		group := rankingGroups[key]
		best := findBestServer(group, cfg)
		if best != nil {
			_, _ = fmt.Fprintf(writer, "Fastest %s: %s (%s, policy %s), %s, score %s\n", key, best.Provider, best.Profile, best.FilteringPolicy, best.ServerAddress, formatScore(best.Score))
		} else {
			_, _ = fmt.Fprintf(writer, "No rankable server for %s.\n", key)
		}
		printServerWarnings(writer, group, best, cfg)
	}

	headerPrinted := false
	for _, key := range sortedKeys(policyGroups) {
		group := policyGroups[key]
		if len(group) < 2 {
			continue
		}
		best := findBestServer(group, cfg)
		if best == nil {
			continue
		}
		if !headerPrinted {
			_, _ = fmt.Fprintln(writer, "\n--- Fastest within matching policy groups ---")
			headerPrinted = true
		}
		_, _ = fmt.Fprintf(writer, "Fastest %s: %s (%s), %s, score %s\n", key, best.Provider, best.Profile, best.ServerAddress, formatScore(best.Score))
	}

	printConclusion(writer, "\n--- Conclusion (system and custom endpoints, no catalogue policy) ---", uncatalogued, cfg)
}

// anyInconclusive reports whether any enabled check was inconclusive for any
// server, matching the per-server "inconclusive" warnings.
func anyInconclusive(results []*analysis.ServerResult, cfg *config.Config) bool {
	enabled := map[string]bool{
		"dnssec": cfg.CheckDNSSEC, "nxdomain": cfg.CheckNXDOMAIN, "rebinding": cfg.CheckRebinding,
		"filtering": cfg.CheckFiltering, "accuracy": cfg.AccuracyCheckFile != "", "dotcom": cfg.CheckDotcom,
	}
	for _, res := range results {
		for name, on := range enabled {
			if on && res.Checks[name] == analysis.Inconclusive {
				return true
			}
		}
	}
	return false
}

// rebindingUnverified reports whether the rebinding check ran but no server
// reached a conclusive state, which happens when no tested server passed the
// test domain's private answer through (see dnsquery finalizeRebinding).
func rebindingUnverified(results []*analysis.ServerResult, cfg *config.Config) bool {
	if !cfg.CheckRebinding || len(results) == 0 {
		return false
	}
	for _, res := range results {
		if state := res.Checks["rebinding"]; state == analysis.Pass || state == analysis.Fail {
			return false
		}
	}
	return true
}

func sortedKeys(groups map[string][]*analysis.ServerResult) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func catalogVersion(results *analysis.BenchmarkResults) string {
	for _, r := range results.Results {
		if r.CatalogVersion != "" {
			return r.CatalogVersion
		}
	}
	return ""
}
