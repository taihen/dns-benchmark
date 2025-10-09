package main

import (
	"fmt"
	"io"
	"os"

	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/config"
	"github.com/taihen/dns-benchmark/pkg/dnsquery"
	"github.com/taihen/dns-benchmark/pkg/output"
)

func run(args []string, stdout io.Writer) int {
	// Load configuration from flags, environment, and potentially config files
	cfg := config.LoadConfig()

	// Display version if requested
	if cfg.ShowVersion {
		fmt.Fprintf(stdout, "dns-benchmark version %s\n", version)
		return 0
	}

	// Create and run the benchmarker
	fmt.Fprintln(stdout, "DNS Benchmark", version)
	fmt.Fprintln(stdout, "Running benchmark...")
	benchmarker := dnsquery.NewBenchmarker(cfg)
	var results *analysis.BenchmarkResults = benchmarker.Run()
	fmt.Fprintln(stdout, "Benchmark finished.")
	fmt.Fprintln(stdout, "---")

	// Analyze the results (calculate derived metrics like averages, stddev, reliability)
	results.Analyze()

	// Determine output writer and write results
	outputWriter, cleanup, err := output.GetWriter(cfg.OutputFile, stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer cleanup()

	if cfg.OutputFile != "" {
		fmt.Fprintf(stdout, "Writing results to %s...\n", cfg.OutputFile)
	}

	if err := output.WriteResults(outputWriter, results, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing results: %v\n", err)
		dnsquery.CleanupQuicPool()
		return 1
	}

	if cfg.OutputFile != "" {
		fmt.Fprintln(stdout, "Done.")
	}

	// Cleanup QUIC connection pool before exit
	dnsquery.CleanupQuicPool()

	return 0 // Exit successfully
}