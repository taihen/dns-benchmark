package main

import (
	"fmt"
	"os"
	"strings"

	// Internal packages structured according to standard Go project layout
	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/config"
	"github.com/taihen/dns-benchmark/pkg/dnsquery"
	"github.com/taihen/dns-benchmark/pkg/output"
)

var version = "dev" // Will be overridden during build

func main() {
	// Explicitly use a type from the analysis package to satisfy the compiler
	_ = analysis.BenchmarkResults{}

	// Load configuration from flags, environment, and potentially config files
	cfg := config.LoadConfig()

	// Display version if requested
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		fmt.Printf("dns-benchmark version %s\n", version)
		os.Exit(0)
	}

	// Create and run the benchmarker
	fmt.Printf("DNS Benchmark %s\n", version) // Removed 'v' prefix here
	fmt.Println("Running benchmark...")
	benchmarker := dnsquery.NewBenchmarker(cfg)
	results := benchmarker.Run()
	fmt.Println("Benchmark finished.")
	fmt.Println("---")

	// Analyze the results (calculate derived metrics like averages, stddev, reliability)
	results.Analyze()

	// Determine output writer (defaults to standard output)
	outputWriter := os.Stdout
	var err error
	if cfg.OutputFile != "" {
		outputWriter, err = os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file %s: %v\n", cfg.OutputFile, err)
			os.Exit(1)
		}
		defer outputWriter.Close()
		fmt.Printf("Writing results to %s...\n", cfg.OutputFile)
	}

	// Output the results based on the configured format
	format := strings.ToLower(cfg.OutputFormat)
	switch format {
	case "console":
		output.PrintConsoleResults(outputWriter, results, cfg)
	case "csv":
		err = output.WriteCSVResults(outputWriter, results, cfg)
	case "json":
		err = output.WriteJSONResults(outputWriter, results, cfg)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown output format '%s'. Use 'console', 'csv', or 'json'.\n", cfg.OutputFormat)
		os.Exit(1)
	}

	// Handle potential errors during file writing for CSV/JSON
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s output: %v\n", format, err)
		// Attempt to remove partially written file? Maybe not necessary.
		os.Exit(1)
	}

	// Indicate completion only when writing to a file
	if outputWriter != os.Stdout {
		fmt.Println("Done.")
	}

	os.Exit(0) // Exit successfully
}
