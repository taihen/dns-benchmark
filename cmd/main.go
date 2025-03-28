package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/config"
	"github.com/taihen/dns-benchmark/pkg/dnsquery"
	"github.com/taihen/dns-benchmark/pkg/output"
)

func main() {
	// Explicitly use a type from the analysis package to satisfy the compiler
	_ = analysis.BenchmarkResults{}

	// Load configuration from flags and environment
	cfg := config.LoadConfig() // Handles verbose output internally now

	// Create and run the benchmarker
	fmt.Println("Running benchmark...")
	benchmarker := dnsquery.NewBenchmarker(cfg)
	results := benchmarker.Run()
	fmt.Println("Benchmark finished.")
	fmt.Println("---")

	// Analyze the results (calculate metrics)
	results.Analyze()

	// Determine output writer (stdout or file)
	outputWriter := os.Stdout // Default to stdout
	var err error
	if cfg.OutputFile != "" {
		outputWriter, err = os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file %s: %v\n", cfg.OutputFile, err)
			os.Exit(1)
		}
		defer outputWriter.Close()
		// Print message only if actually writing to file
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
		fmt.Fprintf(os.Stderr, "Error: Unknown output format '%s'\n", cfg.OutputFormat)
		os.Exit(1)
	}

	// Handle potential errors during CSV/JSON writing
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s output: %v\n", format, err)
		os.Exit(1)
	}

	// Indicate completion if writing to a file
	if outputWriter != os.Stdout {
		fmt.Println("Done.")
	}

	os.Exit(0)
}
