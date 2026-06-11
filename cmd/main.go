package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	// Internal packages structured according to standard Go project layout
	"github.com/taihen/dns-benchmark/pkg/config"
	"github.com/taihen/dns-benchmark/pkg/dnsquery"
	"github.com/taihen/dns-benchmark/pkg/output"
)

var version = "dev" // Will be overridden during build

func main() {
	os.Exit(run())
}

// run executes the benchmark and returns the process exit code. Keeping the
// logic out of main ensures deferred cleanup runs before os.Exit.
func run() int {
	// Load configuration from flags, environment, and potentially config files
	cfg := config.LoadConfig()

	// Display version if requested
	if cfg.ShowVersion {
		fmt.Printf("dns-benchmark version %s\n", version)
		return 0
	}

	// Cancel the benchmark on Ctrl+C / SIGTERM; results collected so far are
	// still analyzed and reported.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Create and run the benchmarker
	fmt.Printf("DNS Benchmark %s\n", version)
	fmt.Println("Running benchmark... (Ctrl+C to stop early and keep partial results)")
	benchmarker := dnsquery.NewBenchmarker(cfg)
	defer benchmarker.Close()
	if isTerminal(os.Stderr) {
		benchmarker.ProgressWriter = os.Stderr
	}
	results := benchmarker.Run(ctx)
	interrupted := ctx.Err() != nil
	stop() // restore default signal behavior: a second Ctrl+C kills immediately
	if interrupted {
		fmt.Fprintln(os.Stderr, "Interrupted - reporting partial results.")
	}
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
			return 1
		}
		defer func() { _ = outputWriter.Close() }()
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
		return 1
	}

	// Handle potential errors during file writing for CSV/JSON
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s output: %v\n", format, err)
		return 1
	}

	// Indicate completion only when writing to a file
	if outputWriter != os.Stdout {
		fmt.Println("Done.")
	}

	if interrupted {
		return 130 // conventional exit code for SIGINT
	}
	return 0
}

// isTerminal reports whether f is attached to an interactive terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
