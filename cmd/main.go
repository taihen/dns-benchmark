package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
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

	// Prepare the output file before the benchmark so that an unwritable path
	// fails immediately instead of discarding a completed run. Results go to
	// a temporary file that replaces the target only once it is complete, so
	// a failed write or a killed run leaves an existing file untouched.
	var outputWriter io.Writer = os.Stdout
	var outFile *outputFile
	if cfg.OutputFile != "" {
		f, err := openOutputFile(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file %s: %v\n", cfg.OutputFile, err)
			return 1
		}
		outFile = f
		outputWriter = f
		// Removes the temporary file on any return before Commit.
		defer outFile.Discard()
	}

	// Cancel the benchmark on Ctrl+C / SIGTERM; results collected so far are
	// still analyzed and reported.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Create and run the benchmarker
	fmt.Fprintf(os.Stderr, "DNS Benchmark %s\n", version)
	fmt.Fprintln(os.Stderr, "Running benchmark... (Ctrl+C to stop early and keep partial results)")
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
	fmt.Fprintln(os.Stderr, "Benchmark finished.")
	fmt.Fprintln(os.Stderr, "---")

	// Analyze the results (calculate derived metrics like averages, stddev, reliability)
	results.Analyze()

	if outFile != nil {
		fmt.Fprintf(os.Stderr, "Writing results to %s...\n", cfg.OutputFile)
	}
	var err error

	// Output the results based on the configured format
	format := strings.ToLower(cfg.OutputFormat)
	switch format {
	case "console":
		err = output.PrintConsoleResults(outputWriter, results, cfg)
	case "csv":
		err = output.WriteCSVResults(outputWriter, results, cfg)
	case "json":
		err = output.WriteJSONResults(outputWriter, results, cfg)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown output format '%s'. Use 'console', 'csv', or 'json'.\n", cfg.OutputFormat)
		return 1
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s output: %v\n", format, err)
		return 1
	}

	// Indicate completion only when writing to a file, and only once the
	// complete report has replaced the target.
	if outFile != nil {
		if err := outFile.Commit(); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s output: %v\n", format, err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "Done.")
	}

	if interrupted {
		return 130 // conventional exit code for SIGINT
	}
	return 0
}

// outputFile is the -o destination. For a regular file or a new path, writes
// go to a temporary file in the same directory, which Commit renames over the
// target; the target is therefore either unchanged or holds the complete
// report. Devices and pipes such as /dev/stdout are written directly.
type outputFile struct {
	*os.File
	target string // final path; empty when the destination is written directly
	done   bool   // set once Commit or Discard has run
}

// openOutputFile prepares path for writing, failing if it cannot be written.
// Symlinks are resolved so that the file they point to is replaced, not the link.
func openOutputFile(path string) (*outputFile, error) {
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	var perm fs.FileMode = 0o666 // narrowed by the umask, as os.Create does
	keepPerm := false
	info, err := os.Stat(target)
	switch {
	case err == nil && !info.Mode().IsRegular():
		f, err := os.OpenFile(target, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		return &outputFile{File: f}, nil
	case err == nil:
		// The rename only needs a writable directory; check the file itself so
		// that a read-only report is refused rather than silently replaced.
		probe, err := os.OpenFile(target, os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		_ = probe.Close()
		perm, keepPerm = info.Mode().Perm(), true
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	f, err := createSibling(target, perm)
	if err != nil {
		return nil, err
	}
	if keepPerm {
		// OpenFile applies the umask; restore the existing file's exact mode.
		if err := f.Chmod(perm); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return nil, err
		}
	}
	return &outputFile{File: f, target: target}, nil
}

// createSibling creates a new, uniquely named hidden file next to target, so
// that the final rename stays on one filesystem.
func createSibling(target string, perm fs.FileMode) (*os.File, error) {
	dir, base := filepath.Split(target)
	for i := 0; ; i++ {
		name := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d-%d", base, os.Getpid(), i))
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, fs.ErrExist) && i < 100 {
			continue
		}
		return f, err
	}
}

// Commit closes the file and, for a temporary file, renames it over the
// target. On failure the temporary file is removed and the target is unchanged.
func (o *outputFile) Commit() error {
	o.done = true
	if err := o.Close(); err != nil {
		o.removeTemp()
		return err
	}
	if o.target == "" {
		return nil
	}
	if err := os.Rename(o.Name(), o.target); err != nil {
		o.removeTemp()
		return err
	}
	return nil
}

// Discard closes the file and removes the temporary file, leaving the target
// unchanged. It does nothing after Commit.
func (o *outputFile) Discard() {
	if o.done {
		return
	}
	o.done = true
	_ = o.Close()
	o.removeTemp()
}

func (o *outputFile) removeTemp() {
	if o.target != "" {
		_ = os.Remove(o.Name())
	}
}

// isTerminal reports whether f is attached to an interactive terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
