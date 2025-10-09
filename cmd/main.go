package main

import (
	"os"
)

var version = "dev" // Will be overridden during build

func main() {
	// os.Args[1:] excludes the program name
	// os.Stdout is the default writer for output
	exitCode := run(os.Args[1:], os.Stdout)
	os.Exit(exitCode)
}