package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runMainEnv makes the test binary act as the dns-benchmark command, so the
// tests below exercise the real flag parsing, exit codes and stream wiring.
const runMainEnv = "DNS_BENCHMARK_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		os.Args = append([]string{"dns-benchmark"}, os.Args[1:]...)
		main()
	}
	os.Exit(m.Run())
}

// startUDPFixture serves an A record for every query on a loopback UDP port.
func startUDPFixture(t *testing.T) string {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	ready := make(chan struct{})
	server := &dns.Server{
		PacketConn:        socket,
		NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			reply := new(dns.Msg)
			reply.SetReply(q)
			if len(q.Question) == 1 && q.Question[0].Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)})
			}
			_ = w.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	return socket.LocalAddr().String()
}

// runCommand runs the test binary as dns-benchmark with args and returns its
// stdout, stderr and exit code.
func runCommand(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else {
		require.NoError(t, err)
	}
	return stdout.String(), stderr.String(), code
}

func writeServersFile(t *testing.T, address string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "servers.txt")
	require.NoError(t, os.WriteFile(path, []byte(address+"\n"), 0o600))
	return path
}

func TestJSONStdoutStaysParseable(t *testing.T) {
	servers := writeServersFile(t, startUDPFixture(t))

	stdout, stderr, code := runCommand(t, "-f", servers, "-system=false", "-n", "2", "-rate", "0", "-format", "json")

	require.Equal(t, 0, code, "stderr: %s", stderr)
	var report struct {
		SchemaVersion string            `json:"schemaVersion"`
		Results       []json.RawMessage `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &report), "stdout must contain only the JSON report, got: %q", stdout)
	assert.Equal(t, "2", report.SchemaVersion)
	assert.Len(t, report.Results, 1)
	assert.Contains(t, stderr, "Benchmark finished.", "progress and banner lines belong on stderr")
}

func TestInvalidFlagsFailBeforeTouchingOutputFile(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"unknown format", []string{"-format", "jsn"}, "unknown output format"},
		{"unknown query type", []string{"-type", "AAA"}, "unknown -type"},
		{"zero timeout", []string{"-t", "0s"}, "-t must be a positive duration"},
		{"rebinding without domain", []string{"-rebinding"}, "-rebinding requires -rebinding-domain"},
		{"missing accuracy file", []string{"-accuracy-file", "/nonexistent/accuracy.txt"}, "could not load accuracy check file"},
		{"accuracy file without a valid entry", []string{"-accuracy-file", "EMPTY_ACCURACY_FILE"}, "could not load accuracy check file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "results.json")
			require.NoError(t, os.WriteFile(output, []byte("previous results"), 0o600))

			// The servers file points at an unused address: validation must fail
			// before any query is sent.
			args := append([]string{"-f", writeServersFile(t, "192.0.2.1"), "-system=false", "-o", output}, tt.args...)
			for i, arg := range args {
				if arg == "EMPTY_ACCURACY_FILE" {
					args[i] = filepath.Join(t.TempDir(), "accuracy.txt")
					require.NoError(t, os.WriteFile(args[i], []byte("# no entries\n"), 0o600))
				}
			}
			stdout, stderr, code := runCommand(t, args...)

			assert.Equal(t, 1, code)
			assert.Empty(t, stdout)
			assert.Contains(t, stderr, tt.wantErr)
			assert.NotContains(t, stderr, "Running benchmark", "the benchmark must not start")
			content, err := os.ReadFile(output)
			require.NoError(t, err)
			assert.Equal(t, "previous results", string(content), "an existing output file must not be truncated")
		})
	}
}

func TestUnwritableOutputFailsBeforeBenchmark(t *testing.T) {
	output := filepath.Join(t.TempDir(), "missing-dir", "results.json")

	stdout, stderr, code := runCommand(t, "-f", writeServersFile(t, "192.0.2.1"), "-system=false", "-o", output)

	assert.Equal(t, 1, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "Error opening output file")
	assert.NotContains(t, stderr, "Running benchmark", "an unwritable output path must fail before the benchmark starts")
}

func TestOutputFileReplacesPreviousContents(t *testing.T) {
	servers := writeServersFile(t, startUDPFixture(t))
	output := filepath.Join(t.TempDir(), "results.json")
	// Longer than the new report, so leftover bytes would break the JSON.
	require.NoError(t, os.WriteFile(output, bytes.Repeat([]byte("x"), 1<<20), 0o600))

	_, stderr, code := runCommand(t, "-f", servers, "-system=false", "-n", "2", "-rate", "0", "-format", "json", "-o", output)

	require.Equal(t, 0, code, "stderr: %s", stderr)
	content, err := os.ReadFile(output)
	require.NoError(t, err)
	var report map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(content, &report), "the output file must hold only the new report")
	assert.Contains(t, report, "results")
}
