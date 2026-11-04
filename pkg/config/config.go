package config

import (
	"bufio"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/taihen/dns-benchmark/pkg/catalog"
)

// ProtocolType defines the DNS protocol.
type ProtocolType string

const (
	UDP ProtocolType = "udp"
	TCP ProtocolType = "tcp"
	DOT ProtocolType = "dot" // DNS over TLS
	DOH ProtocolType = "doh" // DNS over HTTPS
	DOQ ProtocolType = "doq" // DNS over QUIC
)

// ServerInfo holds details about a DNS server endpoint.
type ServerInfo struct {
	catalog.Metadata
	// ConnectAddress optionally pins the DoH connection independently of its URL.
	ConnectAddress string
	// TLSRootCAs optionally supplies a private trust store for controlled endpoints.
	TLSRootCAs *x509.CertPool
	Address    string // For UDP/TCP/DoT/DoQ: IP:Port or Host:Port. For DoH: Full URL.
	Protocol   ProtocolType
	Hostname   string // Hostname for TLS SNI / DoH URL host. Should NOT contain brackets for IPv6.
	DoHPath    string // Path for DoH endpoint (e.g., /dns-query).
}

// String returns the unique identity of an endpoint, used as the results key and
// for verbose output. Catalogue endpoints are prefixed with their endpoint ID so
// that two endpoints sharing an address remain distinct; others use AddressString().
func (si ServerInfo) String() string {
	if si.EndpointID != "" {
		return si.EndpointID + " (" + string(si.Protocol) + ":" + si.Address + ")"
	}
	return si.AddressString()
}

// AddressString returns the protocol-prefixed address format used before the
// catalogue existed (for example "1.1.1.1:53", "tls://1.1.1.1:853" or a DoH URL).
// It is reported as serverAddress in CSV, JSON and console output.
func (si ServerInfo) AddressString() string {
	switch si.Protocol {
	case DOH:
		return si.Address // DoH address is the full URL
	case DOT:
		return tlsAddressString("tls", si)
	case DOQ:
		return tlsAddressString("quic", si)
	case TCP:
		// Preserve tcp:// prefix for TCP endpoints
		return fmt.Sprintf("tcp://%s", si.Address)
	default: // UDP
		return si.Address
	}
}

// tlsAddressString formats a DoT/DoQ endpoint by its authenticated name when it
// has one (catalogue TLSServerName, else a non-IP Hostname), otherwise by Address.
func tlsAddressString(scheme string, si ServerInfo) string {
	name := si.TLSServerName
	if name == "" {
		name = si.Hostname
	}
	if name != "" && net.ParseIP(name) == nil {
		_, port, err := net.SplitHostPort(si.Address)
		if err != nil {
			port = "853" // Default DoT/DoQ port
		}
		return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(name, port))
	}
	return fmt.Sprintf("%s://%s", scheme, si.Address)
}

// Label returns the friendly display name for the protocol (e.g. "DoT").
func (p ProtocolType) Label() string {
	switch p {
	case UDP:
		return "UDP"
	case TCP:
		return "TCP"
	case DOT:
		return "DoT"
	case DOH:
		return "DoH"
	case DOQ:
		return "DoQ"
	default:
		return string(p)
	}
}

var resolvConfNameserverRegex = regexp.MustCompile(`^\s*nameserver\s+([^\s]+)\s*$`)

// Config holds the application configuration derived from flags and files.
type Config struct {
	Preset              string
	Profiles            string
	Transports          string
	IPFamily            string
	RebindingDomain     string
	ServersFile         string
	Servers             []ServerInfo
	NumQueries          int
	Timeout             time.Duration
	Concurrency         int
	RateLimit           int
	QueryType           string
	Domain              string // Domain for cached latency tests
	CheckDNSSEC         bool
	CheckFiltering      bool
	CheckNXDOMAIN       bool
	Verbose             bool
	OutputFile          string
	OutputFormat        string
	IncludeSystemDNS    bool
	CheckRebinding      bool
	AccuracyCheckFile   string
	AccuracyCheckDomain string
	AccuracyCheckIP     string
	CheckDotcom         bool
	ShowVersion         bool
}

// DefaultDNSStrings returns the legacy preset's IPv4 UDP, DoT and DoH endpoints
// in the historical string format. DoT entries now use the provider's TLS
// name (for example tls://one.one.one.one) rather than an IP literal. The
// catalogue is loaded on first call, not at package init, so -version and
// other paths that never need it cannot fail on it.
//
// Deprecated: use Config.LoadServers to retain catalogue metadata and TLS names.
func DefaultDNSStrings() ([]string, error) {
	entries, err := defaultDNSStrings()
	return slices.Clone(entries), err
}

var defaultDNSStrings = sync.OnceValues(legacyEndpointStrings)

// LoadConfig parses flags, reads files, and returns the final configuration.
func LoadConfig() *Config {
	cfg := &Config{}

	flag.StringVar(
		&cfg.ServersFile,
		"f",
		"",
		"Path to file with DNS server endpoints (one per line: IP, tcp://IP, tls://IP, https://..., quic://IP)",
	)
	flag.IntVar(&cfg.NumQueries, "n", 50, "Number of latency queries per server (min 2 for stddev)")
	flag.DurationVar(&cfg.Timeout, "t", 5*time.Second, "Query timeout")
	flag.IntVar(&cfg.Concurrency, "c", 5, "Max concurrent queries/checks")
	flag.IntVar(&cfg.RateLimit, "rate", 50, "Max queries per second (0 for unlimited)")
	flag.StringVar(&cfg.QueryType, "type", "A", "DNS record type for latency queries")
	flag.StringVar(&cfg.Domain, "domain", "example.com", "Domain for repeated-domain latency test (often cached, not guaranteed)")
	flag.BoolVar(&cfg.CheckFiltering, "filtering", false, "Run documented provider filtering probes outside latency scoring")
	flag.BoolVar(&cfg.CheckDNSSEC, "dnssec", false, "Check for DNSSEC support")
	flag.BoolVar(&cfg.CheckNXDOMAIN, "nxdomain", false, "Check for NXDOMAIN hijacking")
	flag.BoolVar(&cfg.CheckRebinding, "rebinding", false, "Check for DNS rebinding protection (requires -rebinding-domain)")
	flag.BoolVar(&cfg.CheckDotcom, "dotcom", false, "Measure latency for a random .com NXDOMAIN lookup")
	flag.StringVar(
		&cfg.AccuracyCheckFile,
		"accuracy-file",
		"",
		"Path to file for accuracy check (domain IP[,IP...] per line, uses first valid entry)",
	)
	flag.BoolVar(&cfg.Verbose, "v", false, "Enable verbose output")
	flag.StringVar(&cfg.OutputFile, "o", "", "Path to output file (CSV/JSON)")
	flag.StringVar(&cfg.OutputFormat, "format", "console", "Output format (console, csv, json)")
	flag.BoolVar(&cfg.IncludeSystemDNS, "system", true, "Include system DNS servers (UDP only)")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "Print version and exit")

	flag.StringVar(&cfg.Preset, "preset", "legacy", "Resolver preset: legacy, general, security, family, extended")
	flag.StringVar(&cfg.Profiles, "profile", "", "Comma-separated catalogue profile IDs (overrides preset)")
	flag.StringVar(&cfg.Transports, "transports", "", "Comma-separated transports: udp,tcp,dot,doh,doq")
	flag.StringVar(&cfg.IPFamily, "ip-family", "auto", "IP family: ipv4, ipv6, auto (both for explicit catalogue selections)")
	flag.StringVar(&cfg.RebindingDomain, "rebinding-domain", "", "Controlled domain with private A and/or AAAA records; required for a conclusive rebinding probe")
	flag.Parse()

	// -version must work without selecting servers or loading the catalogue.
	if cfg.ShowVersion {
		return cfg
	}

	if err := cfg.validateChecks(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Load accuracy check data first
	if cfg.AccuracyCheckFile != "" {
		domain, ip, err := loadAccuracyCheckFile(cfg.AccuracyCheckFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not load accuracy check file %s: %v\n", cfg.AccuracyCheckFile, err)
			os.Exit(1)
		} else {
			cfg.AccuracyCheckDomain = domain
			cfg.AccuracyCheckIP = ip
		}
	}

	if err := cfg.LoadServers(); err != nil {
		fmt.Fprintf(os.Stderr, "Error selecting servers: %v\n", err)
		os.Exit(1)
	}

	if len(cfg.Servers) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No valid DNS servers specified or found.\n")
		os.Exit(1)
	}

	// Print verbose config if enabled (after final server list is ready)
	if cfg.Verbose {
		printVerboseConfig(cfg)
	}

	return cfg
}

// validateChecks rejects check flags that cannot produce a conclusive result.
func (cfg *Config) validateChecks() error {
	if cfg.CheckRebinding && strings.TrimSpace(cfg.RebindingDomain) == "" {
		return fmt.Errorf("-rebinding requires -rebinding-domain=<controlled name with private A and/or AAAA records>")
	}
	return nil
}

// printVerboseConfig prints the configuration details.
func printVerboseConfig(cfg *Config) {
	fmt.Fprintln(os.Stderr, "--- Configuration ---")
	fmt.Fprintf(os.Stderr, "Servers File:      %s\n", cfg.ServersFile)
	fmt.Fprintf(os.Stderr, "Servers Processed: %v\n", cfg.Servers)
	fmt.Fprintf(os.Stderr, "Num Queries:       %d\n", cfg.NumQueries)
	fmt.Fprintf(os.Stderr, "Timeout:           %v\n", cfg.Timeout)
	fmt.Fprintf(os.Stderr, "Concurrency:       %d\n", cfg.Concurrency)
	fmt.Fprintf(os.Stderr, "Rate Limit:        %d qps\n", cfg.RateLimit)
	fmt.Fprintf(os.Stderr, "Query Type:        %s\n", cfg.QueryType)
	fmt.Fprintf(os.Stderr, "Cached Domain:     %s\n", cfg.Domain)
	fmt.Fprintf(os.Stderr, "Check DNSSEC:      %t\n", cfg.CheckDNSSEC)
	fmt.Fprintf(os.Stderr, "Check NXDOMAIN:    %t\n", cfg.CheckNXDOMAIN)
	fmt.Fprintf(os.Stderr, "Check Rebinding:   %t\n", cfg.CheckRebinding)
	fmt.Fprintf(os.Stderr, "Check Dotcom:      %t\n", cfg.CheckDotcom)
	if cfg.AccuracyCheckFile != "" {
		fmt.Fprintf(os.Stderr,
			"Accuracy Check:    Enabled (File: %s, Using: %s -> %s)\n",
			cfg.AccuracyCheckFile,
			cfg.AccuracyCheckDomain,
			cfg.AccuracyCheckIP,
		)
	} else {
		fmt.Fprintln(os.Stderr, "Accuracy Check:    Disabled")
	}
	fmt.Fprintf(os.Stderr, "Include System DNS:%t\n", cfg.IncludeSystemDNS)
	fmt.Fprintf(os.Stderr, "Output Format:     %s\n", cfg.OutputFormat)
	if cfg.OutputFile != "" {
		fmt.Fprintf(os.Stderr, "Output File:       %s\n", cfg.OutputFile)
	}
	fmt.Fprintln(os.Stderr, "---------------------")
}

// readServerStringsFromFile reads server endpoints from a file.
func readServerStringsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		servers = append(servers, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no server endpoints found in file: %s", filePath)
	}
	return servers, nil
}

// isValidHostname performs a basic validation of a hostname string.
// It checks for general validity but does not guarantee DNS resolvability.
// Allows IPv4/IPv6 addresses, and hostnames according to RFC 1123/253.
func isValidHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return true
	} // Allow IPs

	// RFC 1123: labels can contain letters, digits, hyphen. Max 63 chars. Cannot start/end with hyphen.
	// Total length max 253.
	if len(hostname) > 253 {
		return false
	}

	labels := strings.Split(hostname, ".")
	if len(labels) == 1 && hostname != "localhost" {
		// Allow single label if it doesn't contain invalid chars and isn't all numeric (could be mistaken for IP)
		if strings.ContainsAny(hostname, " :/\\") {
			return false
		}
		// Check if purely numeric - this is a basic check and might incorrectly flag valid single-label names
		if _, err := strconv.Atoi(hostname); err == nil {
			return false
		}
		return true
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		} // Empty label or label too long
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false // Invalid label start/end
		}
		for _, r := range label {
			isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			isHyphen := r == '-'
			if !isLetter && !isDigit && !isHyphen {
				return false
			}
		}
	}
	return true
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// parseServerString parses a server endpoint string into a ServerInfo struct.
// It handles various formats including IP:port, Host:port, and URLs for DoH.
// It detects the protocol (UDP, TCP, DoT, DoH, DoQ) from the string prefix or scheme.
// Returns an error if the string is invalid or format is unrecognized.
func parseServerString(serverStr string) (ServerInfo, error) {
	serverStr = strings.TrimSpace(serverStr)
	if serverStr == "" {
		return ServerInfo{}, fmt.Errorf("server string cannot be empty or only whitespace")
	}

	protocol := UDP
	addrPart := serverStr
	if scheme, rest, ok := strings.Cut(serverStr, "://"); ok {
		addrPart = rest
		switch scheme {
		case "https":
			u, err := url.Parse(serverStr)
			if err != nil || u.Hostname() == "" || !isValidHostname(u.Hostname()) || u.User != nil || u.Fragment != "" {
				return ServerInfo{}, fmt.Errorf("invalid DoH URL %q", serverStr)
			}
			if u.Port() != "" {
				if err := validatePort(u.Port()); err != nil {
					return ServerInfo{}, err
				}
			}
			return ServerInfo{Address: serverStr, Protocol: DOH, Hostname: u.Hostname(), DoHPath: u.Path}, nil
		case "udp":
			protocol = UDP
		case "tcp":
			protocol = TCP
		case "tls":
			protocol = DOT
		case "quic":
			protocol = DOQ
		case "http":
			// Plaintext DoH is not supported; treating it as UDP would benchmark
			// something other than what the user asked for.
			return ServerInfo{}, fmt.Errorf("unsupported URI scheme %q (DoH requires https)", scheme)
		default:
			// Historical behaviour, kept for existing server files: warn and
			// fall back to UDP rather than dropping the entry.
			fmt.Fprintf(os.Stderr, "Warning: Unrecognized protocol scheme '%s' in '%s', assuming UDP.\n", scheme, serverStr)
		}
	}
	defaultPort := "53"
	if protocol == DOT || protocol == DOQ {
		defaultPort = "853"
	}
	port := defaultPort
	host := addrPart
	if h, p, err := net.SplitHostPort(addrPart); err == nil {
		host, port = h, p
		if !isNumeric(p) {
			// Historical behaviour: a non-numeric port falls back to the
			// protocol default with a warning. Numeric out-of-range ports
			// still fail below, as they could never have connected.
			fmt.Fprintf(os.Stderr, "Warning: Invalid port in '%s', using default port %s for host '%s'.\n", serverStr, defaultPort, h)
			port = defaultPort
		}
	} else if strings.HasPrefix(addrPart, "[") && strings.HasSuffix(addrPart, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(addrPart, "["), "]")
		if ip := net.ParseIP(host); ip == nil || ip.To4() != nil {
			return ServerInfo{}, fmt.Errorf("invalid bracketed IPv6 %q", addrPart)
		}
	} else if strings.Contains(addrPart, ":") && net.ParseIP(addrPart) == nil {
		return ServerInfo{}, fmt.Errorf("invalid address or port %q", addrPart)
	}
	if err := validatePort(port); err != nil {
		return ServerInfo{}, err
	}
	if !isValidHostname(host) || (net.ParseIP(host) == nil && !strings.Contains(host, ".")) {
		return ServerInfo{}, fmt.Errorf("invalid host %q", host)
	}
	return ServerInfo{Address: net.JoinHostPort(host, port), Protocol: protocol, Hostname: host}, nil
}

// parseAndDeduplicateServers parses a list of server endpoint strings,
// converts them to ServerInfo structs, and removes duplicate entries.
// Entries are deduplicated by protocol and address.
func parseAndDeduplicateServers(serverStrings []string) []ServerInfo {
	seen := make(map[string]struct{})
	result := make([]ServerInfo, 0)
	for _, s := range serverStrings {
		info, err := parseServerString(s)
		if err != nil {
			// Log the error and skip this server string entirely if parsing failed
			fmt.Fprintf(os.Stderr, "Warning: Skipping invalid server endpoint '%s': %v\n", s, err)
			continue // Skip adding this server
		}
		info.Metadata = catalog.Metadata{Provider: "custom", Profile: "custom", Roles: []string{"custom"}, FilteringPolicy: "unknown", ECS: "unknown", IPFamily: addressFamily(info.Hostname), Transport: string(info.Protocol), TLSServerName: customTLSServerName(info)}
		// Deduplicate entries by protocol+address, allowing same address under different protocols
		key := endpointKey(info)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, info)
		}
	}
	return result
}

// getSystemDNSServers attempts to retrieve system DNS resolver addresses.
// It currently supports Unix-like systems by reading /etc/resolv.conf.
// On Windows and if detection fails, it returns an error and an empty list.
// The returned server addresses are intended for UDP queries.
func getSystemDNSServers() ([]string, error) {
	// TODO: Implement system DNS detection for Windows (e.g., using registry or PowerShell).
	// TODO: Consider supporting non-UDP system resolvers if OS provides such info (e.g., DoH URL in some systems).
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("system DNS detection not implemented for Windows")
	}
	// Assumes /etc/resolv.conf for Unix-like systems
	const resolvConfPath = "/etc/resolv.conf"
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", resolvConfPath, err)
	}
	defer func() { _ = file.Close() }()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := resolvConfNameserverRegex.FindStringSubmatch(scanner.Text())
		if len(match) == 2 {
			ip := net.ParseIP(match[1])
			if ip != nil {
				servers = append(servers, match[1])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", resolvConfPath, err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no nameservers found in %s", resolvConfPath)
	}
	return servers, nil
}

// loadAccuracyCheckFile reads an accuracy check file to get a domain and expected IP.
// The file should have lines of 'domain IP[,IP...]', and the first valid entry is used.
// Invalid lines or IPs are skipped with warnings. Returns error if no valid entry is found.
func loadAccuracyCheckFile(filePath string) (domain string, ip string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			fmt.Fprintf(
				os.Stderr,
				"Warning: Skipping invalid format in accuracy file %s (line %d): %s\n",
				filePath,
				lineNumber,
				line,
			)
			continue
		}

		domainToCheck := strings.TrimSuffix(parts[0], ".") // Domain for validation
		ipToCheck := parts[1]
		validIPs := true
		for _, ip := range strings.Split(ipToCheck, ",") {
			if net.ParseIP(ip) == nil {
				validIPs = false
			}
		}
		if !validIPs {
			fmt.Fprintf(
				os.Stderr,
				"Warning: Skipping invalid IP in accuracy file %s (line %d): %s\n",
				filePath,
				lineNumber,
				ipToCheck,
			)
			continue
		}

		// Basic domain check using the validation function and ensure it contains a dot
		if !isValidHostname(domainToCheck) || !strings.Contains(domainToCheck, ".") {
			fmt.Fprintf(
				os.Stderr,
				"Warning: Skipping potentially invalid domain in accuracy file %s (line %d): %s\n",
				filePath,
				lineNumber,
				parts[0],
			)
			continue // Skip this line if domain is invalid
		}

		// If all checks passed for this line, return it as the first valid pair
		// Ensure returned domain has trailing dot
		return domainToCheck + ".", ipToCheck, nil
	}
	// If loop finishes without returning, check for scanner errors first
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	// If no scanner error and no valid line found, return the specific error
	return "", "", fmt.Errorf("no valid 'domain IP' pairs found in %s", filePath)
}

// customTLSServerName returns the name a custom -f endpoint authenticates as:
// its hostname for TLS transports (DoT, DoH, DoQ), and empty for plaintext
// transports or IP-literal hosts, which have no TLS name to report.
func customTLSServerName(info ServerInfo) string {
	switch info.Protocol {
	case DOT, DOH, DOQ:
		if net.ParseIP(info.Hostname) == nil {
			return info.Hostname
		}
	}
	return ""
}
