package config

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv" // Added strconv import
	"strings"
	"time"
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
	Address  string // For UDP/TCP/DoT/DoQ: IP:Port or Host:Port. For DoH: Full URL.
	Protocol ProtocolType
	Hostname string // Hostname for TLS SNI / DoH URL host. Should NOT contain brackets for IPv6.
	DoHPath  string // Path for DoH endpoint (e.g., /dns-query).
}

// String representation for ServerInfo, used for display and deduplication keys.
func (si ServerInfo) String() string {
	switch si.Protocol {
	case DOH:
		return si.Address // DoH address is the full URL
	case DOT:
		// Use Hostname for DoT if it's not an IP, otherwise use Address (which includes port)
		if si.Hostname != "" && net.ParseIP(si.Hostname) == nil {
			_, port, err := net.SplitHostPort(si.Address)
			if err != nil {
				port = "853"
			} // Default DoT port
			return fmt.Sprintf("tls://%s", net.JoinHostPort(si.Hostname, port))
		}
		return fmt.Sprintf("tls://%s", si.Address) // Fallback to using Address
	case DOQ:
		// Use Hostname for DoQ if it's not an IP, otherwise use Address
		if si.Hostname != "" && net.ParseIP(si.Hostname) == nil {
			_, port, err := net.SplitHostPort(si.Address)
			if err != nil {
				port = "853"
			} // Default DoQ port
			return fmt.Sprintf("quic://%s", net.JoinHostPort(si.Hostname, port))
		}
		return fmt.Sprintf("quic://%s", si.Address)
	case TCP:
		return fmt.Sprintf("tcp://%s", si.Address)
	default: // UDP
		return si.Address
	}
}

var resolvConfNameserverRegex = regexp.MustCompile(`^\s*nameserver\s+([^\s]+)\s*$`)

// Config holds the application configuration derived from flags and files.
type Config struct {
	ServersFile         string
	Servers             []ServerInfo
	NumQueries          int
	Timeout             time.Duration
	Concurrency         int
	RateLimit           int
	QueryType           string
	Domain              string // Domain for cached latency tests
	CheckDNSSEC         bool
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
}

// DefaultDNSStrings provides a list of common public DNS endpoints.
var DefaultDNSStrings = []string{
	// Cloudflare
	"1.1.1.1",
	"tls://1.1.1.1",
	"https://cloudflare-dns.com/dns-query",
	// Google
	"8.8.8.8",
	"tls://8.8.8.8",
	"https://dns.google/dns-query",
	// Quad9
	"9.9.9.9",
	"tls://9.9.9.9",
	"https://dns.quad9.net/dns-query",
	// OpenDNS
	"208.67.222.222",
	"tls://dns.opendns.com", // Uses hostname
	"https://doh.opendns.com/dns-query",
	// AdGuard DNS (Default)
	"94.140.14.14",
	"tls://dns.adguard-dns.com",
	"https://dns.adguard-dns.com/dns-query",
	"quic://dns.adguard-dns.com",
}

// LoadConfig parses flags, reads files, and returns the final configuration.
func LoadConfig() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ServersFile, "f", "", "Path to file with DNS server endpoints (one per line: IP, tcp://IP, tls://IP, https://..., quic://IP)")
	flag.IntVar(&cfg.NumQueries, "n", 4, "Number of latency queries per server (min 2 for stddev)")
	flag.DurationVar(&cfg.Timeout, "t", 5*time.Second, "Query timeout")
	flag.IntVar(&cfg.Concurrency, "c", 4, "Max concurrent queries/checks")
	flag.IntVar(&cfg.RateLimit, "rate", 50, "Max queries per second (0 for unlimited)")
	flag.StringVar(&cfg.QueryType, "type", "A", "DNS record type for latency queries")
	flag.StringVar(&cfg.Domain, "domain", "example.com", "Domain for cached latency test")
	flag.BoolVar(&cfg.CheckDNSSEC, "dnssec", false, "Check for DNSSEC support")
	flag.BoolVar(&cfg.CheckNXDOMAIN, "nxdomain", false, "Check for NXDOMAIN hijacking")
	flag.BoolVar(&cfg.CheckRebinding, "rebinding", false, "Check for DNS rebinding protection")
	flag.BoolVar(&cfg.CheckDotcom, "dotcom", false, "Perform '.com' TLD lookup time check")
	flag.StringVar(&cfg.AccuracyCheckFile, "accuracy-file", "", "Path to file for accuracy check (domain IP per line, uses first valid entry)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Enable verbose output")
	flag.StringVar(&cfg.OutputFile, "o", "", "Path to output file (CSV/JSON)")
	flag.StringVar(&cfg.OutputFormat, "format", "console", "Output format (console, csv, json)")
	flag.BoolVar(&cfg.IncludeSystemDNS, "system", true, "Include system DNS servers (UDP only)")

	flag.Parse()

	// Load accuracy check data first
	if cfg.AccuracyCheckFile != "" {
		domain, ip, err := loadAccuracyCheckFile(cfg.AccuracyCheckFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not load accuracy check file %s: %v. Disabling check.\n", cfg.AccuracyCheckFile, err)
			cfg.AccuracyCheckFile = ""
		} else {
			cfg.AccuracyCheckDomain = domain
			cfg.AccuracyCheckIP = ip
		}
	}

	// Determine initial server list
	var serverListInput []string
	if cfg.ServersFile != "" {
		servers, err := readServerStringsFromFile(cfg.ServersFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading servers file %s: %v\n", cfg.ServersFile, err)
			os.Exit(1)
		}
		serverListInput = servers
		cfg.IncludeSystemDNS = false // Disable system DNS if file is provided
	} else {
		serverListInput = DefaultDNSStrings
	}

	// Add system DNS if requested
	if cfg.IncludeSystemDNS && cfg.ServersFile == "" {
		systemServers, err := getSystemDNSServers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not detect system DNS servers: %v\n", err)
		} else {
			serverListInput = append(serverListInput, systemServers...)
		}
	}

	// Parse and deduplicate the final list
	cfg.Servers = parseAndDeduplicateServers(serverListInput)

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

// printVerboseConfig prints the configuration details.
func printVerboseConfig(cfg *Config) {
	fmt.Println("--- Configuration ---")
	fmt.Printf("Servers File:      %s\n", cfg.ServersFile)
	fmt.Printf("Servers Processed: %v\n", cfg.Servers)
	fmt.Printf("Num Queries:       %d\n", cfg.NumQueries)
	fmt.Printf("Timeout:           %v\n", cfg.Timeout)
	fmt.Printf("Concurrency:       %d\n", cfg.Concurrency)
	fmt.Printf("Rate Limit:        %d qps\n", cfg.RateLimit)
	fmt.Printf("Query Type:        %s\n", cfg.QueryType)
	fmt.Printf("Cached Domain:     %s\n", cfg.Domain)
	fmt.Printf("Check DNSSEC:      %t\n", cfg.CheckDNSSEC)
	fmt.Printf("Check NXDOMAIN:    %t\n", cfg.CheckNXDOMAIN)
	fmt.Printf("Check Rebinding:   %t\n", cfg.CheckRebinding)
	fmt.Printf("Check Dotcom:      %t\n", cfg.CheckDotcom)
	if cfg.AccuracyCheckFile != "" {
		fmt.Printf("Accuracy Check:    Enabled (File: %s, Using: %s -> %s)\n", cfg.AccuracyCheckFile, cfg.AccuracyCheckDomain, cfg.AccuracyCheckIP)
	} else {
		fmt.Println("Accuracy Check:    Disabled")
	}
	fmt.Printf("Include System DNS:%t\n", cfg.IncludeSystemDNS)
	fmt.Printf("Output Format:     %s\n", cfg.OutputFormat)
	if cfg.OutputFile != "" {
		fmt.Printf("Output File:       %s\n", cfg.OutputFile)
	}
	fmt.Println("---------------------")
}

// readServerStringsFromFile reads server endpoints from a file.
func readServerStringsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

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
			if !(isLetter || isDigit || isHyphen) {
				return false
			}
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

	// Handle DoH separately as it's a full URL
	if strings.HasPrefix(serverStr, "https://") {
		u, err := url.Parse(serverStr)
		if err != nil {
			return ServerInfo{}, fmt.Errorf("invalid DoH URL '%s': %w", serverStr, err)
		}
		if u.Scheme != "https" {
			return ServerInfo{}, fmt.Errorf("invalid DoH URL scheme in '%s': must be https", serverStr)
		}
		host := u.Hostname()
		if host == "" {
			return ServerInfo{}, fmt.Errorf("invalid DoH URL (missing or invalid host): '%s'", serverStr)
		}
		if !isValidHostname(host) {
			return ServerInfo{}, fmt.Errorf("invalid hostname '%s' in DoH URL '%s'", host, serverStr)
		}
		return ServerInfo{Address: serverStr, Protocol: DOH, Hostname: host, DoHPath: u.Path}, nil
	}

	// Handle other protocols (UDP, TCP, DoT, DoQ)
	var protocol ProtocolType
	var defaultPort string
	addrPart := serverStr // The part potentially containing host/IP and port

	// Detect protocol and strip prefix
	if strings.HasPrefix(addrPart, "tls://") {
		protocol = DOT
		defaultPort = "853"
		addrPart = strings.TrimPrefix(addrPart, "tls://")
	} else if strings.HasPrefix(addrPart, "quic://") {
		protocol = DOQ
		defaultPort = "853"
		addrPart = strings.TrimPrefix(addrPart, "quic://")
	} else if strings.HasPrefix(addrPart, "tcp://") {
		protocol = TCP
		defaultPort = "53"
		addrPart = strings.TrimPrefix(addrPart, "tcp://")
	} else {
		protocol = UDP // Default
		defaultPort = "53"
		// Check for accidental schemes like http://, but ignore if it looks like IPv6
		if i := strings.Index(addrPart, "://"); i != -1 && !strings.Contains(addrPart[:i], ":") {
			if addrPart[:i] != "udp" { // Allow explicit udp://
				fmt.Fprintf(os.Stderr, "Warning: Unrecognized protocol scheme '%s' in '%s', assuming UDP.\n", addrPart[:i], serverStr)
			}
			addrPart = addrPart[i+3:]
		}
	}

	// Now addrPart should be host, ip, [ipv6], host:port, ip:port, or [ipv6]:port
	host, port, err := net.SplitHostPort(addrPart)
	hostname := "" // Hostname for SNI/validation

	if err == nil {
		// Successfully split host and port
		hostname = host
		// Remove brackets for hostname if IPv6 literal
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			hostname = strings.Trim(host, "[]")
		}
	} else {
		// Error likely means no port was specified or format is invalid.
		host = addrPart // Assume the whole part is the host/IP
		port = defaultPort
		hostname = host // Use the assumed host as hostname initially
		// Remove brackets for hostname if IPv6 literal was passed without port
		if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
			hostname = strings.Trim(hostname, "[]")
		}
		// Check if the failure was due to a bad port string (e.g., "host:bad")
		// and try to salvage the host part if it looks valid.
		// We need to re-check the original addrPart because 'hostname' might have brackets removed.
		if strings.Contains(addrPart, ":") {
			// If it wasn't a valid IPv6 literal that failed SplitHostPort...
			if ip := net.ParseIP(hostname); ip == nil || ip.To4() != nil {
				parts := strings.SplitN(addrPart, ":", 2)
				// Check if the salvaged part looks like a valid host
				if len(parts) == 2 && isValidHostname(parts[0]) {
					host = parts[0]     // Use the salvaged part for JoinHostPort
					hostname = parts[0] // Use the salvaged part for Hostname field
					fmt.Fprintf(os.Stderr, "Warning: Invalid port in '%s', using default port %s for host '%s'.\n", serverStr, port, host)
				}
			}
		}
	}

	// Final validation of the derived hostname
	if !isValidHostname(hostname) {
		// Special case: if the original input was just an IPv6 without brackets, it's valid
		// Check addrPart directly here, as hostname might have been trimmed
		if ip := net.ParseIP(addrPart); ip != nil && ip.To4() == nil {
			hostname = addrPart // Use the original IPv6 string as hostname
			host = addrPart     // Use the original IPv6 string for JoinHostPort
		} else {
			return ServerInfo{}, fmt.Errorf("invalid host/IP address derived from '%s': %s", serverStr, hostname)
		}
	}

	// JoinHostPort handles adding brackets for IPv6 automatically if needed
	// Ensure 'host' used here is the correct part (potentially salvaged, or original if no port)
	// For IPv6, 'host' should NOT have brackets when passed to JoinHostPort if SplitHostPort failed.
	// However, if SplitHostPort succeeded, 'host' might already have brackets.
	// net.JoinHostPort correctly handles both bracketed and non-bracketed IPv6 hosts.
	finalAddr := net.JoinHostPort(host, port)
	return ServerInfo{Address: finalAddr, Protocol: protocol, Hostname: hostname}, nil
}

// parseAndDeduplicateServers parses a list of server endpoint strings,
// converts them to ServerInfo structs, and removes duplicate entries.
// Deduplication is based on the String() representation of ServerInfo.
func parseAndDeduplicateServers(serverStrings []string) []ServerInfo {
	seen := make(map[string]struct{})
	var result []ServerInfo
	for _, s := range serverStrings {
		info, err := parseServerString(s)
		if err != nil {
			// Log the error and skip this server string entirely if parsing failed
			fmt.Fprintf(os.Stderr, "Warning: Skipping invalid server endpoint '%s': %v\n", s, err)
			continue // Skip adding this server
		}
		key := info.String() // Use String() method for deduplication key
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
	defer file.Close()

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
// The file should have lines of 'domain IP', and the first valid entry is used.
// Invalid lines or IPs are skipped with warnings. Returns error if no valid entry is found.
func loadAccuracyCheckFile(filePath string) (domain string, ip string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

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
			fmt.Fprintf(os.Stderr, "Warning: Skipping invalid format in accuracy file %s (line %d): %s\n", filePath, lineNumber, line)
			continue
		}

		domainToCheck := strings.TrimSuffix(parts[0], ".") // Domain for validation
		ipToCheck := parts[1]

		parsedIP := net.ParseIP(ipToCheck)
		if parsedIP == nil {
			fmt.Fprintf(os.Stderr, "Warning: Skipping invalid IP in accuracy file %s (line %d): %s\n", filePath, lineNumber, ipToCheck)
			continue
		}

		// Basic domain check using the validation function
		if !isValidHostname(domainToCheck) {
			fmt.Fprintf(os.Stderr, "Warning: Skipping potentially invalid domain in accuracy file %s (line %d): %s\n", filePath, lineNumber, parts[0])
			continue // Skip this line if domain is invalid
		}

		// If all checks passed for this line, return it as the first valid pair
		// Ensure returned domain has trailing dot
		return domainToCheck + ".", parsedIP.String(), nil
	}
	// If loop finishes without returning, check for scanner errors first
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	// If no scanner error and no valid line found, return the specific error
	return "", "", fmt.Errorf("no valid 'domain IP' pairs found in %s", filePath)
}
