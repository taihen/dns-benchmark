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
	Hostname string // Hostname for TLS SNI / DoH URL host.
	DoHPath  string // Path for DoH endpoint (e.g., /dns-query).
}

// String representation for ServerInfo, used for display and deduplication keys.
func (si ServerInfo) String() string {
	switch si.Protocol {
	case DOH:
		return si.Address
	case DOT:
		return fmt.Sprintf("tls://%s", si.Address)
	case DOQ:
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

	// Define flags
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

// parseServerString parses a string endpoint into a ServerInfo struct, handling various protocols and formats.
func parseServerString(serverStr string) (ServerInfo, error) {
	serverStr = strings.TrimSpace(serverStr)
	if strings.HasPrefix(serverStr, "https://") {
		u, err := url.Parse(serverStr)
		if err != nil {
			return ServerInfo{}, fmt.Errorf("invalid DoH URL '%s': %w", serverStr, err)
		}
		if u.Scheme != "https" {
			return ServerInfo{}, fmt.Errorf("invalid DoH URL scheme '%s': must be https", serverStr)
		}
		host := u.Hostname()
		return ServerInfo{Address: serverStr, Protocol: DOH, Hostname: host, DoHPath: u.Path}, nil
	} else if strings.HasPrefix(serverStr, "tls://") {
		addr := strings.TrimPrefix(serverStr, "tls://")
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host, port = addr, "853"
		} // Default DoT port
		addr = net.JoinHostPort(host, port)
		return ServerInfo{Address: addr, Protocol: DOT, Hostname: host}, nil
	} else if strings.HasPrefix(serverStr, "quic://") {
		addr := strings.TrimPrefix(serverStr, "quic://")
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host, port = addr, "853"
		} // Default DoQ port
		addr = net.JoinHostPort(host, port)
		return ServerInfo{Address: addr, Protocol: DOQ, Hostname: host}, nil
	} else if strings.HasPrefix(serverStr, "tcp://") {
		addr := strings.TrimPrefix(serverStr, "tcp://")
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host, port = addr, "53"
		} // Default DNS port
		addr = net.JoinHostPort(host, port)
		return ServerInfo{Address: addr, Protocol: TCP, Hostname: host}, nil
	} else { // Assume UDP
		addr := serverStr
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host, port = addr, "53"
		} // Default DNS port
		addr = net.JoinHostPort(host, port)
		return ServerInfo{Address: addr, Protocol: UDP, Hostname: host}, nil
	}
}

// parseAndDeduplicateServers parses string endpoints and removes duplicates.
func parseAndDeduplicateServers(serverStrings []string) []ServerInfo {
	seen := make(map[string]struct{})
	var result []ServerInfo
	for _, s := range serverStrings {
		info, err := parseServerString(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Skipping invalid server endpoint '%s': %v\n", s, err)
			continue
		}
		key := info.String()
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, info)
		}
	}
	return result
}

// getSystemDNSServers attempts to read system DNS servers (returns IPs only for UDP).
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

// loadAccuracyCheckFile reads a file with 'domain IP' per line and returns the first valid pair.
func loadAccuracyCheckFile(filePath string) (domain string, ip string, err error) {
	// TODO: Allow multiple domain/IP pairs for accuracy check? Currently uses first valid one.
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

		domain = strings.TrimSuffix(parts[0], ".") + "." // Ensure FQDN
		ip = parts[1]

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			fmt.Fprintf(os.Stderr, "Warning: Skipping invalid IP in accuracy file %s (line %d): %s\n", filePath, lineNumber, ip)
			continue
		}
		// Basic domain check
		if !strings.Contains(domain, ".") || len(domain) < 3 {
			fmt.Fprintf(os.Stderr, "Warning: Skipping potentially invalid domain in accuracy file %s (line %d): %s\n", filePath, lineNumber, domain)
			continue
		}
		return domain, parsedIP.String(), nil // Return first valid pair
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	return "", "", fmt.Errorf("no valid 'domain IP' pairs found in %s", filePath)
}
