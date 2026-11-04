package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogSelection(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cfg   Config
		count int
		fail  bool
	}{
		{"bounded defaults", Config{}, 18, false},
		{"family IPv6", Config{Profiles: "cloudflare-family", IPFamily: "ipv6", Transports: "udp,dot,doh"}, 3, false},
		{"DoQ opt in", Config{Profiles: "adguard-default", IPFamily: "ipv4", Transports: "doq"}, 1, false},
		{"bad family", Config{IPFamily: "v5"}, 0, true},
		{"bad transport", Config{Transports: "doh3"}, 0, true},
		{"bad profile", Config{Profiles: "unknown"}, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := cfg.LoadServers()
			if tt.fail {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, cfg.Servers, tt.count)
			for _, s := range cfg.Servers {
				assert.NotEmpty(t, s.Provider)
				assert.NotEmpty(t, s.Profile)
				assert.NotEmpty(t, s.SourceURLs)
				if s.Protocol == DOT || s.Protocol == DOQ {
					assert.NotEqual(t, s.Hostname, s.TLSServerName)
				}
			}
		})
	}
}

func TestLegacyPresetKeepsAddressFormat(t *testing.T) {
	cfg := Config{}
	require.NoError(t, cfg.LoadServers())
	var addresses []string
	for _, s := range cfg.Servers {
		addresses = append(addresses, s.AddressString())
		assert.Contains(t, s.String(), s.EndpointID, "results key must stay unique per endpoint")
	}
	defaults, err := DefaultDNSStrings()
	require.NoError(t, err)
	var want []string
	for _, entry := range defaults {
		s, err := parseServerString(entry)
		require.NoError(t, err)
		want = append(want, s.AddressString())
	}
	assert.ElementsMatch(t, want, addresses)
	assert.Contains(t, addresses, "1.1.1.1:53")
	assert.Contains(t, addresses, "tls://one.one.one.one:853")
	assert.Contains(t, addresses, "https://cloudflare-dns.com/dns-query")
}

func TestLegacyFileMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.txt")
	require.NoError(t, os.WriteFile(path, []byte("# custom endpoints\n1.1.1.1\ntcp://[::1]:5353\ntls://resolver.example\nhttps://resolver.example/dns-query\nquic://resolver.example\n1.1.1.1\n"), 0600))
	cfg := Config{ServersFile: path, IncludeSystemDNS: true}
	require.NoError(t, cfg.LoadServers())
	assert.False(t, cfg.IncludeSystemDNS)
	assert.Len(t, cfg.Servers, 5)
	tlsNames := map[string]string{}
	for _, s := range cfg.Servers {
		assert.Equal(t, "custom", s.Provider)
		assert.Equal(t, "custom", s.Profile)
		tlsNames[s.AddressString()] = s.TLSServerName
	}
	// Plaintext transports have no TLS name to report.
	assert.Equal(t, map[string]string{
		"1.1.1.1:53":                         "",
		"tcp://[::1]:5353":                   "",
		"tls://resolver.example:853":         "resolver.example",
		"https://resolver.example/dns-query": "resolver.example",
		"quic://resolver.example:853":        "resolver.example",
	}, tlsNames)
}

func TestCustomTLSServerName(t *testing.T) {
	tests := []struct {
		entry string
		want  string
	}{
		{"tls://dns.example", "dns.example"},
		{"tls://1.1.1.1", ""},
		{"quic://[2606:4700::1111]", ""},
		{"https://1.1.1.1/dns-query", ""},
		{"https://dns.example/dns-query", "dns.example"},
		{"dns.example", ""},
		{"tcp://dns.example", ""},
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			info, err := parseServerString(tt.entry)
			require.NoError(t, err)
			assert.Equal(t, tt.want, customTLSServerName(info))
		})
	}
}

func TestLegacyFileSelectionErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.txt")
	require.NoError(t, os.WriteFile(path, []byte("1.1.1.1\ntls://dns.example\n"), 0600))
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"with preset", Config{ServersFile: path, Preset: "general"}, "-f cannot be combined"},
		{"with profile", Config{ServersFile: path, Profiles: "cloudflare-default"}, "-f cannot be combined"},
		{"filtered to nothing", Config{ServersFile: path, Transports: "doq"}, "no endpoints match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorContains(t, tt.cfg.LoadServers(), tt.wantErr)
		})
	}

	cfg := Config{ServersFile: path, Transports: "dot"}
	require.NoError(t, cfg.LoadServers())
	require.Len(t, cfg.Servers, 1)
	assert.Equal(t, DOT, cfg.Servers[0].Protocol)
}

func TestRejectMalformedEndpoints(t *testing.T) {
	tests := []struct {
		entry   string
		wantErr string
	}{
		{"http://dns.example", "DoH requires https"},
		{"1.1.1.1:0", "invalid port"},
		{"1.1.1.1:65536", "invalid port"},
		{"[::1", "invalid address or port"},
		{"[1.1.1.1]", "invalid bracketed IPv6"},
		{"[1.1.1.1]:53", "invalid bracketed IPv6"},
		{"tls://[1.1.1.1]:853", "invalid bracketed IPv6"},
		{"[1.1.1.1]:bad", "invalid bracketed IPv6"},
		{"[dns.example]:53", "invalid bracketed IPv6"},
		{"host.example:1:2", "invalid address or port"},
		{"https://dns.example:65536/dns-query", "invalid port"},
		{"https://user:pass@dns.example/dns-query", "invalid DoH URL"},
		{"https://dns.example/dns-query#frag", "invalid DoH URL"},
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			_, err := parseServerString(tt.entry)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestLegacyEndpointFallbacks pins the warn-and-salvage behaviour that existing
// server files rely on: unknown schemes become UDP and non-numeric ports fall
// back to the protocol default.
func TestLegacyEndpointFallbacks(t *testing.T) {
	tests := []struct {
		name         string
		entry        string
		wantAddress  string
		wantProtocol ProtocolType
	}{
		{"unknown scheme assumes UDP", "dns://1.2.3.4", "1.2.3.4:53", UDP},
		{"bogus scheme assumes UDP", "bogus://1.1.1.1", "1.1.1.1:53", UDP},
		{"non-numeric port uses default", "host.example:abc", "host.example:53", UDP},
		{"negative port uses default", "1.1.1.1:-1", "1.1.1.1:53", UDP},
		{"empty port uses default", "1.1.1.1:", "1.1.1.1:53", UDP},
		{"bad IPv6 port uses default", "[::1]:bad", "[::1]:53", UDP},
		{"bad DoT port uses DoT default", "tls://dns.example:x", "dns.example:853", DOT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseServerString(tt.entry)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAddress, info.Address)
			assert.Equal(t, tt.wantProtocol, info.Protocol)
		})
	}
}

func TestValidate(t *testing.T) {
	valid := func(c Config) Config {
		if c.OutputFormat == "" {
			c.OutputFormat = "console"
		}
		if c.QueryType == "" {
			c.QueryType = "A"
		}
		if c.Timeout == 0 {
			c.Timeout = 5 * time.Second
		}
		return c
	}
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"rebinding without domain", valid(Config{CheckRebinding: true}), "-rebinding-domain"},
		{"rebinding with blank domain", valid(Config{CheckRebinding: true, RebindingDomain: "  "}), "-rebinding-domain"},
		{"rebinding with domain", valid(Config{CheckRebinding: true, RebindingDomain: "private.example.net"}), ""},
		{"domain without rebinding", valid(Config{RebindingDomain: "private.example.net"}), ""},
		{"no checks", valid(Config{}), ""},
		{"json format any case", valid(Config{OutputFormat: "JSON"}), ""},
		{"csv format", valid(Config{OutputFormat: "csv"}), ""},
		{"unknown format", valid(Config{OutputFormat: "jsn"}), "unknown output format"},
		{"lower-case type", valid(Config{QueryType: "aaaa"}), ""},
		{"misspelt type", valid(Config{QueryType: "AAA"}), "unknown -type"},
		{"empty type", Config{OutputFormat: "console", Timeout: time.Second}, "unknown -type"},
		{"zero timeout", Config{OutputFormat: "console", QueryType: "A"}, "-t must be a positive duration"},
		{"negative timeout", valid(Config{Timeout: -time.Second}), "-t must be a positive duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSystemDNSDeduplicatedAgainstCatalogue(t *testing.T) {
	original := systemDNSServers
	t.Cleanup(func() { systemDNSServers = original })
	systemDNSServers = func() ([]string, error) { return []string{"1.1.1.1", "192.0.2.53"}, nil }

	cfg := Config{IncludeSystemDNS: true}
	require.NoError(t, cfg.LoadServers())

	counts := map[string]int{}
	var system []string
	for _, s := range cfg.Servers {
		counts[endpointKey(s)]++
		if s.Provider == "system" {
			system = append(system, s.Address)
		}
	}
	assert.Equal(t, 1, counts["udp|1.1.1.1:53"], "system resolver that matches a catalogue endpoint must not be benchmarked twice")
	assert.Equal(t, []string{"192.0.2.53:53"}, system)
}

func TestDefaultDNSStringsPopulated(t *testing.T) {
	entries, err := DefaultDNSStrings()
	require.NoError(t, err)
	assert.Len(t, entries, 18)
}

// TestServersFileFilteredByFamilyAndTransport checks that -ip-family and
// -transports also filter -f entries, and that hostnames take the forced family.
func TestServersFileFilteredByFamilyAndTransport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.txt")
	require.NoError(t, os.WriteFile(path, []byte("1.1.1.1\n2606:4700:4700::1111\ntls://dns.example\nquic://dns.example\n"), 0o600))
	tests := []struct {
		name       string
		family     string
		transports string
		want       []string
		wantFamily string
	}{
		{"auto keeps everything", "auto", "", []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53", "tls://dns.example:853", "quic://dns.example:853"}, ""},
		{"ipv4 drops IPv6 literals and pins hostnames", "ipv4", "", []string{"1.1.1.1:53", "tls://dns.example:853", "quic://dns.example:853"}, "ipv4"},
		{"ipv6 drops IPv4 literals", "ipv6", "", []string{"[2606:4700:4700::1111]:53", "tls://dns.example:853", "quic://dns.example:853"}, "ipv6"},
		{"transports filter", "auto", "dot,doq", []string{"tls://dns.example:853", "quic://dns.example:853"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{ServersFile: path, IPFamily: tt.family, Transports: tt.transports}
			require.NoError(t, cfg.LoadServers())
			var got []string
			for _, s := range cfg.Servers {
				got = append(got, s.AddressString())
				if tt.wantFamily != "" {
					assert.Equal(t, tt.wantFamily, s.IPFamily, s.AddressString())
				}
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestServersFileAllEntriesFilteredReportsCount checks that when -transports
// or -ip-family removes every -f entry, the error says how many were skipped
// instead of only "no endpoints match the selection".
func TestServersFileAllEntriesFilteredReportsCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.txt")
	require.NoError(t, os.WriteFile(path, []byte("1.1.1.1\n8.8.8.8\ntls://dns.example\n"), 0o600))
	tests := []struct {
		name       string
		family     string
		transports string
	}{
		{"transport filter removes all", "auto", "doh"},
		{"family filter removes all literals and the transport filter the rest", "ipv6", "udp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{ServersFile: path, IPFamily: tt.family, Transports: tt.transports}
			err := cfg.LoadServers()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "all 3 endpoint(s)")
			assert.Contains(t, err.Error(), "-transports/-ip-family")
		})
	}
}
