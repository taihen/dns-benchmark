package config

import (
	"os"
	"path/filepath"
	"testing"

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
	for _, entry := range []string{"http://dns.example", "1.1.1.1:0", "1.1.1.1:65536", "[::1", "[1.1.1.1]", "https://dns.example:65536/dns-query", "https://user:pass@dns.example/dns-query"} {
		t.Run(entry, func(t *testing.T) { _, err := parseServerString(entry); assert.Error(t, err) })
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

func TestValidateChecks(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"rebinding without domain", Config{CheckRebinding: true}, true},
		{"rebinding with blank domain", Config{CheckRebinding: true, RebindingDomain: "  "}, true},
		{"rebinding with domain", Config{CheckRebinding: true, RebindingDomain: "private.example.net"}, false},
		{"domain without rebinding", Config{RebindingDomain: "private.example.net"}, false},
		{"no checks", Config{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateChecks()
			if tt.wantErr {
				assert.ErrorContains(t, err, "-rebinding-domain")
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
