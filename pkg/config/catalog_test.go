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

func TestLegacyFileMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.txt")
	require.NoError(t, os.WriteFile(path, []byte("# custom endpoints\n1.1.1.1\ntcp://[::1]:5353\ntls://resolver.example\nhttps://resolver.example/dns-query\nquic://resolver.example\n1.1.1.1\n"), 0600))
	cfg := Config{ServersFile: path, IncludeSystemDNS: true}
	require.NoError(t, cfg.LoadServers())
	assert.False(t, cfg.IncludeSystemDNS)
	assert.Len(t, cfg.Servers, 5)
	for _, s := range cfg.Servers {
		assert.Equal(t, "custom", s.Provider)
		assert.Equal(t, "custom", s.Profile)
	}
}

func TestRejectMalformedEndpoints(t *testing.T) {
	for _, entry := range []string{"http://dns.example", "bogus://1.1.1.1", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:-1", "[::1]:bad", "[::1", "[1.1.1.1]", "https://dns.example:65536/dns-query", "https://user:pass@dns.example/dns-query"} {
		t.Run(entry, func(t *testing.T) { _, err := parseServerString(entry); assert.Error(t, err) })
	}
}
