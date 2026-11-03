package catalog

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedCatalog(t *testing.T) {
	c, err := Load()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(c.Profiles), 30)
	profiles, err := c.Select("legacy", "")
	require.NoError(t, err)
	assert.Len(t, profiles, 6)
	for _, p := range c.Profiles {
		assert.NotContains(t, p.ID, "mullvad")
	}
}

func TestCatalogRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Catalog)
	}{
		{"duplicate profile", func(c *Catalog) { c.Profiles[1].ID = c.Profiles[0].ID }},
		{"duplicate endpoint", func(c *Catalog) { c.Profiles[0].Endpoints[1].ID = c.Profiles[0].Endpoints[0].ID }},
		{"missing sources", func(c *Catalog) { c.Profiles[0].SourceURLs = nil }},
		{"IP TLS name", func(c *Catalog) { c.Profiles[0].Endpoints[2].TLSServerName = "1.1.1.1" }},
		{"bad URL", func(c *Catalog) { c.Profiles[0].Endpoints[3].URL = "http://example.com/dns-query" }},
		{"unsupported protocol", func(c *Catalog) { c.Profiles[0].Endpoints[0].Protocol = "doh3" }},
		{"unsupported claim", func(c *Catalog) { c.Profiles[0].Protocols = append(c.Profiles[0].Protocols, "dnscrypt") }},
		{"invalid family", func(c *Catalog) { c.Profiles[0].Endpoints[0].Family = "ipv6" }},
		{"bad port", func(c *Catalog) { c.Profiles[0].Endpoints[0].Port = 65536 }},
		{"stale", func(c *Catalog) { c.Profiles[0].LastVerified = "2020-01-01" }},
		{"invalid status", func(c *Catalog) { c.Profiles[0].Status = "retired" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Load()
			require.NoError(t, err)
			tt.mutate(c)
			assert.Error(t, c.Validate(time.Now()))
		})
	}
}

func TestSelectProfiles(t *testing.T) {
	for _, tt := range []struct {
		preset, ids string
		fail        bool
	}{
		{"general", "", false}, {"security", "", false}, {"family", "", false}, {"extended", "cloudflare-family", false}, {"bogus", "", true}, {"legacy", "bogus", true},
	} {
		t.Run(tt.preset+tt.ids, func(t *testing.T) {
			c, err := Load()
			require.NoError(t, err)
			p, err := c.Select(tt.preset, tt.ids)
			if tt.fail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, p)
			}
		})
	}
	c, err := Load()
	require.NoError(t, err)
	c.Profiles[0].Status = "deprecated"
	profiles, err := c.Select("extended", "")
	require.NoError(t, err)
	for _, p := range profiles {
		assert.NotEqual(t, c.Profiles[0].ID, p.ID)
	}
	_, err = c.Select("extended", c.Profiles[0].ID)
	assert.Error(t, err)
}
