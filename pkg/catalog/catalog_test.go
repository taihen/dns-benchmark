package catalog

import (
	"os"
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
		{"malformed verification date", func(c *Catalog) { c.Profiles[0].LastVerified = "03/11/2026" }},
		{"invalid status", func(c *Catalog) { c.Profiles[0].Status = "retired" }},
		{"misspelled role", func(c *Catalog) { c.Profiles[0].Roles = []string{"securty"} }},
		{"unknown filtering policy token", func(c *Catalog) { c.Profiles[0].FilteringPolicy = "malware+adlut" }},
		{"unknown ECS value", func(c *Catalog) { c.Profiles[0].ECS = "on" }},
		{"unknown DNSSEC claim", func(c *Catalog) { c.Profiles[0].DNSSECClaim = "yes" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Load()
			require.NoError(t, err)
			tt.mutate(c)
			assert.Error(t, c.Validate())
		})
	}
}

// TestCatalogFreshness depends on the wall clock, so it only runs when
// DNSBENCH_CHECK_CATALOG_FRESHNESS is set (see the scheduled catalogue-freshness
// workflow). Running it on every PR would start failing unrelated changes once
// the catalogue ages past MaxReviewAge.
func TestCatalogFreshness(t *testing.T) {
	if os.Getenv("DNSBENCH_CHECK_CATALOG_FRESHNESS") == "" {
		t.Skip("set DNSBENCH_CHECK_CATALOG_FRESHNESS=1 to check catalogue review dates against today")
	}
	c, err := Load()
	require.NoError(t, err)
	// Maintenance reminder: this fails once the embedded catalogue needs re-verification.
	assert.NoError(t, c.CheckFreshness(time.Now()))
}

func TestCheckFreshnessDoesNotAffectLoading(t *testing.T) {
	verified := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		status    string
		now       time.Time
		wantStale bool
	}{
		{"fresh", "active", verified.Add(30 * 24 * time.Hour), false},
		{"boundary", "active", verified.Add(MaxReviewAge), false},
		{"stale active", "active", verified.Add(MaxReviewAge + 24*time.Hour), true},
		{"stale deprecated", "deprecated", verified.Add(MaxReviewAge + 24*time.Hour), false},
		{"clock behind", "active", verified.Add(-48 * time.Hour), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Load()
			require.NoError(t, err)
			c.Profiles[0].Status = tt.status
			c.Profiles[0].LastVerified = verified.Format("2006-01-02")
			for i := 1; i < len(c.Profiles); i++ {
				c.Profiles[i].Status = "deprecated" // isolate the profile under test
			}
			assert.NoError(t, c.Validate(), "freshness must never fail structural validation")
			err = c.CheckFreshness(tt.now)
			if tt.wantStale {
				assert.ErrorContains(t, err, c.Profiles[0].ID)
			} else {
				assert.NoError(t, err)
			}
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
