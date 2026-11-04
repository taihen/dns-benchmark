// Package catalog contains the versioned, documented public resolver catalogue.
package catalog

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed resolvers.json
var embedded []byte

// Catalog is a versioned collection of resolver profiles.
type Catalog struct {
	Version  string            `json:"version"`
	Profiles []ResolverProfile `json:"profiles"`
}

// ResolverProfile describes provider policy independently of transport.
type ResolverProfile struct {
	FilteringProbeDomains []string   `json:"filteringProbeDomains,omitempty"`
	ID                    string     `json:"id"`
	Provider              string     `json:"provider"`
	DisplayName           string     `json:"displayName"`
	Roles                 []string   `json:"roles"`
	FilteringPolicy       string     `json:"filteringPolicy"`
	ECS                   string     `json:"ecs"`
	DNSSECClaim           string     `json:"dnssecClaim"`
	Protocols             []string   `json:"protocols"`
	Endpoints             []Endpoint `json:"endpoints"`
	SourceURLs            []string   `json:"sourceURLs"`
	LastVerified          string     `json:"lastVerified"`
	// Status is "active" or "deprecated"; deprecated profiles are never selected.
	Status string `json:"status"`
	// Legacy marks profiles that belong to the default legacy preset.
	Legacy bool `json:"legacy,omitempty"`
}

// Endpoint separates a connection target from its authenticated TLS name.
type Endpoint struct {
	ID            string `json:"id"`
	Protocol      string `json:"protocol"`
	Address       string `json:"address"` // Empty for DoH: resolve URL hostname within Family.
	URL           string `json:"url,omitempty"`
	Port          int    `json:"port"`
	Family        string `json:"family"`
	TLSServerName string `json:"tlsServerName,omitempty"`
}

// Load decodes and structurally validates the embedded catalogue without making
// network requests. Review freshness is deliberately not enforced here so that a
// released binary keeps working after its catalogue ages; see CheckFreshness.
func Load() (*Catalog, error) {
	var c Catalog
	decoder := json.NewDecoder(bytes.NewReader(embedded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode catalogue: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("embedded resolver catalogue %s is invalid: %w", c.Version, err)
	}
	return &c, nil
}

// Allowed values for policy metadata. Rankings and presets group on these
// fields, so a misspelling would silently move a profile into its own group or
// drop it from a preset; Validate rejects anything not listed here.
var (
	validRoles             = []string{"general", "security", "family", "ads", "social"}
	validECS               = []string{"enabled", "disabled", "unknown"}
	validDNSSECClaims      = []string{"validating", "unknown"}
	validFilteringPolicies = []string{"unfiltered", "uncensored", "malware", "security", "configurable", "ads", "trackers", "adult", "family", "child", "social", "legal", "legal-only", "proxy", "mixed-content"}
)

func validFilteringPolicy(policy string) bool {
	for _, token := range strings.Split(policy, "+") {
		if !slices.Contains(validFilteringPolicies, token) {
			return false
		}
	}
	return true
}

func validName(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

// Validate checks identifiers, provenance, lifecycle, families and transport claims.
// It is independent of the current time; review freshness is checked separately
// by CheckFreshness.
func (c *Catalog) Validate() error {
	if c.Version == "" || len(c.Profiles) == 0 {
		return fmt.Errorf("catalogue requires version and profiles")
	}
	ids := map[string]bool{}
	for _, p := range c.Profiles {
		if p.ID == "" || ids[p.ID] {
			return fmt.Errorf("duplicate or empty profile ID %q", p.ID)
		}
		ids[p.ID] = true
		if p.Provider == "" || p.DisplayName == "" || len(p.Roles) == 0 || p.FilteringPolicy == "" || p.ECS == "" || p.DNSSECClaim == "" || len(p.SourceURLs) == 0 || len(p.Endpoints) == 0 || len(p.Protocols) == 0 {
			return fmt.Errorf("incomplete metadata for %s", p.ID)
		}
		for _, role := range p.Roles {
			if !slices.Contains(validRoles, role) {
				return fmt.Errorf("unknown role %q for %s", role, p.ID)
			}
		}
		if !validFilteringPolicy(p.FilteringPolicy) {
			return fmt.Errorf("unknown filtering policy %q for %s", p.FilteringPolicy, p.ID)
		}
		if !slices.Contains(validECS, p.ECS) {
			return fmt.Errorf("unknown ECS value %q for %s", p.ECS, p.ID)
		}
		if !slices.Contains(validDNSSECClaims, p.DNSSECClaim) {
			return fmt.Errorf("unknown DNSSEC claim %q for %s", p.DNSSECClaim, p.ID)
		}
		if p.Status != "active" && p.Status != "deprecated" {
			return fmt.Errorf("invalid status for %s", p.ID)
		}
		if _, err := time.Parse("2006-01-02", p.LastVerified); err != nil {
			return fmt.Errorf("invalid verification date for %s", p.ID)
		}
		for _, source := range p.SourceURLs {
			u, err := url.Parse(source)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" {
				return fmt.Errorf("invalid source for %s", p.ID)
			}
		}
		for _, protocol := range p.Protocols {
			if !slices.Contains([]string{"udp", "tcp", "dot", "doh", "doq"}, protocol) {
				return fmt.Errorf("unsupported protocol %s", protocol)
			}
		}
		for _, e := range p.Endpoints {
			if e.ID == "" || ids[e.ID] {
				return fmt.Errorf("duplicate or empty endpoint ID %q", e.ID)
			}
			ids[e.ID] = true
			if !slices.Contains(p.Protocols, e.Protocol) {
				return fmt.Errorf("undocumented protocol for %s", e.ID)
			}
			if e.Port < 1 || e.Port > 65535 {
				return fmt.Errorf("invalid port for %s", e.ID)
			}
			ip := net.ParseIP(e.Address)
			if (e.Family != "ipv4" && e.Family != "ipv6") || (e.Protocol != "doh" && (ip == nil || (ip.To4() != nil) != (e.Family == "ipv4"))) || (e.Protocol == "doh" && e.Address != "") {
				return fmt.Errorf("invalid address/family for %s", e.ID)
			}
			if e.Protocol == "dot" || e.Protocol == "doq" || e.Protocol == "doh" {
				if !validName(e.TLSServerName) {
					return fmt.Errorf("invalid TLS name for %s", e.ID)
				}
			}
			if e.Protocol == "doh" {
				u, err := url.Parse(e.URL)
				if err != nil || u.Scheme != "https" || u.Hostname() != e.TLSServerName || u.Path == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
					return fmt.Errorf("invalid DoH URL for %s", e.ID)
				}
				urlPort := 443
				if u.Port() != "" {
					urlPort, err = strconv.Atoi(u.Port())
					if err != nil {
						return fmt.Errorf("invalid DoH URL port for %s", e.ID)
					}
				}
				if urlPort != e.Port {
					return fmt.Errorf("DoH URL port %d does not match port %d for %s", urlPort, e.Port, e.ID)
				}
			}
		}
	}
	return nil
}

// MaxReviewAge is how long an active profile may go without re-verification
// before CheckFreshness reports it as stale.
const MaxReviewAge = 366 * 24 * time.Hour

// CheckFreshness reports active profiles whose lastVerified date is older than
// MaxReviewAge or later than now (plus one day of clock tolerance). It is a
// maintenance check for tests and CI, and a warning at runtime, never a reason
// to refuse to run.
func (c *Catalog) CheckFreshness(now time.Time) error {
	var stale []string
	for _, p := range c.Profiles {
		if p.Status != "active" {
			continue
		}
		verified, err := time.Parse("2006-01-02", p.LastVerified)
		if err != nil || verified.After(now.Add(24*time.Hour)) || now.Sub(verified) > MaxReviewAge {
			stale = append(stale, p.ID)
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("catalogue %s has profiles not verified within %d days of %s: %s", c.Version, int(MaxReviewAge.Hours()/24), now.Format("2006-01-02"), strings.Join(stale, ", "))
	}
	return nil
}

// Select returns active profiles matching a preset or explicit comma-separated IDs.
func (c *Catalog) Select(preset, profiles string) ([]ResolverProfile, error) {
	if !slices.Contains([]string{"legacy", "general", "security", "family", "extended"}, preset) {
		return nil, fmt.Errorf("unknown preset %q", preset)
	}
	requested := map[string]bool{}
	if profiles != "" {
		for _, id := range strings.Split(profiles, ",") {
			requested[strings.TrimSpace(id)] = false
		}
	}
	var result []ResolverProfile
	for _, p := range c.Profiles {
		_, explicit := requested[p.ID]
		if p.Status != "active" {
			continue
		}
		match := preset == "extended" || preset == "legacy" && p.Legacy || slices.Contains(p.Roles, preset)
		if len(requested) > 0 {
			match = explicit
		}
		if match {
			result = append(result, p)
			if explicit {
				requested[p.ID] = true
			}
		}
	}
	for id, found := range requested {
		if !found {
			return nil, fmt.Errorf("unknown or inactive profile %q", id)
		}
	}
	return result, nil
}

// Metadata accompanies endpoints through measurement and serialization.
type Metadata struct {
	FilteringProbeDomains []string `json:"filteringProbeDomains,omitempty"`
	Provider              string   `json:"provider"`
	Profile               string   `json:"profile"`
	Roles                 []string `json:"roles"`
	FilteringPolicy       string   `json:"filteringPolicy"`
	ECS                   string   `json:"ecs"`
	EndpointID            string   `json:"endpointId"`
	IPFamily              string   `json:"ipFamily"`
	Transport             string   `json:"transport"`
	TLSServerName         string   `json:"tlsServerName"`
	CatalogVersion        string   `json:"catalogVersion"`
	SourceURLs            []string `json:"sourceURLs"`
}
