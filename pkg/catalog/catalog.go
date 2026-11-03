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
	Status                string     `json:"status"`
	Legacy                bool       `json:"legacy,omitempty"`
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

// Load decodes and validates the embedded catalogue without making network requests.
func Load() (*Catalog, error) {
	var c Catalog
	decoder := json.NewDecoder(bytes.NewReader(embedded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode catalogue: %w", err)
	}
	if err := c.Validate(time.Now()); err != nil {
		return nil, err
	}
	return &c, nil
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
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

// Validate checks identifiers, provenance, lifecycle, families and transport claims.
// Active entries must be reviewed within 366 days; deprecated entries are retained
// for historical use but excluded from selection.
func (c *Catalog) Validate(now time.Time) error {
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
		if p.Status != "active" && p.Status != "deprecated" {
			return fmt.Errorf("invalid status for %s", p.ID)
		}
		verified, err := time.Parse("2006-01-02", p.LastVerified)
		if err != nil || verified.After(now.Add(24*time.Hour)) || (p.Status == "active" && now.Sub(verified) > 366*24*time.Hour) {
			return fmt.Errorf("invalid or stale verification date for %s", p.ID)
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
			}
		}
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
