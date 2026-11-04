package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/taihen/dns-benchmark/pkg/catalog"
)

func validatePort(port string) error {
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return fmt.Errorf("invalid port %q", port)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q (expected 1–65535)", port)
	}
	return nil
}

func addressFamily(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return "auto"
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

// LoadServers applies catalogue selection or legacy file input and system DNS.
func (cfg *Config) LoadServers() error {
	if cfg.Preset == "" {
		cfg.Preset = "legacy"
	}
	if cfg.IPFamily == "" {
		cfg.IPFamily = "auto"
	}
	if !slices.Contains([]string{"auto", "ipv4", "ipv6"}, cfg.IPFamily) {
		return fmt.Errorf("unknown IP family %q", cfg.IPFamily)
	}
	transports := []string{"udp", "dot", "doh"}
	if cfg.Preset == "extended" || cfg.Profiles != "" {
		transports = []string{"udp", "tcp", "dot", "doh", "doq"}
	}
	if cfg.Transports != "" {
		transports = strings.Split(cfg.Transports, ",")
		for _, p := range transports {
			if !slices.Contains([]string{"udp", "tcp", "dot", "doh", "doq"}, p) {
				return fmt.Errorf("unknown transport %q", p)
			}
		}
	}
	cfg.Servers = nil
	if cfg.ServersFile != "" {
		if cfg.Profiles != "" || cfg.Preset != "legacy" {
			return fmt.Errorf("-f cannot be combined with catalogue profiles or presets")
		}
		entries, err := readServerStringsFromFile(cfg.ServersFile)
		if err != nil {
			return err
		}
		cfg.Servers = parseAndDeduplicateServers(entries)
		cfg.IncludeSystemDNS = false
		var selected []ServerInfo
		for _, s := range cfg.Servers {
			if cfg.Transports != "" && !slices.Contains(transports, string(s.Protocol)) {
				continue
			}
			if cfg.IPFamily != "auto" {
				if s.IPFamily != "auto" && s.IPFamily != cfg.IPFamily {
					continue
				}
				s.IPFamily = cfg.IPFamily
			}
			selected = append(selected, s)
		}
		cfg.Servers = selected
	} else {
		c, err := catalog.Load()
		if err != nil {
			return err
		}
		if err := c.CheckFreshness(time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v; resolver details may be out of date, consider upgrading dns-benchmark.\n", err)
		}
		profiles, err := c.Select(cfg.Preset, cfg.Profiles)
		if err != nil {
			return err
		}
		family := cfg.IPFamily
		if family == "auto" && cfg.Preset == "legacy" && cfg.Profiles == "" {
			family = "ipv4"
		}
		for _, p := range profiles {
			for _, e := range p.Endpoints {
				if !slices.Contains(transports, e.Protocol) || family != "auto" && family != e.Family {
					continue
				}
				s := ServerInfo{
					Address:  net.JoinHostPort(e.Address, strconv.Itoa(e.Port)),
					Protocol: ProtocolType(e.Protocol),
					Hostname: e.Address,
					Metadata: catalog.Metadata{
						FilteringProbeDomains: p.FilteringProbeDomains,
						Provider:              p.Provider, Profile: p.ID, Roles: p.Roles,
						FilteringPolicy: p.FilteringPolicy, ECS: p.ECS,
						EndpointID: e.ID, IPFamily: e.Family, Transport: e.Protocol,
						TLSServerName: e.TLSServerName, CatalogVersion: c.Version,
						SourceURLs: p.SourceURLs,
					},
				}
				if s.Protocol == DOH {
					s.Address = e.URL
					u, _ := url.Parse(e.URL)
					s.Hostname = u.Hostname()
					s.DoHPath = u.Path
				}
				cfg.Servers = append(cfg.Servers, s)
			}
		}
	}
	if cfg.IncludeSystemDNS {
		entries, err := systemDNSServers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not detect system DNS servers: %v\n", err)
		}
		if cfg.Transports == "" || slices.Contains(transports, "udp") {
			// A system resolver that is also a selected catalogue endpoint
			// (commonly 1.1.1.1 or 8.8.8.8) is benchmarked once, as the
			// catalogue entry, rather than twice under two names.
			selected := make(map[string]bool, len(cfg.Servers))
			for _, s := range cfg.Servers {
				selected[endpointKey(s)] = true
			}
			for _, s := range parseAndDeduplicateServers(entries) {
				if cfg.IPFamily != "auto" && s.IPFamily != cfg.IPFamily {
					continue
				}
				if selected[endpointKey(s)] {
					continue
				}
				s.Provider = "system"
				s.Profile = "system"
				s.Roles = []string{"system"}
				cfg.Servers = append(cfg.Servers, s)
			}
		}
	}
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("no endpoints match the selection")
	}
	return nil
}

// systemDNSServers is a variable so tests can substitute resolv.conf contents.
var systemDNSServers = getSystemDNSServers

// endpointKey identifies an endpoint by what is actually contacted, so the same
// resolver reached through different selection paths compares equal.
func endpointKey(s ServerInfo) string {
	return string(s.Protocol) + "|" + s.Address
}

// legacyEndpointStrings renders the legacy preset in the historical string
// format. The catalogue is embedded at build time, so a load or selection
// failure is a build defect; it panics rather than leaving DefaultDNSStrings
// silently empty.
func legacyEndpointStrings() []string {
	c, err := catalog.Load()
	if err != nil {
		panic(fmt.Sprintf("dns-benchmark: %v", err))
	}
	profiles, err := c.Select("legacy", "")
	if err != nil {
		panic(fmt.Sprintf("dns-benchmark: select legacy preset: %v", err))
	}
	var entries []string
	for _, p := range profiles {
		for _, e := range p.Endpoints {
			if e.Family != "ipv4" {
				continue
			}
			switch e.Protocol {
			case "udp":
				entries = append(entries, e.Address)
			case "dot":
				entries = append(entries, "tls://"+e.TLSServerName)
			case "doh":
				entries = append(entries, e.URL)
			}
		}
	}
	return entries
}
