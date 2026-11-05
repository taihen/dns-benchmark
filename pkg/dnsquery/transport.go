package dnsquery

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/taihen/dns-benchmark/pkg/analysis"
	"github.com/taihen/dns-benchmark/pkg/config"
)

func authenticationName(server config.ServerInfo) string {
	if server.TLSServerName != "" {
		return server.TLSServerName
	}
	return server.Hostname
}

func networkForFamily(network, family string) string {
	switch family {
	case "ipv4":
		return network + "4"
	case "ipv6":
		return network + "6"
	}
	return network
}

func newDoHClient(server config.ServerInfo, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Direct connections make the selected family meaningful even when HTTP_PROXY is set.
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: server.TLSRootCAs, ServerName: authenticationName(server), MinVersion: tls.VersionTLS12}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if server.ConnectAddress != "" {
			address = server.ConnectAddress
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, networkForFamily("tcp", server.IPFamily), address)
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func initialCheckStates(cfg *config.Config, servers ...config.ServerInfo) map[string]analysis.CheckState {
	checks := map[string]analysis.CheckState{}
	for name, enabled := range map[string]bool{"dnssec": cfg.CheckDNSSEC, "nxdomain": cfg.CheckNXDOMAIN, "rebinding": cfg.CheckRebinding, "accuracy": cfg.AccuracyCheckFile != "", "dotcom": cfg.CheckDotcom} {
		checks[name] = analysis.NotApplicable
		if enabled {
			checks[name] = analysis.Inconclusive
		}
	}
	checks["filtering"] = analysis.NotApplicable
	if cfg.CheckFiltering && len(servers) > 0 && len(servers[0].FilteringProbeDomains) > 0 {
		checks["filtering"] = analysis.Inconclusive
	}
	return checks
}

// boolFromState maps a check state to the legacy *bool compatibility value.
func boolFromState(state analysis.CheckState) *bool {
	switch state {
	case analysis.Pass:
		return boolPtr(true)
	case analysis.Fail:
		return boolPtr(false)
	default:
		return nil
	}
}

// combineProbeStates merges per-domain probe states. Any observed Fail is
// conclusive even when other probes are missing or inconclusive; Pass requires
// all expected probes to pass.
func combineProbeStates(states []analysis.CheckState, expected int) analysis.CheckState {
	state := analysis.Pass
	for _, s := range states {
		if s == analysis.Fail {
			return analysis.Fail
		}
		if s == analysis.Inconclusive {
			state = s
		}
	}
	if len(states) < expected {
		return analysis.Inconclusive
	}
	return state
}
