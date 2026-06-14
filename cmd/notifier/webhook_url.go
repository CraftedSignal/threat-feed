package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type webhookLookupFunc func(context.Context, string) ([]net.IPAddr, error)

func newWebhookHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           safeWebhookDialContext(&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}, net.DefaultResolver.LookupIPAddr),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validateWebhookURL(raw string, channel Channel) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid webhook URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("invalid webhook URL: HTTPS is required")
	}
	if u.User != nil || u.Host == "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid webhook URL")
	}
	host := canonicalWebhookHost(u)
	if host == "" || net.ParseIP(host) != nil {
		return "", fmt.Errorf("invalid webhook URL host")
	}
	if port := u.Port(); port != "" && port != "443" {
		return "", fmt.Errorf("invalid webhook URL port")
	}

	ok := false
	switch channel {
	case ChannelSlack:
		ok = host == "hooks.slack.com" && strings.HasPrefix(u.EscapedPath(), "/services/")
	case ChannelTeams:
		ok = validTeamsWebhookURL(u, host)
	default:
		return "", fmt.Errorf("invalid webhook channel")
	}
	if !ok {
		return "", fmt.Errorf("invalid webhook URL for %s", channel)
	}

	u.Scheme = "https"
	u.Host = host
	return u.String(), nil
}

func canonicalWebhookHost(u *url.URL) string {
	host := strings.TrimSpace(strings.ToLower(u.Hostname()))
	host = strings.TrimSuffix(host, ".")
	return host
}

func validTeamsWebhookURL(u *url.URL, host string) bool {
	path := u.EscapedPath()
	switch {
	case host == "outlook.office.com":
		return strings.HasPrefix(path, "/webhook/") || strings.HasPrefix(path, "/webhookb2/")
	case host == "webhook.office.com" || strings.HasSuffix(host, ".webhook.office.com"):
		return strings.HasPrefix(path, "/webhook/") || strings.HasPrefix(path, "/webhookb2/")
	case host == "logic.azure.com" || strings.HasSuffix(host, ".logic.azure.com"):
		return strings.HasPrefix(path, "/workflows/")
	default:
		return false
	}
}

func safeWebhookDialContext(dialer *net.Dialer, lookup webhookLookupFunc) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unsupported webhook network %q", network)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid webhook address: %w", err)
		}
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedWebhookIP(ip) {
				return nil, fmt.Errorf("webhook resolved to blocked IP %s", ip)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}

		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve webhook host: %w", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve webhook host: no addresses")
		}
		for _, ip := range ips {
			if isBlockedWebhookIP(ip.IP) {
				return nil, fmt.Errorf("webhook resolved to blocked IP %s", ip.IP)
			}
		}

		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func isBlockedWebhookIP(ip net.IP) bool {
	addr, ok := webhookNetipAddr(ip)
	if !ok {
		return true
	}
	if !addr.IsGlobalUnicast() ||
		addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return true
	}
	for _, prefix := range specialUseWebhookIPPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func webhookNetipAddr(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		addr, ok := netip.AddrFromSlice(v4)
		return addr, ok
	}
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

var specialUseWebhookIPPrefixes = []netip.Prefix{
	mustWebhookPrefix("0.0.0.0/8"),
	mustWebhookPrefix("100.64.0.0/10"),
	mustWebhookPrefix("192.0.0.0/24"),
	mustWebhookPrefix("192.0.2.0/24"),
	mustWebhookPrefix("192.88.99.0/24"),
	mustWebhookPrefix("198.18.0.0/15"),
	mustWebhookPrefix("198.51.100.0/24"),
	mustWebhookPrefix("203.0.113.0/24"),
	mustWebhookPrefix("240.0.0.0/4"),
	mustWebhookPrefix("64:ff9b::/96"),
	mustWebhookPrefix("64:ff9b:1::/48"),
	mustWebhookPrefix("100::/64"),
	mustWebhookPrefix("2001::/23"),
	mustWebhookPrefix("2001:2::/48"),
	mustWebhookPrefix("2001:db8::/32"),
	mustWebhookPrefix("2002::/16"),
}

func mustWebhookPrefix(cidr string) netip.Prefix {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}
	return prefix
}
