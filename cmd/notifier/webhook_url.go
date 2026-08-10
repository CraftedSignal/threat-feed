package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type webhookLookupFunc func(context.Context, string) ([]net.IPAddr, error)

var (
	externalWebhookURLPattern = regexp.MustCompile(`^https://[^[:space:]#]+$`)
	webhookDNSNamePattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

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
	if channel != ChannelSlack && channel != ChannelTeams {
		return "", fmt.Errorf("invalid webhook channel")
	}

	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid webhook URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("invalid webhook URL: HTTPS is required")
	}
	if u.User != nil || u.Host == "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid webhook URL")
	}
	host, err := canonicalWebhookHost(u)
	if err != nil {
		return "", err
	}
	port, err := canonicalWebhookPort(u.Port())
	if err != nil {
		return "", err
	}

	u.Scheme = "https"
	u.Host = webhookAuthority(host, port)
	normalized := u.String()
	if !externalWebhookURLPattern.MatchString(normalized) {
		return "", fmt.Errorf("invalid webhook URL")
	}
	return normalized, nil
}

func canonicalWebhookHost(u *url.URL) (string, error) {
	host := strings.TrimSpace(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.Contains(host, "%") {
		return "", fmt.Errorf("invalid webhook URL host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if isBlockedWebhookAddr(addr) {
			return "", fmt.Errorf("invalid webhook URL host: IP must be external")
		}
		return addr.String(), nil
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid webhook URL host: %w", err)
	}
	host = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if !validWebhookDNSName(host) {
		return "", fmt.Errorf("invalid webhook URL host")
	}
	return host, nil
}

func canonicalWebhookPort(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid webhook URL port")
	}
	if port == 443 {
		return "", nil
	}
	return strconv.Itoa(port), nil
}

func webhookAuthority(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func validWebhookDNSName(host string) bool {
	return len(host) <= 253 &&
		webhookDNSNamePattern.MatchString(host) &&
		!blockedWebhookDNSName(host)
}

func blockedWebhookDNSName(host string) bool {
	for _, suffix := range blockedWebhookDNSSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
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
	return isBlockedWebhookAddr(addr)
}

func isBlockedWebhookAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
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

var blockedWebhookDNSSuffixes = []string{
	"example",
	"home.arpa",
	"invalid",
	"internal",
	"local",
	"localhost",
	"test",
}

func mustWebhookPrefix(cidr string) netip.Prefix {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}
	return prefix
}
