---
title: X-Forwarded-For Header Injection Vulnerability in tsdproxy
slug: 2026-07-tsdproxy-ip-spoofing
description: An authenticated Tailscale user can bypass IP-based access controls, rate limiting, and manipulate audit logs by injecting arbitrary X-Forwarded-For or X-Real-IP headers into proxied requests via `tsdproxy`. This vulnerability stems from `tsdproxy`'s failure to strip these headers before forwarding them, allowing an attacker to spoof their source IP address. This is particularly impactful when `tsdproxy` is the sole enforcement point for backend services, enabling actions such as gaining unauthorized admin access to backend applications.
date: "2026-07-14T20:27:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ip-spoofing
  - header-injection
  - reverse-proxy
  - access-control-bypass
  - tailscale
  - network
vendors:
  - almeidapaulopt
products:
  - tsdproxy (< 3.0.0-alpha.3)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated Tailscale user who should only have regular user access can bypass IP-based admin restrictions on the backend application
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: bypass IP-based admin restrictions on the backend application by spoofing X-Forwarded-For to 127.0.0.1
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pqg7-v6wh-3pfp
rules:
  - title: Detect X-Forwarded-For/X-Real-IP Spoofing via tsdproxy
    description: Detects attempts to bypass IP-based access controls by injecting spoofed X-Forwarded-For or X-Real-IP headers, often targeting sensitive endpoints like /admin. This exploits a vulnerability in tsdproxy (< 3.0.0-alpha.3).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
      - T1078
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability (CVE-NONE) has been identified in `tsdproxy` versions prior to `3.0.0-alpha.3`, allowing authenticated Tailscale users to inject arbitrary `X-Forwarded-For` or `X-Real-IP` headers into proxied requests. The `tsdproxy` HTTP reverse proxy handler fails to strip these headers from incoming requests before forwarding them to backend services. This omission means that if an attacker provides a spoofed IP address in these headers, `tsdproxy` will append the legitimate client IP to `X-Forwarded-For` but will not remove the attacker-supplied value, or in the case of `X-Real-IP`, forward it verbatim. This enables attackers to bypass IP-based access controls, rate limiting, and manipulate audit logs on downstream applications, posing a significant risk, especially where `tsdproxy` is the sole access control enforcement point for isolated backend services. The vulnerability was reported by Vishal Shukla.

## Attack Chain

1. An authenticated Tailscale user identifies a `tsdproxy` instance fronting a sensitive backend service.
2. The attacker determines the backend service enforces IP-based restrictions, such as limiting access to `/admin` paths to `127.0.0.1`.
3. The attacker crafts an HTTP request, including a spoofed `X-Forwarded-For: 127.0.0.1` or `X-Real-IP: 127.0.0.1` header.
4. The request is sent through `tsdproxy`, targeting the sensitive `/admin` endpoint of the backend service.
5. Due to the vulnerability, `tsdproxy` forwards the request without stripping the attacker's spoofed `X-Forwarded-For` or `X-Real-IP` header.
6. The `httputil.ProxyRequest.SetXForwarded()` function appends the real Tailscale client IP to `X-Forwarded-For`, resulting in `X-Forwarded-For: 127.0.0.1, <real-tailscale-client-ip>`. For `X-Real-IP`, the attacker's `127.0.0.1` is passed directly.
7. The backend service, configured to trust the first IP in `X-Forwarded-For` (or `X-Real-IP`), interprets the request as originating from `127.0.0.1`.
8. The attacker successfully bypasses the IP-based access control, gaining unauthorized access to the `/admin` functionality.

## Impact

This vulnerability allows an authenticated Tailscale user to significantly escalate their privileges and evade security controls on backend applications protected by `tsdproxy`. Successful exploitation can lead to unauthorized access to sensitive administrative interfaces, bypassing of critical security mechanisms like rate limiting and geo-blocking, and the ability to manipulate audit logs by falsifying source IP addresses. The impact is particularly severe because `tsdproxy` is often deployed as the single entry point for otherwise network-isolated backend services, making its header handling crucial for security. Attackers can leverage this to gain full control over backend systems that rely on IP-based authentication or authorization.

## Recommendation

* Upgrade `tsdproxy` to version `3.0.0-alpha.3` or higher immediately to apply the fix that correctly strips `X-Forwarded-For` and `X-Real-IP` headers.
* Deploy the Sigma rule "Detect X-Forwarded-For/X-Real-IP Spoofing via tsdproxy" to your SIEM and monitor `webserver` logs for suspicious header injection attempts targeting sensitive paths.
* Review and audit backend application configurations to ensure they correctly interpret `X-Forwarded-For` headers, ideally by configuring trusted proxies (e.g., `real_ip_recursive` in Nginx) to prevent spoofing from internal network segments.
* Implement additional application-level authentication and authorization beyond IP-based controls for sensitive endpoints to mitigate the risk of header spoofing.
