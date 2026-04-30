---
title: Axios NO_PROXY Hostname Normalization Bypass Leads to SSRF
slug: 2024-01-axios-ssrf
description: Axios is vulnerable to a NO_PROXY hostname normalization bypass leading to SSRF, where requests to loopback addresses like `localhost.` or `[::1]` bypass `NO_PROXY` rules, allowing attackers to force requests through a proxy and potentially exfiltrate sensitive data.
date: "2026-04-09T17:32:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - no_proxy
  - axios
  - hostname_normalization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-62718
references:
  - https://github.com/advisories/GHSA-3p68-rc4w-qgx5
  - https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
  - https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
rules:
  - title: Detect Axios SSRF via NO_PROXY Bypass
    description: Detects SSRF attempts exploiting Axios NO_PROXY bypass via hostname normalization issues (trailing dots or IPv6 brackets).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Axios SSRF via NO_PROXY Bypass (HTTP Host Header)
    description: Detects SSRF attempts exploiting Axios NO_PROXY bypass by checking the HTTP Host header for loopback addresses with trailing dots or IPv6 brackets.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Axios, a popular HTTP client for Node.js, is susceptible to a NO_PROXY bypass vulnerability due to incorrect hostname normalization. This flaw, confirmed in version 1.12.2 and affecting all versions prior to 1.15.0, arises from the application's failure to properly handle hostnames with trailing dots (e.g., `localhost.`) or IPv6 literals (e.g., `[::1]`) when evaluating `NO_PROXY` rules.  Instead of performing normalization as recommended by RFC standards, Axios conducts literal string comparisons. This oversight allows attackers to circumvent intended `NO_PROXY` configurations and force requests through an attacker-controlled proxy, even when loopback or internal services are meant to be protected. The vulnerability could be exploited to bypass SSRF mitigations, potentially enabling exfiltration of sensitive information.

## Attack Chain

1.  The attacker identifies an application using a vulnerable version of Axios and relies on `NO_PROXY` for loopback protection.
2.  The attacker crafts a malicious URL targeting a loopback address (e.g., `http://localhost.:8080/` or `http://[::1]:8080/`).
3.  The vulnerable Axios instance processes the URL without proper hostname normalization.
4.  Due to the lack of normalization, the `NO_PROXY` check fails to recognize `localhost.` or `[::1]` as loopback addresses.
5.  Axios incorrectly routes the request through a configured proxy server, which could be controlled by the attacker.
6.  The attacker-controlled proxy receives the request and can forward it to the intended internal service.
7.  The internal service responds to the proxy.
8.  The attacker-controlled proxy captures the response data, potentially containing sensitive information, and can exfiltrate it.

## Impact

Applications that depend on `NO_PROXY` settings to safeguard loopback or internal access are vulnerable to SSRF attacks. Attackers can exploit this flaw to force Axios to send local traffic through an attacker-controlled proxy server. This bypasses SSRF mitigations that rely on `NO_PROXY` rules, allowing the potential exfiltration of sensitive information from internal services via the compromised proxy.  The number of affected applications is potentially large, given the widespread use of Axios in Node.js environments. Successful exploitation could lead to unauthorized access to sensitive internal resources and data breaches.

## Recommendation

*   Upgrade Axios to version 1.15.0 or later to address the vulnerability (CVE-2025-62718).
*   Deploy the Sigma rule `Detect Axios SSRF via NO_PROXY Bypass` to identify attempts to exploit this vulnerability.
*   Inspect web server logs for requests containing loopback addresses with trailing dots or bracketed IPv6 literals to identify potential exploitation attempts.
