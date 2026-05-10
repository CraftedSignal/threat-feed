---
title: dssrf SSRF Protection Bypass via IPv6 Addresses
slug: 2024-01-dssrf-ipv6-bypass
description: A vulnerability in the dssrf npm package allows attackers to bypass SSRF protections by using specially crafted IPv6 addresses, despite documentation claiming IPv6 is disabled, which can lead to internal resource access or other malicious activities.
date: "2026-05-06T18:13:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - ipv6
  - defense-evasion
products:
  - dssrf (< 1.3.0)
references:
  - https://github.com/advisories/GHSA-8p33-q827-ghj5
iocs:
  - type: url
    value: http://[::1]/
  - type: url
    value: http://[fc00::1]/
  - type: url
    value: http://[fe80::1]/
  - type: url
    value: http://[::ffff:127.0.0.1]/
  - type: url
    value: http://[::ffff:169.254.169.254]/
  - type: url
    value: http://[::ffff:100.64.0.1]/
  - type: url
    value: http://[64:ff9b::7f00:1]/
  - type: url
    value: http://[64:ff9b:1::1]/
  - type: url
    value: http://[5f00::1]/
  - type: url
    value: http://[3fff::1]/
  - type: url
    value: http://[fec0::1]/
  - type: url
    value: http://[::127.0.0.1]/
ioc_counts:
  url: 12
rules:
  - title: Detect dssrf SSRF Bypass Attempts via IPv6 Addresses
    description: Detects attempts to bypass SSRF protections by using specific IPv6 address formats known to be mishandled by dssrf.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
  - title: Detect dssrf SSRF Bypass Attempts via IPv6 Host Header
    description: Detects attempts to bypass SSRF protections by using specific IPv6 address formats in the HTTP Host header, which may be missed by URL parsing logic.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The dssrf npm package, designed to prevent Server-Side Request Forgery (SSRF) attacks, contains a flaw that permits attackers to bypass its protections. This bypass is achieved by supplying specific IPv6 addresses that the `is_url_safe` function fails to properly validate. The dssrf documentation incorrectly states that IPv6 is disabled entirely, leading to a false sense of security.  The vulnerability affects versions prior to 1.3.0. This allows attackers to potentially access internal network resources or conduct other malicious activities by crafting requests that appear safe but are ultimately routed to unintended destinations. This issue was reported responsibly, and users are urged to update to version 1.3.0 immediately.

## Attack Chain

1. An attacker identifies a web application utilizing a vulnerable version of the `dssrf` npm package for URL safety checks.
2. The attacker crafts a malicious URL containing an IPv6 address designed to bypass the `is_url_safe` function, such as `http://[::1]/` (IPv6 loopback) or `http://[::ffff:169.254.169.254]/` (IPv4-mapped IMDS).
3. The web application, relying on the flawed `dssrf.is_url_safe` function, incorrectly identifies the malicious URL as safe.
4. The web application then uses the "safe" URL to make an HTTP request using standard libraries like `node-fetch`.
5. Due to the bypassed SSRF protection, the request is sent to the attacker-specified IPv6 address, potentially targeting internal resources or services.
6. The internal service processes the attacker's request, potentially exposing sensitive data or allowing unauthorized actions.
7. The attacker receives the response from the internal service, successfully exfiltrating data or manipulating internal systems.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass SSRF protections, potentially granting access to internal network resources, sensitive data, or unintended services.  The number of affected applications is currently unknown, but any application using a vulnerable version of `dssrf` (< 1.3.0) is susceptible.  This could lead to data breaches, unauthorized access to cloud metadata services, or other internal service exploitation.  The vulnerable package has had over 10,000 weekly downloads, demonstrating widespread use and potential impact.

## Recommendation

*   Upgrade the `dssrf` npm package to version 1.3.0 or later to remediate the vulnerability as advised in the advisory (https://github.com/advisories/GHSA-8p33-q827-ghj5).
*   Implement additional server-side input validation to filter URLs containing potentially malicious IPv6 addresses, complementing the `dssrf` package.
*   Deploy the Sigma rule provided below to identify attempts to bypass SSRF protections by using IPv6 addresses in URLs (see Sigma rule below).
