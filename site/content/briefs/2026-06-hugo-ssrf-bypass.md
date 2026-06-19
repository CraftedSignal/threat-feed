---
title: Hugo security.http.urls Bypass via Alternate IPv4 Encodings (SSRF)
slug: 2026-06-hugo-ssrf-bypass
description: A Server-Side Request Forgery (SSRF) vulnerability exists in Hugo versions 0.162.0 through 0.163.0, where the 'security.http.urls' policy designed to deny requests to loopback, internal, and cloud-metadata IPv4 literals could be bypassed as the policy only matched dotted-decimal notation, allowing alternate IPv4 encodings (integer, hex, octal) to pass, enabling build-time server-side requests to internal services and cloud-metadata endpoints when untrusted or data-derived URLs are passed to 'resources.GetRemote'.
date: "2026-06-19T19:22:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - hugo
  - build-time
  - webserver
vendors:
  - gohugoio
products:
  - Hugo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://github.com/advisories/GHSA-r46f-3rpw-hxrv
rules:
  - title: Detect Outbound Connection to Cloud Metadata IP (169.254.169.254)
    description: Detects processes attempting to connect to the cloud metadata IP address (169.254.169.254). This is often an indicator of SSRF or reconnaissance if initiated by unexpected processes like build tools.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1016
      - T1580
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Outbound Connection to Loopback IP by Build Tools
    description: Detects processes commonly associated with build environments making outbound network connections to loopback IP addresses (e.g., 127.0.0.1). This could indicate an SSRF attempt to access local services.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A significant Server-Side Request Forgery (SSRF) vulnerability, impacting Hugo versions 0.162.0 through 0.163.0, allows attackers to bypass the `security.http.urls` policy. This policy is intended to prevent Hugo from making requests to sensitive internal, loopback, or cloud-metadata IPv4 addresses during site generation, especially when processing untrusted URLs via `resources.GetRemote`. The bypass occurs because the denial rule only recognized IPv4 addresses in standard dotted-decimal format, failing to catch alternate encodings such as integer, hexadecimal, or octal representations. This flaw can lead to build-time server-side requests to internal infrastructure or cloud metadata endpoints when a host platform utilizes the `cgo` system resolver, enabling potential information disclosure or unauthorized internal network access during CI/CD processes or other build environments. The vulnerability was patched in Hugo v0.163.1, which canonicalizes IPv4 hosts to dotted-decimal before applying the policy.

## Attack Chain

1.  **Initial Access / Injection**: An attacker injects a specially crafted URL containing an alternate IPv4 encoding (e.g., `http://2130706433/` for `127.0.0.1` or `http://2852039166/` for cloud metadata) into a Hugo template or data source.
2.  **Vulnerable Processing**: During a Hugo site build, a template attempts to fetch content from this untrusted URL using the `resources.GetRemote` function.
3.  **Policy Bypass Attempt**: Hugo's `security.http.urls` policy is consulted to determine if the URL should be denied, but it only checks for dotted-decimal IPv4 formats.
4.  **Encoding Misinterpretation**: Due to the vulnerability, the policy fails to recognize the integer, hexadecimal, or octal IPv4 encoding as a disallowed internal, loopback, or cloud-metadata address.
5.  **DNS/Resolver Resolution**: The host platform's `cgo` system resolver resolves the alternate IPv4 encoding (e.g., `2130706433`) to its standard dotted-decimal equivalent (`127.0.0.1`).
6.  **Internal Request Execution**: Hugo proceeds to make an outbound HTTP GET request to the now-resolved internal IP address (e.g., `127.0.0.1`, `169.254.169.254`, or another internal service).
7.  **Information Disclosure/Internal Access**: The build environment's internal services or cloud metadata endpoint respond to Hugo's request, potentially disclosing sensitive configuration data, credentials, or allowing access to internal resources that should have been protected.

## Impact

The primary impact of this vulnerability is the potential for Server-Side Request Forgery (SSRF) during the Hugo site build process. If exploited, an attacker can coerce the build server to make outbound HTTP requests to arbitrary internal network resources, including loopback addresses, internal hosts, or cloud metadata endpoints (e.g., `169.254.169.254`). This can lead to the exposure of sensitive information such as cloud instance credentials, internal network topology, or other confidential data accessible from the build environment. While no specific victim counts or sectors were noted, organizations using Hugo in CI/CD pipelines or environments where untrusted content influences builds are at risk of unauthorized data access and potential lateral movement within their internal infrastructure.

## Recommendation

*   Upgrade Hugo to version **v0.163.1** or newer immediately to apply the patch that correctly canonicalizes IPv4 addresses.
*   Review CI/CD pipeline configurations and Hugo site templates to avoid passing untrusted or data-derived URLs directly to `resources.GetRemote`.
*   Harden `security.http.urls` in Hugo configurations to implement an explicit allow-list of trusted hosts for `resources.GetRemote` calls.
*   Deploy the provided Sigma rules to detect unexpected outbound network connections from build servers and similar environments.
*   Ensure network connection logging is enabled on build servers and developer workstations to capture attempts to access internal or cloud metadata IPs.
