---
title: Heimdall IP Spoofing via Unvalidated Forwarding Headers
slug: 2026-06-heimdall-ip-spoofing
description: A high-severity vulnerability in dadrus/heimdall (versions <= 0.17.16) enables attackers to spoof client IP addresses by injecting unvalidated or malformed values into `Forwarded` or `X-Forwarded-For` HTTP headers, potentially bypassing access controls or propagating malicious IP data to upstream services when `trusted_proxies` is configured.
date: "2026-06-18T15:12:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ip-spoofing
  - access-bypass
  - web-application
  - github-advisory
vendors:
  - dadrus
products:
  - heimdall (<= 0.17.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://github.com/advisories/GHSA-38x9-25wx-7fg2
rules:
  - title: Detect Heimdall IP Spoofing - Malformed X-Forwarded-For Header
    description: Detects attempts to exploit Heimdall's vulnerability by injecting non-IP characters or 'unknown' identifiers into the 'X-Forwarded-For' header to spoof client IP addresses.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1071.001
      - T1190
    data_sources:
      - webserver
  - title: Detect Heimdall IP Spoofing - Malformed Forwarded Header 'for=' Parameter
    description: Detects attempts to exploit Heimdall's vulnerability via the 'Forwarded' header's 'for=' parameter, specifically looking for non-IP values, the 'unknown' identifier, or quoted strings containing internal delimiters like ';' or ',' that could lead to misparsing.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1071.001
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A high-severity vulnerability has been identified in `dadrus/heimdall` versions up to and including 0.17.16. This flaw allows attackers to spoof client IP addresses when the `trusted_proxies` option is configured, due to insufficient validation of values extracted from `Forwarded` and `X-Forwarded-For` HTTP headers. Heimdall extracts these header values into `Request.ClientIPAddresses` without checking for syntactically valid IP addresses, accepting arbitrary strings, malformed literals, or RFC 7239 `unknown` values. Additionally, the `Forwarded` header parser fails to correctly handle quoted strings containing delimiters (`,` or `;`), leading to misparsing and the creation of malformed entries. This vulnerability can be exploited by manipulating HTTP forwarding headers, allowing attackers to bypass access control rules that rely on `Request.ClientIPAddresses` for authorization, or to propagate attacker-controlled IP values to upstream services when Heimdall operates in proxy mode.

## Attack Chain

1.  An attacker crafts an HTTP request targeting a heimdall instance where the `trusted_proxies` configuration option is enabled.
2.  The attacker includes a manipulated `X-Forwarded-For` header (e.g., `X-Forwarded-For: 192.168.1.1, EVIL_IP`) or `Forwarded` header (e.g., `Forwarded: for="127.0.0.1;attacker_id"`, `Forwarded: for="unknown"`) containing a syntactically invalid, spoofed, or otherwise malformed IP address value.
3.  Heimdall, lacking proper validation, extracts this malicious value from the forwarding header and populates its internal `Request.ClientIPAddresses` property with the attacker-controlled string.
4.  If the heimdall instance uses rules (e.g., a CEL authorizer) that reference `Request.ClientIPAddresses` to enforce access control (e.g., restricting access to specific IP ranges), these rules evaluate against the spoofed IP.
5.  The attacker successfully bypasses the intended access control logic, gaining unauthorized access or circumventing restrictions based on the spoofed IP address.
6.  (Alternative/Concurrent): If heimdall is operating in proxy mode, it uses the manipulated `Request.ClientIPAddresses` to reconstruct `X-Forwarded-For` and `Forwarded` headers before forwarding the request to upstream services.
7.  Upstream services that trust these forwarded headers will receive and process the attacker-controlled IP value, potentially leading to incorrect logging, misattribution, or further exploitation within the internal network.

## Impact

The primary impact of this vulnerability is the circumvention of application-level access controls and the potential for misattribution or further exploitation of upstream systems. Organizations utilizing `dadrus/heimdall` as an API gateway or proxy with the `trusted_proxies` option enabled are at risk. Attackers can bypass IP-based authorization checks, granting them unauthorized access to protected resources. Furthermore, in proxy mode, attacker-controlled IP values can be propagated to backend services, corrupting security logs, impacting forensic investigations, or enabling further attacks that rely on source IP validation. There is no information regarding specific victim counts or targeted sectors in the advisory, but any organization relying on Heimdall's IP-based security features could be affected.

## Recommendation

*   Upgrade `dadrus/heimdall` to a version higher than 0.17.16 immediately to patch the vulnerability described in the GHSA advisory.
*   Ensure network-level controls are in place to only permit trusted proxies to communicate directly with your Heimdall instances.
*   Configure any proxies forwarding requests to Heimdall to sanitize or completely override, rather than append to, existing `Forwarded` or `X-Forwarded-For` headers.
*   Review and adjust any rules (e.g., CEL authorizer rules) that rely on `Request.ClientIPAddresses` for security-sensitive decisions, considering the potential for IP spoofing until patches are applied.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect attempts at IP spoofing via manipulated `X-Forwarded-For` and `Forwarded` headers.
