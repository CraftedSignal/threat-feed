---
title: OpenClaw SSRF Vulnerability via Unguarded Configured Base URLs
slug: 2026-05-openclaw-ssrf
description: OpenClaw versions 2026.3.24 and earlier are vulnerable to Server-Side Request Forgery (SSRF) because of unguarded configured base URLs in multiple channel extensions, allowing attackers to potentially access internal resources.
date: "2026-03-29T15:49:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - openclaw
  - cve-2026-28476
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rhfg-j8jq-7v2h
rules:
  - title: Detect OpenClaw SSRF Vulnerable Versions
    description: Detects requests potentially originating from vulnerable OpenClaw versions based on user agent strings.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF Outbound Connections to Internal IPs
    description: Detects outbound network connections from openclaw processes to private IP address ranges, which could indicate SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The `openclaw` package, a Node.js module, contains a Server-Side Request Forgery (SSRF) vulnerability in versions 2026.3.24 and earlier. This flaw stems from an incomplete fix for CVE-2026-28476, where several channel extensions continued to use raw `fetch()` against configured base URLs without proper SSRF protection. This omission allows attackers to potentially manipulate configured endpoints to target blocked internal destinations, bypassing intended security measures. The vulnerability was identified and patched in version 2026.3.25 through commit `f92c92515bd439a71bd03eb1bc969c1964f17acf`, which routes outbound requests through `fetchWithSsrFGuard`. Defenders should ensure they are running version 2026.3.25 or later.

## Attack Chain

1.  Attacker identifies an `openclaw` instance running version 2026.3.24 or earlier.
2.  The attacker identifies a channel extension that uses a configured base URL.
3.  Attacker crafts a malicious configuration that redirects the base URL to an internal resource.
4.  The vulnerable `fetch()` function in the channel extension makes an HTTP request to the attacker-controlled URL.
5.  The request bypasses the SSRF guard due to the incomplete fix for CVE-2026-28476.
6.  The targeted internal resource processes the attacker's request.
7.  Sensitive information from the internal resource is potentially exposed to the attacker.
8.  Attacker exfiltrates the exposed information, completing the SSRF attack.

## Impact

Successful exploitation of this SSRF vulnerability could allow an attacker to gain unauthorized access to internal resources and sensitive information. The number of potential victims is dependent on the prevalence of vulnerable `openclaw` instances. If successful, the attacker can read internal files, access internal services, or even potentially execute commands on internal systems, leading to data breaches or further compromise of the network.

## Recommendation

*   Upgrade the `openclaw` package to version 2026.3.25 or later to incorporate the fix for CVE-2026-28476, as described in the overview.
*   Implement network segmentation to limit the impact of potential SSRF vulnerabilities by restricting access from the affected systems to sensitive internal resources.
*   Deploy the Sigma rule "Detect OpenClaw SSRF Vulnerable Versions" to identify potentially vulnerable instances of the `openclaw` package based on user-agent strings.
*   Monitor outbound network connections from `openclaw` instances for connections to internal IP addresses or unexpected domains, which could indicate SSRF exploitation attempts.
