---
title: OpenClaw SSRF Vulnerability (CVE-2026-41302)
slug: 2024-01-openclaw-ssrf
description: OpenClaw before 2026.3.31 is vulnerable to server-side request forgery, enabling remote attackers to make arbitrary network requests and potentially access internal resources or interact with external services.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-41302
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41302
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41302
rules:
  - title: Detect OpenClaw SSRF Attempt
    description: Detects potential SSRF attempts in OpenClaw by monitoring for suspicious outbound connections originating from the web server.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Internal Resource Access via SSRF
    description: Detects potential SSRF attempts accessing internal resources based on destination IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.31 are susceptible to a server-side request forgery (SSRF) vulnerability (CVE-2026-41302) within the marketplace plugin's download functionality. This flaw enables unauthenticated, remote attackers to craft malicious requests that force the OpenClaw server to make arbitrary HTTP requests to attacker-controlled or internal destinations. The vulnerability stems from insufficient validation of user-supplied input used in fetch() calls, allowing attackers to bypass intended restrictions and abuse the server's trust relationship with other systems. Successful exploitation could lead to sensitive information disclosure, internal network scanning, or denial-of-service against internal resources. This issue poses a significant risk to organizations using affected versions of OpenClaw, particularly those with sensitive data or critical services accessible from the internal network.

## Attack Chain

1.  The attacker identifies an OpenClaw instance running a vulnerable version (prior to 2026.3.31).
2.  The attacker crafts a malicious HTTP request targeting the marketplace plugin download functionality. This request includes a manipulated URL or parameter designed to be used by the `fetch()` call.
3.  The crafted request is sent to the OpenClaw server.
4.  The OpenClaw server receives the request and processes it through the vulnerable marketplace plugin.
5.  The application uses the attacker-supplied URL in a `fetch()` call without proper sanitization or validation.
6.  The `fetch()` call initiates an HTTP request from the OpenClaw server to the attacker-specified destination. This could be an internal resource (e.g., metadata server, internal service) or an external server.
7.  The OpenClaw server receives the response from the target and, depending on the application logic, may expose parts or all of the response to the attacker.
8. The attacker gains access to sensitive information from internal resources, scans the internal network, or leverages the server to interact with external services, potentially leading to data exfiltration or further compromise.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-41302) could allow attackers to access sensitive internal resources, such as configuration files, databases, or internal APIs. Attackers might be able to perform reconnaissance on the internal network, identify other vulnerable systems, or even pivot to other internal hosts. The impact ranges from information disclosure to denial-of-service or potentially remote code execution if internal services are vulnerable. While the specific number of affected OpenClaw instances is unknown, organizations in various sectors using the vulnerable software are at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch CVE-2026-41302.
*   Implement input validation and sanitization on all user-supplied data used in network requests to prevent SSRF attacks.
*   Monitor web server logs (category: webserver, product: linux) for unusual outbound connections originating from the OpenClaw server, especially to internal IP addresses or unusual ports.
*   Deploy the Sigma rule "Detect OpenClaw SSRF Attempt" to identify potential exploitation attempts based on HTTP request patterns.
