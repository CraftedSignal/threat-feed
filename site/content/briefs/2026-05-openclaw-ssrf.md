---
title: OpenClaw Server-Side Request Forgery Vulnerability
slug: 2026-05-openclaw-ssrf
description: OpenClaw before 2026.4.5 is vulnerable to server-side request forgery (SSRF) via the CDP /json/version WebSocket endpoint by not properly validating the webSocketDebuggerUrl response field, enabling attackers to redirect connections to arbitrary hosts and perform SSRF-style attacks to pivot to untrusted second-hop targets.
date: "2026-05-06T20:16:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-43576
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
  - OpenClaw CDP /json/version WebSocket endpoint
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-43576
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43576
  - https://github.com/openclaw/openclaw/commit/bc356cc8c2beaa747c71dd86cceab8f804699665
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-f7fh-qg34-x2xh
  - https://www.vulncheck.com/advisories/openclaw-second-hop-ssrf-via-cdp-json-version-websocket-url
rules:
  - title: Detect OpenClaw SSRF Attempt via Modified WebSocket Debugger URL
    description: Detects attempts to exploit the OpenClaw SSRF vulnerability by monitoring requests to the /json/version endpoint with a suspicious webSocketDebuggerUrl.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF Response with External WebSocket URL
    description: Detects OpenClaw responses to the /json/version endpoint containing an external webSocketDebuggerUrl, potentially indicating an SSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.4.5 are susceptible to a server-side request forgery (SSRF) vulnerability. The vulnerability resides in the CDP /json/version WebSocket endpoint. Insufficient validation of the `webSocketDebuggerUrl` response field allows attackers to manipulate connections to arbitrary hosts. This flaw enables attackers to perform SSRF attacks, effectively pivoting to internal, untrusted second-hop targets. The vulnerability was reported on May 6, 2026, and poses a significant risk to systems running affected versions of OpenClaw by potentially exposing internal resources and services to unauthorized access.

## Attack Chain

1. An attacker identifies an OpenClaw instance running a version prior to 2026.4.5.
2. The attacker sends a request to the `/json/version` WebSocket endpoint.
3. The OpenClaw server responds with a JSON payload that includes the `webSocketDebuggerUrl` field.
4. The attacker intercepts and modifies the `webSocketDebuggerUrl` field in the response to point to an internal or external host controlled by the attacker.
5. A user or application attempts to use the WebSocket debugger URL.
6. The connection is redirected to the attacker-controlled host due to the manipulated URL.
7. The attacker can now proxy requests through the OpenClaw server, effectively performing an SSRF attack against the target host.
8. The attacker can potentially access internal resources or exploit other vulnerabilities on the second-hop target.

## Impact

Successful exploitation of this SSRF vulnerability allows an attacker to pivot to internal, untrusted second-hop targets. This can lead to the exposure of sensitive information, unauthorized access to internal services, and further exploitation of vulnerabilities on internal systems. The CVSS v3.1 base score is rated as 7.7 (High), reflecting the potential for significant impact. There is no information about the number of victims or sectors targeted in the source material.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.5 or later to patch the vulnerability (CVE-2026-43576).
*   Implement network segmentation to limit the impact of potential SSRF attacks.
*   Monitor web server logs for requests to the `/json/version` endpoint that contain suspicious or unexpected URLs in the `webSocketDebuggerUrl` field. Deploy the provided Sigma rule to detect this activity.
