---
title: OpenClaw Incomplete Navigation Guard SSRF Bypass (CVE-2026-43580)
slug: 2026-05-openclaw-ssrf-bypass
description: OpenClaw before version 2026.4.10 contains an incomplete navigation guard vulnerability, allowing attackers to trigger navigation without proper SSRF policy enforcement by bypassing post-action security checks via browser interactions like pressKey and type submit flows, potentially leading to unauthorized Server-Side Request Forgery (SSRF).
date: "2026-05-06T20:16:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - web application
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
  - id: CVE-2026-43580
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43580
  - https://github.com/openclaw/openclaw/commit/049acf23cb03e1b92f5c71cd99c6ec5f35cc56fe
  - https://github.com/openclaw/openclaw/commit/5f5b3d733bdd791cb457f838514179e1288b10b3
  - https://github.com/openclaw/openclaw/commit/e0b8ddc1a55185aff1cf9e0e095014d2e4f1d894
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-536q-mj95-h29h
  - https://www.vulncheck.com/advisories/openclaw-incomplete-navigation-guard-coverage-in-browser-interactions
rules:
  - title: Detect OpenClaw SSRF Attempt via Navigation Bypass
    description: Detects potential SSRF attempts in OpenClaw applications by monitoring for suspicious navigation requests containing file:// or similar protocols.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Suspicious Submit Request
    description: Detects suspicious submit requests in OpenClaw applications, which may indicate SSRF exploitation.
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

OpenClaw, a web application framework, is vulnerable to an SSRF bypass due to an incomplete navigation guard implementation. Specifically, versions prior to 2026.4.10 fail to properly enforce SSRF policies when navigation is triggered through browser-style interactions such as `pressKey` and `type submit` flows. This flaw, identified as CVE-2026-43580, allows attackers to potentially bypass intended security checks and initiate unauthorized navigation, potentially accessing internal resources or triggering other backend vulnerabilities. The vulnerability was reported by VulnCheck and affects any application using vulnerable versions of the OpenClaw framework. Successful exploitation requires an attacker to manipulate user input in a way that triggers navigation events handled by the vulnerable code.

## Attack Chain

1. An attacker identifies an OpenClaw application using a version prior to 2026.4.10.
2. The attacker locates an input field or button that triggers a navigation event upon submission.
3. The attacker crafts malicious input designed to bypass the intended SSRF policy enforcement. This could involve specific characters or sequences that are not properly sanitized or validated.
4. The attacker uses browser interaction techniques (e.g., `pressKey` or `type submit` flows) to submit the crafted input, triggering the navigation event.
5. The incomplete navigation guard fails to properly validate the target of the navigation request due to the bypassed security checks.
6. OpenClaw application initiates a request to a server controlled by the attacker (or an internal resource), effectively bypassing SSRF protections.
7. The attacker receives the response from the targeted server.
8. The attacker exploits the data obtained from the targeted server.

## Impact

Successful exploitation of this vulnerability (CVE-2026-43580) can lead to Server-Side Request Forgery (SSRF). An attacker could potentially access sensitive internal resources, such as configuration files, databases, or internal APIs, that are not exposed to the public internet. While the CVSS score indicates no impact to Integrity or Availability directly, the compromise of sensitive internal data can lead to further attacks or data breaches, potentially affecting user data, intellectual property, or critical infrastructure. The number of affected installations depends on the adoption rate of OpenClaw before the patch.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.10 or later to remediate CVE-2026-43580 by applying the patches referenced in the advisory URLs.
*   Inspect web server logs for unusual navigation patterns, especially those originating from browser-style interactions as a compensating control. Create a detection rule monitoring for these patterns (see example Sigma rule below).
*   Implement strict input validation and sanitization on all user-provided data to prevent attackers from crafting malicious navigation requests.
*   Review and harden SSRF policies within the OpenClaw application to ensure comprehensive coverage of all navigation paths, including those triggered by browser interactions.
