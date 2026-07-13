---
title: OpenClaw Policy Bypass Vulnerability in Browser CDP Discovery
slug: 2026-07-openclaw-cdp-bypass
description: OpenClaw before version 2026.6.6 contains a policy bypass vulnerability in its browser CDP discovery feature that allows attackers with lower-trust access to circumvent network blocking policies by accepting WebSocket URLs that should have been blocked, enabling them to reach otherwise restricted network destinations when the affected feature is enabled.
date: "2026-07-13T22:28:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - policy-bypass
  - ssrf
vendors:
  - OpenClaw
products:
  - OpenClaw < 2026.6.6
cves:
  - id: CVE-2026-62197
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62197
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-3x84-qq85-fj65
  - https://www.vulncheck.com/advisories/openclaw-policy-bypass-via-cdp-discovery
---

OpenClaw, a browser automation framework, contains a critical policy bypass vulnerability, CVE-2026-62197, affecting versions prior to 2026.6.6. This flaw resides within its browser CDP (Chrome DevTools Protocol) discovery feature, which improperly accepts WebSocket URLs that are explicitly configured to be blocked by the OpenClaw policy. The vulnerability allows attackers who have lower-trust access to the OpenClaw environment to circumvent established network security controls. By exploiting this weakness, malicious actors can reach internal or otherwise restricted network destinations that should be inaccessible according to the defined OpenClaw policies. This can lead to Server-Side Request Forgery (SSRF) and enable unauthorized access to sensitive internal services or data. The vulnerability was published on July 13, 2026, and carries a CVSS 3.1 base score of 8.5 (High), indicating its severe potential impact on systems where the affected feature is enabled.

## Impact

Successful exploitation of CVE-2026-62197 allows an attacker with lower-trust access to bypass network restrictions within the OpenClaw environment. This policy bypass can enable attackers to initiate connections to internal network resources that should otherwise be blocked, effectively turning the OpenClaw instance into a proxy for Server-Side Request Forgery (SSRF) attacks (CWE-918). The primary damage involves unauthorized access to sensitive internal services, data exfiltration from private networks, or further compromise of internal systems, depending on the accessed targets. The vulnerability poses a significant risk to organizations using OpenClaw in configurations where network isolation is critical, as it directly undermines security policies designed to prevent such unauthorized access. The CVSS 3.1 base score of 8.5 highlights the high severity and potential for significant impact.

## Recommendation

* Patch CVE-2026-62197 immediately by upgrading OpenClaw to version 2026.6.6 or later.
* Review and monitor network connection logs from OpenClaw instances for unusual outbound WebSocket connections to internal or unexpected destinations.
