---
title: OpenClaw SSRF Policy Bypass Vulnerability (CVE-2026-43573)
slug: 2026-05-openclaw-ssrf
description: OpenClaw before version 2026.4.10 is vulnerable to a server-side request forgery (SSRF) policy bypass, allowing attackers to bypass navigation guards and interact with unauthorized targets.
date: "2026-05-05T12:16:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-43573
  - vulnerability
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
  - id: CVE-2026-43573
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43573
  - https://github.com/openclaw/openclaw/commit/daeb74920d5ad986cb600625180037e23221e93a
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-527m-976r-jf79
  - https://www.vulncheck.com/advisories/openclaw-ssrf-policy-bypass-in-existing-session-browser-interaction-routes
rules:
  - title: OpenClaw SSRF Attempt
    description: Detects potential SSRF attacks against OpenClaw by monitoring for suspicious requests in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: OpenClaw SSRF - Suspicious Referer Header
    description: Detects potential SSRF attempts against OpenClaw by monitoring for requests with a suspicious Referer header pointing to an internal resource.
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

OpenClaw versions prior to 2026.4.10 are susceptible to a server-side request forgery (SSRF) policy bypass vulnerability, identified as CVE-2026-43573. This flaw exists in the existing-session browser interaction routes, enabling attackers to circumvent SSRF navigation guards. Successful exploitation allows an attacker to interact with or navigate to unauthorized targets without the intended policy enforcement. This vulnerability could lead to the exposure of sensitive information, unauthorized access to internal resources, or further exploitation of other system components. Defenders need to ensure OpenClaw instances are updated to the latest version to mitigate this risk.

## Attack Chain

1. An attacker identifies an OpenClaw instance running a version prior to 2026.4.10.
2. The attacker crafts a malicious request targeting an existing user session within the OpenClaw application.
3. The crafted request is designed to exploit the SSRF policy bypass in the browser interaction routes.
4. The vulnerable code fails to properly enforce SSRF navigation guards during browser interaction.
5. The attacker is able to bypass the intended SSRF protections and initiate requests to unauthorized internal or external targets.
6. The OpenClaw server processes the attacker-initiated request without proper validation.
7. The attacker interacts with or navigates to unauthorized targets, potentially gaining access to sensitive information or internal resources.
8. The attacker may leverage the compromised session to further escalate privileges or perform other malicious activities within the network.

## Impact

Successful exploitation of CVE-2026-43573 allows attackers to bypass SSRF protections in OpenClaw, potentially leading to unauthorized access to sensitive data or internal resources. The impact depends on the specific configurations and network architecture of the affected OpenClaw deployment, but could include exposure of confidential information, disruption of services, or further compromise of internal systems.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.10 or later to patch the SSRF policy bypass vulnerability (CVE-2026-43573).
*   Deploy the Sigma rule "OpenClaw SSRF Attempt" to detect exploitation attempts targeting the vulnerable browser interaction routes.
*   Review and harden existing session management policies in OpenClaw to prevent unauthorized session access.
