---
title: OpenClaw SSRF Vulnerability Allows Private Network Access (CVE-2026-43527)
slug: 2026-05-openclaw-ssrf
description: OpenClaw before 2026.4.14 contains a server-side request forgery vulnerability due to a misconfigured browser SSRF policy, allowing attackers to access internal services via browser-driven requests.
date: "2026-05-05T12:16:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-43527
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
  - id: CVE-2026-43527
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43527
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-53vx-pmqw-863c
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-via-private-network-navigation
rules:
  - title: Detect OpenClaw SSRF Attempt
    description: Detects potential SSRF attempts by monitoring requests made through OpenClaw to internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Private Network Navigation
    description: Detects attempts to navigate to private network addresses using OpenClaw, indicating potential SSRF exploitation.
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

OpenClaw versions prior to 2026.4.14 are susceptible to a server-side request forgery (SSRF) vulnerability, identified as CVE-2026-43527. The vulnerability stems from a default configuration that permits private-network navigation within the browser's SSRF policy. This flaw allows attackers to potentially bypass network restrictions and gain unauthorized access to internal services, resources, and metadata endpoints within the targeted environment. By crafting malicious browser-driven requests, an attacker can leverage the OpenClaw instance to probe and interact with systems that should otherwise be inaccessible from the public internet, potentially leading to information disclosure or further exploitation.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a version prior to 2026.4.14.
2.  Attacker crafts a malicious URL that targets an internal service or metadata endpoint.
3.  Attacker induces a user to access the malicious URL through the OpenClaw application. This may involve social engineering.
4.  OpenClaw, due to the misconfigured SSRF policy, processes the request without proper validation.
5.  OpenClaw sends a request to the internal service specified in the malicious URL.
6.  The internal service responds to the OpenClaw instance.
7.  OpenClaw relays the response back to the attacker-controlled endpoint, potentially exposing sensitive information.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-43527) could allow an attacker to gain unauthorized access to internal systems and data. This could lead to the disclosure of sensitive information, such as configuration details, API keys, or internal documentation. The vulnerability could also be leveraged to perform other attacks against internal services, such as remote code execution or denial-of-service. The severity of the impact depends on the sensitivity of the data exposed and the nature of the internal services that are accessible.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.14 or later to remediate CVE-2026-43527.
*   Implement the provided Sigma rule `Detect OpenClaw SSRF Attempt` to identify potential exploitation attempts.
*   Review and harden SSRF policies within OpenClaw configurations to restrict access to internal networks.
