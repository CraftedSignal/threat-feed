---
title: OpenClaw QQ Bot Media Download SSRF Vulnerability
slug: 2026-04-openclaw-ssrf
description: OpenClaw before 2026.4.8 is vulnerable to server-side request forgery (SSRF) in QQ Bot media download paths, allowing attackers to bypass SSRF protections and access internal resources.
date: "2026-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-41914
  - openclaw
vendors:
  - openclaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1068
    technique_name: Proxy
cves:
  - id: CVE-2026-41914
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41914
  - https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-3fv3-6p2v-gxwj
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-in-qq-bot-media-fetch-paths
rules:
  - title: Detect Suspicious OpenClaw SSRF Attempt
    description: Detects potential SSRF attempts in OpenClaw QQ Bot media download paths by monitoring for requests to internal IP addresses or unexpected domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Version Prior to 2026.4.8 in User Agent
    description: Detects OpenClaw versions prior to 2026.4.8 based on the User-Agent header, indicating a potentially vulnerable system.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a QQ Bot platform, is susceptible to a server-side request forgery (SSRF) vulnerability. This flaw exists in versions prior to 2026.4.8 within the media download paths of the QQ Bot functionality. Specifically, the vulnerability allows attackers to bypass existing SSRF protections. By exploiting unprotected media fetch endpoints, malicious actors can potentially gain unauthorized access to internal resources and circumvent established allowlist policies. This vulnerability poses a significant risk to the confidentiality and integrity of systems and data accessible from the OpenClaw server. Successful exploitation can lead to information disclosure, denial of service, or even remote code execution on internal systems, depending on the accessible resources.

## Attack Chain

1. The attacker identifies an OpenClaw instance running a version prior to 2026.4.8.
2. The attacker crafts a malicious URL targeting the QQ Bot media download functionality. This URL contains a payload designed to exploit the SSRF vulnerability.
3. The attacker injects the malicious URL into the QQ Bot's media download path, bypassing expected SSRF protections.
4. OpenClaw processes the crafted URL without proper validation, initiating a request to an attacker-controlled internal resource.
5. The OpenClaw server makes a request to the specified internal resource, potentially exposing sensitive information or triggering unintended actions.
6. The internal resource responds to the OpenClaw server, and the response is potentially relayed back to the attacker or used to further compromise the system.
7. The attacker gains unauthorized access to internal resources or sensitive data due to the successful SSRF attack.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-41914) can lead to the disclosure of sensitive information from internal systems, potentially affecting all users and services dependent on the compromised OpenClaw instance. The severity is amplified by the potential to bypass existing SSRF protections, increasing the attack surface and difficulty of detection. Impact ranges from information disclosure to potential compromise of other internal services, depending on the specific internal resources accessible from the OpenClaw server.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to patch the SSRF vulnerability (CVE-2026-41914).
*   Deploy the Sigma rule `Detect Suspicious OpenClaw SSRF Attempt` to identify potential exploitation attempts targeting the vulnerable media download paths.
*   Implement strict network segmentation to limit the impact of a successful SSRF attack by restricting access to sensitive internal resources from the OpenClaw server.
