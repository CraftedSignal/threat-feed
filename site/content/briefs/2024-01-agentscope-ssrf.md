---
title: Modelscope Agentscope Server-Side Request Forgery Vulnerability (CVE-2026-6606)
slug: 2024-01-agentscope-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in Modelscope Agentscope versions up to 1.0.18, allowing remote attackers to manipulate the 'url' argument in the `_process_audio_block` function, potentially leading to unauthorized internal resource access or external interaction.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ssrf
  - agentscope
  - cve-2026-6606
  - vulnerability
vendors:
  - Modelscope
products:
  - Agentscope
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6606
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6606
rules:
  - title: Detect Agentscope SSRF Attempt via URL Manipulation
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in Modelscope Agentscope by monitoring web server logs for requests to the `_process_audio_block` function with suspicious URLs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Agentscope SSRF Attempt via Internal IP Address
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in Modelscope Agentscope by monitoring web server logs for requests to the `_process_audio_block` function with internal IP addresses in the URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-6606, affects Modelscope Agentscope versions up to 1.0.18. This flaw resides within the `_process_audio_block` function located in `src/agentscope/agent/_agent_base.py`. A remote attacker can exploit this vulnerability by manipulating the `url` argument passed to this function. Successful exploitation allows the attacker to potentially force the application to make requests to internal resources or external services on their behalf, bypassing security controls and potentially leading to information disclosure or further compromise. The vulnerability has a CVSS v3.1 base score of 7.3, indicating a significant risk. The exploit is publicly available, which increases the likelihood of active exploitation attempts. The vendor was contacted but did not respond.

## Attack Chain

1. An attacker identifies a Modelscope Agentscope instance running a vulnerable version (<= 1.0.18).
2. The attacker crafts a malicious `url` argument containing a target internal IP address or hostname or an external service URL controlled by the attacker.
3. The attacker sends a request to the Agentscope application, triggering the `_process_audio_block` function with the crafted `url` argument.
4. The `_process_audio_block` function, without proper validation of the `url`, attempts to make a request to the URL specified in the `url` argument.
5. If the `url` points to an internal resource, the Agentscope application unwittingly accesses the internal resource and potentially returns sensitive information to the attacker.
6. If the `url` points to an external service controlled by the attacker, the Agentscope application makes a request to the attacker's server, potentially leaking internal network information or application secrets via HTTP headers or the request body.
7. The attacker analyzes the response from the Agentscope application to gain access to sensitive information or internal resources.
8. The attacker uses the gained information to further compromise the application or internal network.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-6606) can allow an attacker to read internal files, access internal services, or interact with external systems from the perspective of the vulnerable application. This can lead to information disclosure, such as internal configuration files, API keys, or sensitive data stored within the application's environment. It could also be leveraged to perform further attacks, such as port scanning of the internal network or compromising other internal services. The impact is highly dependent on the specific internal resources accessible from the vulnerable application.

## Recommendation

*   Upgrade Modelscope Agentscope to a version greater than 1.0.18 to patch CVE-2026-6606.
*   Deploy the Sigma rule `Detect Agentscope SSRF Attempt via URL Manipulation` to your SIEM to detect potential exploitation attempts by monitoring web server logs for suspicious URL patterns.
*   Implement strict input validation and sanitization for the `url` argument in the `_process_audio_block` function to prevent SSRF attacks.
*   Configure network segmentation and firewall rules to restrict access from the Agentscope application to only necessary internal resources to minimize the impact of a successful SSRF attack.
