---
title: NousResearch hermes-agent Injection Vulnerability (CVE-2026-9366)
slug: 2026-05-nousresearch-injection
description: A remote injection vulnerability exists in NousResearch hermes-agent 2026.4.23 within the _scan_context_content function of the agent/prompt_builder.py file, allowing attackers to inject malicious code.
date: "2026-05-26T13:46:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - injection
  - hermes-agent
vendors:
  - NousResearch
products:
  - hermes-agent (2026.4.23)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9366
    cvss: 7.3
    epss: 0.00044
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9366
  - https://gist.github.com/YLChen-007/581fd92de5548fbaacb2092e848a75cc
  - https://vuldb.com/submit/812227
  - https://vuldb.com/vuln/365329
  - https://vuldb.com/vuln/365329/cti
rules:
  - title: Detect CVE-2026-9366 Exploitation Attempt - Suspicious Input to hermes-agent
    description: Detects CVE-2026-9366 exploitation attempt - suspicious input to the _scan_context_content function in hermes-agent via web request with injection-like patterns
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9366 Exploitation Attempt - Process Creation from hermes-agent with Suspicious Arguments
    description: Detects CVE-2026-9366 exploitation attempt - process creation by hermes-agent process with suspicious arguments indicative of code injection
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability, identified as CVE-2026-9366, has been discovered in NousResearch hermes-agent version 2026.4.23. This injection vulnerability resides within the _scan_context_content function located in the agent/prompt_builder.py file. The vulnerability can be exploited remotely, and publicly available exploits exist. The vendor was contacted about the disclosure but did not respond. This vulnerability matters because it allows attackers to inject malicious code into the application potentially leading to arbitrary code execution.

## Attack Chain

1.  Attacker identifies a vulnerable instance of NousResearch hermes-agent running version 2026.4.23.
2.  Attacker crafts a malicious input string designed to exploit the injection vulnerability in the `_scan_context_content` function.
3.  Attacker sends the crafted input to the vulnerable function, potentially through a network request or API call.
4.  The `_scan_context_content` function fails to properly neutralize special elements within the input, leading to code injection.
5.  The injected code is executed within the context of the hermes-agent application.
6.  The attacker gains control over parts of the application.
7.  The attacker escalates privileges within the application.
8.  The attacker achieves arbitrary code execution on the server.

## Impact

Successful exploitation of CVE-2026-9366 can allow an attacker to execute arbitrary code on the server running NousResearch hermes-agent. The affected version is 2026.4.23. Given the nature of injection vulnerabilities, it's plausible that attackers could leverage this to gain full control over the system, potentially leading to data breaches, service disruption, or further lateral movement within the network.

## Recommendation

*   Upgrade NousResearch hermes-agent to a patched version that addresses CVE-2026-9366 (no version available).
*   Implement input validation and sanitization for the `_scan_context_content` function in `agent/prompt_builder.py` to prevent injection attacks.
*   Monitor network traffic for suspicious patterns and payloads targeting the hermes-agent application.
*   Deploy the Sigma rules provided below to your SIEM to detect potential exploitation attempts of CVE-2026-9366.
*   Enable and review application logs for anomalies related to the `_scan_context_content` function.
