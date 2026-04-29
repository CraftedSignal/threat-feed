---
title: OpenClaw Agentic Consent Bypass Vulnerability (CVE-2026-41349)
slug: 2026-04-openclaw-bypass
description: OpenClaw before version 2026.3.28 contains an agentic consent bypass vulnerability (CVE-2026-41349) that allows LLM agents to silently disable execution approval via the config.patch parameter, potentially enabling remote attackers to bypass security controls and execute unauthorized operations without user consent.
date: "2026-04-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-41349
  - agentic consent bypass
  - llm
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2026-41349
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41349
  - https://github.com/openclaw/openclaw/commit/76411b2afc4ae721e36c12e0ea24fd23e2fed61e
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-v3qc-wrwx-j3pw
  - https://www.vulncheck.com/advisories/openclaw-agentic-consent-bypass-via-config-patch
rules:
  - title: Detect OpenClaw Config Patch Manipulation
    description: Detects modifications to OpenClaw configuration files that contain 'config.patch', indicating a potential attempt to bypass security controls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
  - title: Detect OpenClaw Unauthorized Execution
    description: Detects execution of critical OpenClaw functions without prior authorization, potentially indicating a bypass of consent mechanisms.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw, a framework for building LLM agents, is vulnerable to an agentic consent bypass. Specifically, versions prior to 2026.3.28 are susceptible to CVE-2026-41349, where an LLM agent can silently disable execution approval through manipulation of the `config.patch` parameter. This vulnerability allows remote attackers to bypass security controls that are meant to ensure user consent before executing operations. The vulnerability was reported on April 23, 2026. Successful exploitation could lead to unauthorized actions being performed by the LLM agent without the user's knowledge or permission, undermining the intended security model of OpenClaw.

## Attack Chain

1.  An attacker gains initial access to an OpenClaw instance or application using it, potentially through compromised credentials or by exploiting another vulnerability.
2.  The attacker crafts a malicious `config.patch` parameter designed to disable execution approval.
3.  The attacker injects the crafted `config.patch` into the OpenClaw configuration, exploiting the vulnerability.
4.  The OpenClaw application processes the modified configuration, effectively bypassing consent checks.
5.  The LLM agent, now operating without consent requirements, initiates unauthorized actions.
6.  These unauthorized actions can include data exfiltration, system modification, or other malicious activities depending on the LLM agent's capabilities.
7.  The attacker monitors the LLM agent's activities, leveraging its capabilities for further malicious purposes.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass intended security controls and execute unauthorized operations. The severity of impact depends on the privileges and capabilities granted to the LLM agent. In a worst-case scenario, an attacker could gain complete control over systems accessible to the LLM agent, leading to significant data breaches, system compromise, or financial loss. While the exact number of affected organizations is unknown, any deployment of OpenClaw before version 2026.3.28 is potentially vulnerable.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to remediate CVE-2026-41349.
*   Implement monitoring for unexpected modifications to the OpenClaw configuration, especially those involving the `config.patch` parameter. Deploy the Sigma rule `Detect OpenClaw Config Patch Manipulation` to detect such modifications.
*   Review and restrict the permissions granted to LLM agents to minimize the potential impact of unauthorized actions.
*   Monitor network traffic for suspicious activity originating from OpenClaw instances. Use the IOC information provided by VulnCheck's advisory for threat hunting.
