---
brief_id: brief-2026-06-flowise-os-command-injection
event_id: brief-2026-06-flowise-os-command-injection
revision: 1
activity_at: "2026-06-23T13:27:56Z"
title: Flowise OS Command Injection Vulnerabilities (CVE-2026-56274)
slug: 2026-06-flowise-os-command-injection
description: Multiple OS command injection vulnerabilities exist in Flowise versions prior to 3.1.2, specifically within the Custom MCP Server feature, allowing attackers with any Flowise account role or API access to bypass command-flag validation and local file access restrictions to execute arbitrary commands on the Flowise host via crafted malicious MCP server configurations.
date: "2026-06-23T13:27:56Z"
lastmod: "2026-11-14T19:03:35Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-FLOWISE_CVE_2026_56274_DETECT&utm_source=rss&utm_medium=rss
tags:
  - os-command-injection
  - vulnerability
  - flowise
  - web-application
vendors:
  - FlowiseAI
products:
  - Flowise
product_versions:
  - product: Flowise
    range: < 3.1.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execution of arbitrary commands on the Flowise host
    confidence_band: high
cve_verification:
  CVE-2026-56274:
    status: verified
    source: cve_program
    checked_at: 2026-11-14T19:03:35.943423934Z
cves:
  - id: CVE-2026-56274
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56274
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-FLOWISE_CVE_2026_56274_DETECT&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-56274 Exploitation — Suspicious Commands from Flowise
    description: Detects CVE-2026-56274 exploitation by identifying the execution of commands explicitly mentioned as bypass vectors ('docker build', 'npx --yes') which should not be spawned by a typical Flowise application process during normal operation, indicating OS command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
rules_count: 1
updates:
  - at: "2026-11-14T19:03:35Z"
    level: L2
    summary: poc_available; added CVE-2026-56274
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-FLOWISE_CVE_2026_56274_DETECT&utm_source=rss&utm_medium=rss
---

## Overview

Flowise versions prior to 3.1.2 are susceptible to multiple OS command injection vulnerabilities (CVE-2026-56274) found within its Custom MCP Server feature. This critical vulnerability allows an attacker, who has an authenticated Flowise account of any role or API access with view/update permissions for chatflows, to execute arbitrary commands on the underlying host system. The exploitation stems from incomplete blocklisting in the `validateCommandFlags` function, which fails to block commands such as `'docker build'` and `'npx --yes'` (while only `'-y'` is blocked), coupled with a regex bypass that circumvents `validateArgsForLocalFileAccess` checks. These weaknesses enable attackers to craft malicious Custom MCP server configurations that lead to full system compromise.

## Attack Chain

1.  **Initial Access / Authentication**: An attacker obtains valid credentials for a Flowise account (any role) or gains API access with view/update permissions for chatflows.
2.  **Configuration Modification (Custom MCP Server)**: The attacker leverages their authenticated access to configure or modify a "Custom MCP Server" within the Flowise environment.
3.  **Command Flag Bypass**: The attacker crafts commands or parameters within the Custom MCP Server configuration that exploit incomplete blocklisting in the `validateCommandFlags` function, specifically using commands like `docker build` or `npx --yes` which are not properly blocked.
4.  **Local File Access Restriction Bypass**: Concurrently or sequentially, the attacker implements a regex bypass within the configuration to evade `validateArgsForLocalFileAccess` restrictions.
5.  **Command Injection Trigger**: The Flowise application processes the malicious Custom MCP Server configuration, leading to the execution of the crafted commands on the host.
6.  **Arbitrary Command Execution**: The Flowise host system executes the attacker-supplied commands, granting the attacker arbitrary code execution capabilities on the underlying operating system.
7.  **Post-Exploitation Actions**: With arbitrary code execution, the attacker can proceed with further malicious activities such as data exfiltration, deployment of additional malware, or establishing persistent access mechanisms.

## Impact

Successful exploitation of CVE-2026-56274 results in arbitrary command execution on the Flowise host system, carrying a CVSS v3.1 Base Score of 9.9 (Critical). This allows attackers to fully compromise the server running Flowise, leading to potential data breaches, denial of service, or the use of the compromised server as a pivot point for further attacks within the network. This vulnerability poses a severe risk to organizations deploying Flowise for their AI/LLM applications, potentially leading to unauthorized access to sensitive data and critical system infrastructure.

## Recommendation

*   Patch CVE-2026-56274 immediately by upgrading Flowise to version 3.1.2 or higher.
*   Enable process creation logging (e.g., Sysmon for Windows, Auditd for Linux) to activate the rules below and monitor for unusual child processes spawned by the Flowise application.
*   Deploy the Sigma rules in this brief to your SIEM and tune them for your environment to detect suspicious command execution.
*   Review existing Custom MCP Server configurations within Flowise for any suspicious commands or patterns indicative of bypass attempts.
