---
title: OpenClaw Insufficient Environment Variable Denylist Vulnerability (CVE-2026-43584)
slug: 2026-05-openclaw-env-vuln
description: OpenClaw before 2026.4.10 is vulnerable to an insufficient environment variable denylist, allowing attackers to manipulate interpreter startup variables to influence execution behavior or network connectivity.
date: "2026-05-06T20:16:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - environment-variable
  - code-execution
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
cves:
  - id: CVE-2026-43584
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43584
  - https://github.com/openclaw/openclaw/commit/2d126fc62343a7b6895351f96e4e1474bc358140
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vfp4-8x56-j7c5
  - https://www.vulncheck.com/advisories/openclaw-insufficient-environment-variable-denylist-in-exec-policy
rules:
  - title: Detect Process Creation with VIMINIT Environment Variable
    description: Detects process creation with the VIMINIT environment variable set, indicating potential exploitation of CVE-2026-43584.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Creation with EXINIT Environment Variable
    description: Detects process creation with the EXINIT environment variable set, indicating potential exploitation of CVE-2026-43584.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Creation with LUA_INIT Environment Variable
    description: Detects process creation with the LUA_INIT environment variable set, indicating potential exploitation of CVE-2026-43584.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

OpenClaw before version 2026.4.10 contains a vulnerability related to an insufficient environment variable denylist within its exec environment policy. This flaw allows attackers with some level of control to override high-risk interpreter startup variables, specifically VIMINIT, EXINIT, LUA_INIT, and HOSTALIASES. By manipulating these environment variables, an attacker can influence the behavior of downstream processes and potentially alter network connectivity. This vulnerability, identified as CVE-2026-43584, poses a significant risk as it enables attackers to inject malicious configurations into system processes.

## Attack Chain

1.  Attacker gains initial access to a system where they can set environment variables.
2.  Attacker identifies that OpenClaw is running in a vulnerable version (prior to 2026.4.10).
3.  Attacker crafts a malicious payload that leverages interpreter-specific startup variables, such as VIMINIT to execute arbitrary code.
4.  Attacker sets the environment variable (e.g., VIMINIT) to point to their malicious payload.
5.  OpenClaw executes a process that utilizes the affected interpreter (e.g., vim).
6.  The interpreter reads the attacker-controlled environment variable (e.g., VIMINIT) and executes the malicious code.
7.  Attacker achieves arbitrary code execution within the context of the OpenClaw process.
8.  The attacker uses the gained code execution to move laterally within the network or exfiltrate sensitive data.

## Impact

Successful exploitation of this vulnerability allows attackers to inject arbitrary code into processes managed by OpenClaw. This can lead to complete compromise of the affected system, potentially allowing for lateral movement within the network and exfiltration of sensitive information. The impact is high, as it grants attackers the ability to bypass security controls and execute malicious operations with elevated privileges.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.10 or later to remediate CVE-2026-43584.
*   Implement strict input validation and sanitization for environment variables used by OpenClaw.
*   Monitor process creation events for unexpected interpreter processes (vim, lua) launched with suspicious environment variables using the Sigma rules provided below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
