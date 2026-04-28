---
title: PraisonAI Subprocess Sandbox Escape Vulnerability (CVE-2026-34955)
slug: 2026-04-praisonai-rce
description: PraisonAI versions prior to 4.5.97 are vulnerable to OS Command Injection (CVE-2026-34955) due to insufficient input validation in the SubprocessSandbox, allowing for trivial sandbox escapes.
date: "2026-04-04T00:16:19Z"
severities:
  - critical
tags:
  - cve
  - rce
  - sandbox-escape
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2026-34955
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34955
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-r4f2-3m54-pp7q
rules:
  - title: Detect PraisonAI Sandbox Escape via sh or bash
    description: Detects attempts to escape the PraisonAI SubprocessSandbox by executing commands through `sh` or `bash`.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Process Spawning Shell
    description: Detects PraisonAI processes spawning a shell, which may indicate a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, contains a critical vulnerability (CVE-2026-34955) in versions prior to 4.5.97. The vulnerability lies within the SubprocessSandbox, which is responsible for executing subprocesses in a controlled environment. The SubprocessSandbox, regardless of its configured mode (BASIC, STRICT, NETWORK_ISOLATED), uses `subprocess.run()` with `shell=True`. This approach, coupled with a reliance on simple string-pattern matching for command blocking, creates an exploitable condition. Specifically, the blocklist fails to include `sh` or `bash` as standalone executables. This omission enables attackers to bypass the sandbox restrictions in STRICT mode by executing commands through `sh -c '<command>'`. The vulnerability has been patched in version 4.5.97. This vulnerability could allow an attacker to execute arbitrary commands on the underlying system.

## Attack Chain

1.  Attacker identifies a PraisonAI instance running a version prior to 4.5.97.
2.  Attacker crafts a malicious payload designed to be executed within the SubprocessSandbox.
3.  The payload leverages the `sh -c` command to bypass the insufficient blocklist.
4.  PraisonAI executes the crafted payload using `subprocess.run()` with `shell=True`.
5.  The `sh` interpreter executes the command provided within the `-c` argument.
6.  The attacker gains arbitrary code execution within the context of the PraisonAI process.
7.  The attacker leverages the initial foothold to escalate privileges.
8.  The attacker achieves complete control over the system, potentially leading to data exfiltration, system compromise, or denial of service.

## Impact

Successful exploitation of CVE-2026-34955 allows an attacker to execute arbitrary commands on the system hosting PraisonAI. This can lead to complete system compromise, data exfiltration, or denial of service. Given the nature of multi-agent systems, a compromised PraisonAI instance could be used to pivot to other systems or data sources accessible to the compromised agent. While the number of affected installations is unknown, any organization using vulnerable versions of PraisonAI is at risk.

## Recommendation

*   Upgrade PraisonAI to version 4.5.97 or later to remediate CVE-2026-34955.
*   Deploy the Sigma rule "Detect PraisonAI Sandbox Escape via sh or bash" to identify exploitation attempts in your environment.
*   Review the PraisonAI SubprocessSandbox configuration to ensure that the most restrictive mode (NETWORK_ISOLATED) is enabled where possible.
*   If upgrading is not immediately feasible, consider implementing a compensating control that blocks the execution of `sh` and `bash` commands at the system level.
