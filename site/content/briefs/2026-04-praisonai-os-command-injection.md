---
title: PraisonAI OS Command Injection Vulnerability (CVE-2026-34937)
slug: 2026-04-praisonai-os-command-injection
description: PraisonAI versions prior to 1.5.90 are vulnerable to OS Command Injection (CVE-2026-34937) due to insufficient escaping in the run_python() function, allowing arbitrary OS command execution via shell interpolation.
date: "2026-04-03T23:17:06Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-34937
  - os command injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34937
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34937
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-w37c-qqfp-c67f
rules:
  - title: Detect PraisonAI OS Command Injection Attempt
    description: Detects potential OS command injection attempts in PraisonAI by monitoring for suspicious process executions originating from the PraisonAI application.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Subprocess Execution via PraisonAI
    description: Detects potential OS command injection attempts by monitoring for suspicious subprocess.run calls with shell=True in PraisonAI processes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to an OS command injection vulnerability affecting versions prior to 1.5.90. The vulnerability, identified as CVE-2026-34937, stems from the `run_python()` function's construction of shell command strings. This function interpolates user-controlled code into a `python3 -c "<code>"` command and executes it using `subprocess.run(..., shell=True)`. The inadequate escaping logic, specifically the failure to escape `$()` and backtick substitutions, enables arbitrary OS command execution prior to Python's invocation. Users of PraisonAI are urged to upgrade to version 1.5.90 or later to mitigate this risk.

## Attack Chain

1. An attacker identifies an instance of PraisonAI running a version prior to 1.5.90.
2. The attacker crafts malicious code containing OS command injection payloads using `$()` or backticks.
3. The attacker injects the malicious code into a parameter or input field that is processed by the `run_python()` function.
4. The `run_python()` function constructs the shell command string, interpolating the attacker's malicious code without proper escaping.
5. The `subprocess.run()` function executes the crafted shell command with `shell=True`.
6. The attacker's OS command is executed on the host system with the privileges of the PraisonAI application.
7. The attacker gains unauthorized access to the system, potentially enabling data exfiltration, system modification, or denial of service.

## Impact

Successful exploitation of this vulnerability (CVE-2026-34937) allows an attacker to execute arbitrary OS commands on the system running PraisonAI. This could lead to complete system compromise, data breaches, or denial of service. The severity is high because it allows unauthenticated or low-privileged users to gain complete control of the system. Organizations using affected versions of PraisonAI are at risk of significant data loss and reputational damage.

## Recommendation

*   Immediately upgrade PraisonAI to version 1.5.90 or later to patch CVE-2026-34937.
*   Deploy the Sigma rule "Detect PraisonAI OS Command Injection Attempt" to your SIEM to identify potential exploitation attempts.
*   Monitor process creation events for the execution of unexpected processes originating from the PraisonAI application to detect post-exploitation activity.
