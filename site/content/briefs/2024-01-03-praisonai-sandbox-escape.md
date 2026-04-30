---
title: PraisonAI SubprocessSandbox Shell Escape via sh/bash
slug: 2024-01-03-praisonai-sandbox-escape
description: PraisonAI's SubprocessSandbox allows attackers to bypass command restrictions due to the use of `shell=True` in `subprocess.run()` combined with an insufficient blocklist that does not include `sh` or `bash`, enabling command execution via `sh -c '<command>'`.
date: "2026-04-01T23:26:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox-escape
  - command-injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://github.com/advisories/GHSA-r4f2-3m54-pp7q
rules:
  - title: Detect sh/bash Command Execution with -c Option
    description: Detects the execution of sh or bash with the -c option, which is often used to execute commands from a string, potentially bypassing security restrictions.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI SubprocessSandbox Escape Attempt
    description: Detects command line arguments indicative of an attempt to bypass PraisonAI's SubprocessSandbox by invoking sh/bash with a command string.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI's `SubprocessSandbox`, even in STRICT mode, is vulnerable to a sandbox escape. The vulnerability arises from the use of `subprocess.run()` with `shell=True` in `sandbox_executor.py`, coupled with an insufficient blocklist that fails to include `sh` and `bash` as standalone executables. This oversight allows attackers to bypass the intended command restrictions by executing arbitrary commands through `sh -c '<command>'`.  Versions of PraisonAI up to 4.5.96 are affected. This means that any command blocked by the configured policy can be trivially executed, which could allow agent prompt injection attacks to lead to full system compromise.

## Attack Chain

1. An attacker crafts a malicious command to be executed within the PraisonAI environment.
2. The PraisonAI application receives the crafted command and attempts to execute it within the `SubprocessSandbox`.
3. The `SubprocessSandbox` uses `subprocess.run()` with `shell=True` to execute the provided command.
4. The blocklist in `sandbox_executor.py` fails to block the `sh` or `bash` commands themselves.
5. The attacker injects shell commands via `sh -c '<blocked_command>'`, bypassing the string-pattern matching intended to restrict execution.
6. The `sh` process executes the attacker's command within the sandbox's context, bypassing the intended security restrictions.
7. The attacker gains unauthorized access to resources such as network connections, the filesystem, or cloud metadata services.
8. The attacker escalates privileges and potentially compromises the entire system.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass the intended security restrictions imposed by the PraisonAI `SubprocessSandbox`, even in its strictest configuration. This could lead to privilege escalation, unauthorized access to sensitive data, and the potential compromise of the entire system. Specifically, an attacker could leverage this escape to access network resources, manipulate the filesystem, or extract sensitive information from cloud metadata services. The lack of effective sandboxing could have severe consequences for environments relying on PraisonAI for secure execution of untrusted code.

## Recommendation

*   Apply the suggested fix of using `shlex.split()` and `shell=False` when calling `subprocess.run()` to prevent shell command injection (reference: suggested fix code block).
*   Upgrade PraisonAI to a version beyond 4.5.96 to incorporate the patch for CVE-2026-34955 (reference: CVE-2026-34955).
*   Deploy the provided Sigma rule to detect the execution of `sh` or `bash` with the `-c` option, which is indicative of attempts to bypass command restrictions (reference: Sigma rule "Detect sh/bash Command Execution with -c Option").
*   Implement a more comprehensive blocklist that includes `sh` and `bash` as standalone executables in addition to dangerous patterns (reference: `sandbox_executor.py:179`).
