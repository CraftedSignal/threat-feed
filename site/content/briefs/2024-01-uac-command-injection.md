---
title: UAC (Unix-like Artifacts Collector) Command Injection Vulnerability
slug: 2024-01-uac-command-injection
description: UAC before 3.3.0-rc1 is vulnerable to command injection in the _run_command() function, allowing attackers to execute arbitrary commands with the privileges of the UAC process through manipulated input values.
date: "2026-04-08T22:16:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - uac
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40032
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40032
rules:
  - title: Detect Suspicious Processes Spawned by UAC
    description: Detects suspicious processes spawned by UAC, indicating potential command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect UAC Executing Eval
    description: Detects the execution of `eval` commands from the UAC (Unix-like Artifacts Collector) process, which is indicative of potential command injection exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

UAC (Unix-like Artifacts Collector) before version 3.3.0-rc1 is susceptible to a command injection vulnerability. This flaw resides in the placeholder substitution and command execution pipeline within the application. Specifically, the `_run_command()` function directly passes constructed command strings to `eval` without proper sanitization. This lack of input validation allows attackers to inject malicious shell metacharacters or command substitutions into the command strings. Exploitation is possible through attacker-controlled inputs such as `%line%` values from `foreach` iterators and `%user%` / `%user_home%` values derived from system files. Successful exploitation leads to arbitrary command execution with the same privileges as the UAC process. This poses a significant risk to system integrity and confidentiality.

## Attack Chain

1.  Attacker identifies a vulnerable UAC instance running a version prior to 3.3.0-rc1.
2.  Attacker crafts a malicious input string containing shell metacharacters or command substitutions, targeting either `%line%` values in `foreach` iterators, or the `%user%` and `%user_home%` values.
3.  The attacker-controlled input is passed to UAC, potentially via a configuration file, command-line argument, or other input mechanism.
4.  UAC's `_run_command()` function receives the malicious input and performs placeholder substitution.
5.  The resulting command string, now containing the injected commands, is passed to the `eval` function without proper sanitization.
6.  The `eval` function executes the attacker-injected commands with the privileges of the UAC process.
7.  The attacker gains arbitrary code execution on the system.
8.  The attacker can then perform actions such as data exfiltration, system compromise, or lateral movement within the network.

## Impact

The command injection vulnerability in UAC before 3.3.0-rc1 allows attackers to execute arbitrary commands on the affected system. The impact of successful exploitation includes complete system compromise, data breaches, and potential for lateral movement to other systems within the network. Since UAC is used to collect artifacts, successful exploitation could lead to the collection of sensitive data from the compromised system, which could then be exfiltrated. The specific number of potential victims is unknown.

## Recommendation

*   Upgrade UAC to version 3.3.0-rc1 or later to patch CVE-2026-40032.
*   Implement input validation and sanitization for all user-supplied input, particularly those used in command construction and execution, to prevent command injection vulnerabilities.
*   Monitor process execution for unexpected or unauthorized commands originating from the UAC process, using the Sigma rules provided below.
