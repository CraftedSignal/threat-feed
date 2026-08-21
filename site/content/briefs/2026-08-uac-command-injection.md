---
title: Command Injection in Unix-like Artifacts Collector
slug: 2026-08-uac-command-injection
description: Unix-like Artifacts Collector (UAC) versions prior to 3.3.0 are vulnerable to command injection via the _command_collector function, allowing arbitrary command execution through malicious filenames or artifact definitions.
date: "2026-08-21T19:26:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - command-injection
  - forensic-tooling
vendors:
  - UAC
products:
  - Unix-like Artifacts Collector
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can exploit this by crafting malicious filenames or artifact definitions containing shell metacharacters such as command substitution syntax or semicolons to execute arbitrary commands on the analyst's host system.
    confidence_band: high
cves:
  - id: CVE-2026-41450
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41450
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Incident Response
  immediate_actions:
    - action: Patch all UAC deployments to version 3.3.0 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-41450 remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict UAC execution to low-privileged service accounts on analyst machines.
      owner: IT Operations
      addresses: CVE-2026-41450
      evidence: Vulnerability involves arbitrary command execution via user-supplied input
---

Unix-like Artifacts Collector (UAC) versions prior to 3.3.0 contain a command injection vulnerability within the _command_collector function. The vulnerability arises because lines of command output are processed through a sed command and subsequently evaluated using the shell eval command without sufficient input sanitization. An attacker capable of influencing the filenames or the contents of artifact definitions can inject shell metacharacters, such as command substitution syntax or semicolons, to execute arbitrary code with the privileges of the user running the collection script. This poses a significant risk to forensic analysts, as UAC is frequently executed on compromised systems where malicious artifacts may be present specifically to target investigative tooling.

## Attack Chain

1. An attacker gains initial access to a target system and anticipates forensic investigation using UAC.
2. The attacker creates malicious files or modifies artifact definitions containing shell metacharacters (e.g., $(id), ;rm -rf /).
3. A forensic analyst initiates a UAC collection run on the compromised host.
4. The UAC script invokes the _command_collector function to process system artifacts.
5. The collector reads the attacker-controlled filenames or artifact contents containing the malicious payload.
6. The vulnerability in _command_collector passes these strings through sed and subsequently to eval without escaping.
7. The shell interprets the injected metacharacters, executing arbitrary commands under the context of the user running the UAC script.

## Impact

Successful exploitation allows for arbitrary command execution on the analyst's machine. Given that UAC is intended for forensic acquisition, this vulnerability could be used by an attacker to compromise the forensic workstation, potentially leading to the modification of evidence, exfiltration of collected forensic data, or lateral movement within the incident response infrastructure.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Upgrade all instances of UAC to version 3.3.0 or later to patch the underlying vulnerability in _command_collector.
* Audit existing custom artifact definitions for shell metacharacters and unusual patterns that could trigger the eval-based injection.
* Monitor execution logs for UAC processes where the command line contains suspicious shell operators, which may indicate an attempt to weaponize artifact collection against an analyst.
