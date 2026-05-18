---
title: Claude HUD Command Injection Vulnerability via COMSPEC Manipulation (CVE-2026-47092)
slug: 2026-05-claude-hud-command-injection
description: Claude HUD through version 0.0.12 is vulnerable to command injection (CVE-2026-47092) allowing a local attacker to execute arbitrary commands on a Windows system by manipulating the COMSPEC environment variable; this vulnerability has been patched in commit 234d9aa.
date: "2026-05-18T20:18:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - windows
vendors:
  - VulnCheck
products:
  - Claude HUD (<= 0.0.12)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2026-47092
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47092
  - https://github.com/jarrodwatts/claude-hud/commit/234d9aad919b51326a43bcf90b45ae35c23afc30
  - https://github.com/jarrodwatts/claude-hud/issues/485
  - https://github.com/jarrodwatts/claude-hud/pull/487
  - https://www.vulncheck.com/advisories/claude-hud-arbitrary-command-execution-via-comspec-environment-variable
rules:
  - title: Detect COMSPEC Environment Variable Modification
    description: Detects modifications to the COMSPEC environment variable, which can be indicative of command injection attempts like CVE-2026-47092.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Suspicious Process Execution via Modified COMSPEC
    description: Detects process execution of unusual executables via cmd.exe based on a non-standard COMSPEC variable, potentially indicating CVE-2026-47092 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Claude HUD through version 0.0.12, patched in commit 234d9aa, contains a command injection vulnerability (CVE-2026-47092). A local attacker can exploit this flaw by manipulating the COMSPEC environment variable. Specifically, the application performs a version check using `execFile()`. If the attacker sets COMSPEC to an arbitrary binary path prior to this check, the attacker-supplied executable will be executed with cmd.exe arguments. This allows for arbitrary code execution on vulnerable Windows systems. This vulnerability matters to defenders because it allows an attacker to gain unauthorized access and control over affected systems, potentially leading to data breaches, system compromise, or other malicious activities.

## Attack Chain

1. The attacker gains local access to the target Windows system.
2. The attacker identifies that Claude HUD version 0.0.12 or earlier is installed.
3. The attacker modifies the COMSPEC environment variable to point to a malicious executable. For example, they might set `COMSPEC=C:\evil\malware.exe`.
4. The attacker triggers the Claude HUD application, which initiates its version check.
5. The `execFile()` function is called to execute the version check. Due to the manipulated COMSPEC variable, the attacker-controlled executable (`C:\evil\malware.exe` in this example) is executed instead of the intended command.
6. The malicious executable runs with the privileges of the user running Claude HUD.
7. The attacker gains arbitrary code execution on the system.

## Impact

Successful exploitation of this command injection vulnerability (CVE-2026-47092) allows a local attacker to execute arbitrary commands on the targeted Windows system. This can lead to a complete compromise of the system, including unauthorized access to sensitive data, installation of malware, or further lateral movement within the network. The NVD assigned this vulnerability a CVSS v3.1 score of 7.8, indicating a high severity.

## Recommendation

*   Apply the patch provided in commit 234d9aa to remediate the vulnerability.
*   Implement the following Sigma rule to detect suspicious modifications to the COMSPEC environment variable.
*   Deploy the Sigma rule to your SIEM and tune for your environment.
*   Monitor process creation events for execution of unusual binaries from non-standard locations when Claude HUD is run.
