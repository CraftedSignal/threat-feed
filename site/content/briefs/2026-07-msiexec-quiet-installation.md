---
title: Msiexec Quiet Installation for Proxy Execution
slug: 2026-07-msiexec-quiet-installation
description: Adversaries leverage the Windows Installer utility msiexec.exe to proxy the quiet execution of malicious payloads, bypassing traditional security controls by masquerading as legitimate installation processes.
date: "2026-07-28T08:27:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - proxy-execution
  - persistence
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
  - https://twitter.com/_st0pp3r_/status/1583914244344799235
rules:
  - title: Detect Msiexec Quiet Installation via Proxy Execution
    description: Detects suspicious quiet installations performed by msiexec.exe that are not originating from common legitimate system or temporary directories, indicating potential proxy execution of malicious payloads.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries are actively abusing `msiexec.exe`, the command-line utility for the Windows Installer, to proxy the execution of malicious payloads. This technique, classified under T1218.007, allows attackers to execute arbitrary code or install unwanted software on victim systems using a legitimate, signed Microsoft binary. By invoking `msiexec.exe` with quiet installation flags (e.g., `-q` or `/quiet`) and other installation parameters (`-i`, `-package`, `-a`, `-j`), attackers can bypass application whitelisting solutions and evade detection by blending in with normal system activities. This method enables the silent deployment of malware, persistence mechanisms, or other adversarial tools without user interaction or visible prompts, posing a significant challenge for defenders attempting to distinguish malicious activity from legitimate system operations. This technique is often used as a post-compromise action to establish persistence or deliver additional stages of an attack.

## Recommendation

* Deploy the Sigma rule `Detect Msiexec Quiet Installation via Proxy Execution` to your SIEM to identify suspicious `msiexec.exe` activity.
* Ensure process creation logging is enabled across your endpoints (e.g., via Sysmon or Windows Event Log) to generate the necessary telemetry for the provided Sigma rule.
* Regularly review `msiexec.exe` processes originating from unusual parent processes or non-standard temporary directories that are not covered by the rule's legitimate filters.
