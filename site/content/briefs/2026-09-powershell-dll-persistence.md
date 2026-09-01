---
title: Detection of PowerShell-Based DLL Placement in System Directories
slug: 2026-09-powershell-dll-persistence
description: Adversaries utilize PowerShell commands to move malicious DLLs into protected Windows system directories, a technique commonly associated with persistence and credential access.
date: "2026-09-01T12:07:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - credential-access
  - defense-impairment
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: The rule and reference document the installation of a password filter DLL into system directories.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_copy_item_system_directory.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1556.002/T1556.002.md#atomic-test-1---install-and-register-password-filter-dll
rules:
  - title: Detect PowerShell Copy-Item to System Directory
    description: Detects usage of Copy-Item or cpi to copy files into system directories like System32 or SysWOW64
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - persistence
    techniques:
      - T1556.002
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 48h
      evidence: Source requirement for rule operation.
  hunt_leads:
    - lead: Search for instances of files written to System32/SysWOW64 by non-trusted processes or users.
      technique_id: T1556.002
      data_needed:
        - Sysmon Event ID 11
        - Endpoint EDR file write events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This activity is a key indicator of DLL-based persistence.
---

This threat brief focuses on the behavioral detection of PowerShell scripts used to copy or move files, specifically malicious DLLs, into sensitive Windows system directories such as C:\Windows\System32 or C:\Windows\SysWOW64. This activity is frequently observed in post-exploitation scenarios where an attacker seeks to establish persistence or facilitate credential access, such as by installing a custom password filter DLL. By moving binaries into these directories, attackers often attempt to blend in with legitimate system files or exploit search order hijacking vulnerabilities. Defenders must monitor PowerShell Script Block logging (Event ID 4104) to identify these administrative operations initiated by potentially compromised user or service accounts.

## Attack Chain

1. Initial compromise of a workstation or server via phishing or exploit.
2. Execution of a PowerShell command to locate or download a malicious DLL payload.
3. Escalation of privileges to reach the level required for writing into protected directories.
4. Use of `Copy-Item` or `cpi` PowerShell cmdlets to move the malicious DLL into a target path within System32 or SysWOW64.
5. Modification of registry keys (e.g., Notification Packages or Password Filters) to link the dropped DLL.
6. Service restart or system reboot to force the loading of the malicious DLL by system processes.
7. Final objective achieved: persistent code execution in the context of high-privileged system processes for credential dumping or C2.

## Impact

Successful execution allows attackers to maintain persistent access to the host, bypass security controls, and capture sensitive credentials (such as plaintext passwords or NTLM hashes) directly from the LSASS process, potentially leading to domain-wide compromise.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) to capture the full command strings executed by PowerShell.
2. Deploy the provided Sigma rule to identify unauthorized file operations targeting sensitive directories.
3. Implement File Integrity Monitoring (FIM) on C:\Windows\System32 and C:\Windows\SysWOW64 to alert on the creation of new, unexpected DLLs.
4. Enforce strict least-privilege policies to ensure that standard user or service accounts cannot write to protected system directories.
