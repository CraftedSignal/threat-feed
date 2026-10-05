---
title: Detection of Msiexec.exe Used for Persistence
slug: 2026-10-msiexec-persistence
description: This brief identifies the abuse of the Windows Installer process, msiexec.exe, by adversaries to establish persistence via scheduled tasks, startup folders, and registry autorun keys.
date: "2026-10-05T12:02:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - persistence
  - living-off-the-land
  - installer-abuse
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries may abuse msiexec.exe to create malicious scheduled tasks.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries may abuse msiexec.exe to modify registry run keys.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Adversaries exploit msiexec.exe to create persistence mechanisms.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_msi_installer_task_startup.toml
  - https://attack.mitre.org/techniques/T1218/007/
  - https://attack.mitre.org/techniques/T1547/001/
  - https://attack.mitre.org/techniques/T1053/005/
rules:
  - title: Persistence via a Windows Installer
    description: Detects msiexec.exe modifying registry run keys or creating files in startup folders, a common persistence technique.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1218.007
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the persistence detection rule to your SIEM.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for instances of msiexec.exe creating files in user Startup directories.
      technique_id: T1547.001
      data_needed:
        - File creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
---

Adversaries frequently abuse the Windows Installer process (msiexec.exe) as a living-off-the-land technique to maintain persistence on compromised Windows systems. By leveraging the legitimate functionality of msiexec.exe, attackers can mask the creation of malicious scheduled tasks, the placement of payloads in startup directories, or the modification of Windows Registry Run keys. Because msiexec.exe is a trusted system binary, its involvement in these actions often bypasses basic security scrutiny. Defenders should monitor for instances where msiexec.exe performs actions inconsistent with standard software installation patterns, such as creating persistence entries in non-standard locations or modifying registry keys outside of defined enterprise software deployment windows.

## Attack Chain

1. Attacker delivers a malicious MSI package or executes an msiexec.exe command line via a compromised vector.
2. Msiexec.exe is executed with elevated privileges (often via UAC bypass or service account impersonation).
3. The installer process proceeds to write a malicious binary or script to a persistence location, such as the Startup folder.
4. Alternatively, msiexec.exe modifies registry keys under HKLM or HKCU CurrentVersion\Run to trigger execution at next login.
5. The installer process may create a new Scheduled Task to ensure persistent background execution.
6. Attacker deletes the original MSI package to clean up artifacts while leaving the persistence mechanism intact.
7. Upon system reboot or user login, the established persistence entry invokes the malicious payload to regain access.

## Impact

Successful exploitation allows an adversary to maintain long-term, persistent access to a compromised host, facilitating further lateral movement, credential theft, or exfiltration. Because this technique uses a native Windows component, it allows for stealthy execution that may evade signature-based detection mechanisms that ignore trusted system binaries.

## Recommendation

Prioritize the implementation of EDR telemetry that tracks file and registry modifications specifically sourced from the msiexec.exe process. Enable the provided Sigma rules to capture these modifications. Maintain an allowlist of legitimate installer behaviors, specifically focusing on enterprise-managed deployment software and trusted update processes, to reduce false positives. Investigate any instances where msiexec.exe is spawned by non-standard parent processes, such as web servers, unauthorized PowerShell scripts, or unexpected user-level processes.
