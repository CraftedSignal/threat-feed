---
title: Detection of PowerShell Get-Process Execution on LSASS
slug: 2026-09-powershell-lsass-getprocess
description: Adversaries may use PowerShell to enumerate the Local Security Authority Subsystem Service (LSASS) process as a precursor to credential dumping or process injection.
date: "2026-09-03T12:40:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - powershell
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Detects a Get-Process cmdlet and its aliases on lsass process, which is in almost all cases a sign of malicious activity.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass.yml
  - https://web.archive.org/web/20220205033028/https://twitter.com/PythonResponder/status/1385064506049630211
rules:
  - title: Detect PowerShell Get-Process LSASS Enumeration
    description: Detects the use of PowerShell Get-Process, ps, or gps cmdlets targeting the LSASS process, which is often indicative of malicious credential access reconnaissance.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1552.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to SIEM to detect LSASS enumeration.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific cmdlet patterns observed in malicious activity.
  hunt_leads:
    - lead: Search historic process creation logs for 'Get-Process lsass' to identify past unauthorized access attempts.
      technique_id: T1552.004
      data_needed:
        - CommandLine
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Historical telemetry can reveal if the environment has been previously probed.
---

Monitoring for the execution of PowerShell cmdlets targeting the Local Security Authority Subsystem Service (LSASS) process is a critical detection capability for identifying credential access activities. Attackers often leverage built-in PowerShell commands like Get-Process (or its aliases 'ps' and 'gps') to enumerate the LSASS process handle or existence within a compromised environment. While these cmdlets can be used for administrative purposes, their application against LSASS is highly anomalous and frequently serves as a reconnaissance step before attempting to access LSASS memory to extract credentials (e.g., via tools like Mimikatz). Defenders should establish baseline activity for administrative scripts and alert on direct PowerShell interactions with this critical system process.

## Impact

Successful reconnaissance of the LSASS process is often the first stage in credential theft campaigns. Unauthorized access to LSASS memory allows attackers to extract cleartext passwords, NTLM hashes, and Kerberos tickets, which facilitates lateral movement, privilege escalation, and persistent access to the enterprise domain.

## Recommendation

Deploy the provided Sigma rule to your SIEM environment to detect enumeration of the LSASS process via PowerShell. Ensure that PowerShell script block logging (Event ID 4104) and process creation events (Sysmon Event ID 1) are enabled to capture these command lines. Investigate any instances where administrative service accounts or user accounts execute these commands against LSASS, as they likely indicate credential access attempts.
