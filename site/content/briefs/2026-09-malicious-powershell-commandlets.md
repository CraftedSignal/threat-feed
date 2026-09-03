---
title: Detection of Malicious PowerShell Framework Commandlets
slug: 2026-09-malicious-powershell-commandlets
description: This brief documents a comprehensive list of commandlet patterns associated with common PowerShell-based exploitation frameworks, privilege escalation tools, and post-exploitation modules used by threat actors.
date: "2026-09-03T12:36:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - powershell
  - execution
  - discovery
  - post-exploitation
rules:
  - title: Detect Malicious PowerShell Commandlets - ScriptBlock
    description: Detects known commandlet names associated with PowerShell-based exploitation frameworks via Script Block Logging.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 48h
      evidence: Log source requirement.
    - action: Deploy the provided Sigma rule to detect malicious commandlets.
      owner: Detection Engineering
      due: 24h
      evidence: Detection logic.
  hunt_leads:
    - lead: Search for historical Event ID 4104 logs containing the listed commandlets.
      technique_id: T1059.001
      data_needed:
        - Powershell Operational logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known patterns of exploitation.
  mitigation_plan:
    - priority: short_term
      action: Implement JEA (Just Enough Administration) to limit PowerShell execution privileges.
      owner: IT Operations
      addresses: PowerShell abuse
      evidence: General best practice.
---

This intelligence provides a consolidated detection baseline for activity originating from well-known PowerShell exploitation frameworks. These frameworks, including PowerSploit, Nishang, BloodHound, and others, utilize specific function names that are often logged during PowerShell Script Block Logging (Event ID 4104). Attackers leverage these scripts to perform reconnaissance, credential dumping, persistence, and lateral movement. By monitoring for these specific commandlet patterns, defenders can identify the execution of offensive security tools within their environment. This list covers a broad spectrum of techniques, ranging from AD reconnaissance (Invoke-ADRecon) to credential access (Invoke-Mimikatz) and data exfiltration, providing high-signal coverage for unauthorized administrative activity.

## Attack Chain

1. Initial delivery or staging of the PowerShell script to the target endpoint.
2. Execution of the script, triggering PowerShell Script Block logging (Event ID 4104).
3. Reconnaissance phase utilizing modules like Invoke-UserHunter or Get-System to map the environment.
4. Credential access phase via modules such as Get-PassHashes, Invoke-Mimikatz, or Get-VaultCredential.
5. Persistence mechanism installation using functions like Add-Persistence or Add-RegBackdoor.
6. Privilege escalation via modules like Invoke-BypassUAC or Invoke-BadPotato.
7. Exfiltration of sensitive data or credentials using functions like Invoke-DNSExfiltrator or Do-Exfiltration.

## Impact

Successful execution of these PowerShell commandlets grants attackers a foothold, allowing for the extraction of sensitive credentials, full domain environment mapping, elevation of privileges to system or domain admin, and stealthy persistence within the victim's infrastructure.

## Recommendation

Prioritize the implementation of PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints. Deploy the provided Sigma rule to detect these specific malicious commandlet patterns. Ensure logs are forwarded to a SIEM for immediate alerting and historical hunting. Exclude known administrative or deployment scripts from the detection logic to reduce noise.
