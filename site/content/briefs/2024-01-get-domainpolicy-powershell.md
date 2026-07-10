---
title: PowerShell Get-DomainPolicy Usage for Reconnaissance
slug: 2024-01-get-domainpolicy-powershell
description: Adversaries use the PowerShell `Get-DomainPolicy` commandlet to enumerate domain password policies for situational awareness and Active Directory discovery, logged via PowerShell Script Block Logging.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - discovery
  - powershell
vendors:
  - Microsoft
products:
  - Active Directory
  - PowerShell
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Reconnaissance
    technique_id: T1201
    technique_name: Permission Groups Discovery
references:
  - https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
  - https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainPolicy/
  - https://attack.mitre.org/techniques/T1201/
rules:
  - title: Detect Get-DomainPolicy with Powershell Script Block
    description: Detects the execution of the Get-DomainPolicy commandlet within PowerShell script block logs, indicating potential Active Directory discovery.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1201
    data_sources:
      - process_creation
      - windows
  - title: Detect Get-DomainPolicy with Powershell Script Block Logging
    description: Detects the execution of Get-DomainPolicy using Powershell Script Block Logging (EventCode=4104)
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1201
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers and red teams use PowerShell to enumerate domain policies for situational awareness and Active Directory discovery. This involves using the `Get-DomainPolicy` commandlet to obtain password policies. This command is logged when PowerShell Script Block Logging (EventCode=4104) is enabled. Identifying this command's execution can help detect reconnaissance activities within a Windows domain. The activity is useful for attackers to understand password complexity requirements and other domain security settings. The scope is limited to systems where PowerShell Script Block Logging is enabled, typically within organizations that prioritize security monitoring.

## Attack Chain

1. An attacker gains initial access to a compromised host within the target network.
2. The attacker executes PowerShell with the intention of gathering domain information.
3. The attacker uses the `Get-DomainPolicy` commandlet to query the current domain password policy.
4. PowerShell Script Block Logging captures the execution of the `Get-DomainPolicy` command (EventCode 4104).
5. The attacker parses the output of the command to understand password complexity, account lockout thresholds, and other security settings.
6. The attacker uses the gathered information to refine subsequent attack strategies, such as password spraying or brute-force attacks.
7. The attacker leverages the discovered information to escalate privileges or move laterally within the domain.

## Impact

Successful execution allows attackers to understand the domain's password policies, aiding in privilege escalation and lateral movement. It serves as a reconnaissance step, often preceding more damaging activities. If successful, attackers can craft more effective attacks tailored to bypass existing security measures. While no specific number of victims is mentioned, any organization using Active Directory is potentially at risk.

## Recommendation

*   Enable PowerShell Script Block Logging (EventCode 4104) on all endpoints to capture the execution of PowerShell commands, which is required for the provided detections.
*   Deploy the Sigma rule `Detect Get-DomainPolicy with Powershell Script Block` to identify instances of the `Get-DomainPolicy` commandlet being used.
*   Investigate any detected instances of `Get-DomainPolicy` execution, especially those originating from unusual or unauthorized systems based on the logs.
