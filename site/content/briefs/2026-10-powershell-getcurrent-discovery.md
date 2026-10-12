---
title: Detection of PowerShell-based System User Discovery
slug: 2026-10-powershell-getcurrent-discovery
description: Adversaries may use the .NET System.Security.Principal.WindowsIdentity::GetCurrent() method via PowerShell to perform system discovery and identify the current user context.
date: "2026-10-12T17:46:05Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - powershell
  - active-directory
  - system-discovery
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: Adversaries and Red Teams may use it to gain situational awareness and perform Active Directory discovery on compromised endpoints.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.getcurrent
rules:
  - title: Detect PowerShell System Identity Discovery
    description: Detects the use of the .NET System.Security.Principal.WindowsIdentity::GetCurrent() method via PowerShell Script Block Logging.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (EventID 4104) on sensitive endpoints.
      owner: IT Operations
      due: 7d
      evidence: Required to capture the script block text analyzed by this rule.
  hunt_leads:
    - lead: Search for script blocks containing both System.Security.Principal.WindowsIdentity and GetCurrent.
      technique_id: T1033
      data_needed:
        - PowerShell Script Block logs (EventID 4104)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: This activity is a common indicator of situational awareness gathering.
---

Adversaries and Red Teams utilize the System.Security.Principal.WindowsIdentity::GetCurrent() .NET method within PowerShell scripts to gather situational awareness on compromised endpoints. By invoking this method, attackers can programmatically resolve the identity of the current user session, a necessary step for refining subsequent Active Directory discovery, identifying targets for privilege escalation, or establishing the account context for lateral movement. While legitimate administrative and troubleshooting activities may invoke this method, its presence within obfuscated or unexpected PowerShell script blocks is a common indicator of unauthorized discovery operations. Detection teams should focus on PowerShell Script Block Logging (EventID 4104) to monitor for calls to this specific .NET class and method.

## Impact

Successful execution of this discovery technique allows attackers to map the user landscape on a target host. This intelligence is typically used to tailor post-exploitation activities, such as targeting specific user accounts for credential theft or identifying accounts with higher privileges required for domain-wide lateral movement.

## Recommendation

* Deploy the Sigma rule below to monitor for suspicious PowerShell script blocks invoking the WindowsIdentity class.
* Enable PowerShell Script Block Logging (EventID 4104) across all Windows endpoints to capture script execution content.
* Baseline administrative PowerShell usage to identify and tune out common scripting tools that utilize this method for management tasks.
* Investigate occurrences of this pattern in conjunction with other discovery commands, such as 'whoami' or 'net user', to prioritize high-risk alerts.
