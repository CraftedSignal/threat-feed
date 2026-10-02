---
title: Suspicious Kerberos Ticket Request via PowerShell CLI
slug: 2026-10-kerberos-ticket-request
description: Adversaries utilize the System.IdentityModel.Tokens.KerberosRequestorSecurityToken class via PowerShell command lines to conduct Kerberoasting and ticket-based credential access attacks.
date: "2026-10-02T10:12:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - kerberoasting
  - powershell
  - active-directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    evidence: Threat actors may use command line interfaces to request Kerberos tickets for service accounts in order to perform offline password cracking attacks commonly known as Kerberoasting.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_kerberos_kerberos_ticket_request_via_cli.yml
  - https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken
rules:
  - title: Suspicious Kerberos Ticket Request via CLI
    description: Detects suspicious Kerberos ticket requests via command line using System.IdentityModel.Tokens.KerberosRequestorSecurityToken class.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1558.003
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
    - action: Deploy Sigma detection rule to monitor for KerberosRequestorSecurityToken usage
      owner: Detection Engineering
      due: 48h
      evidence: Source provides high-fidelity detection logic
  hunt_leads:
    - lead: Search historical logs for processes spawning PowerShell with the specific .NET class
      technique_id: T1558.003
      data_needed:
        - Process command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Class name usage is a specific indicator of Kerberos interaction
---

Threat actors frequently leverage native administrative tools to conduct credential access operations. By executing the System.IdentityModel.Tokens.KerberosRequestorSecurityToken class directly via PowerShell or pwsh.exe command lines, an attacker can programmatically request Kerberos service tickets for arbitrary accounts. This behavior is indicative of Kerberoasting, an attack technique where service tickets are requested and subsequently exported for offline brute-force cracking to extract service account passwords. While this specific detection focuses on the explicit usage of the .NET class within command-line arguments, it is important to note that attackers frequently use obfuscation or encoded commands to bypass such visibility. Defenders should monitor for this specific pattern to identify unauthorized ticket requests originating from non-standard processes or administrative sessions.

## Impact

Successful exploitation allows attackers to obtain Kerberos service tickets, which are subsequently used to perform offline password cracking. This leads to the compromise of service account credentials, potential lateral movement, and privilege escalation within Active Directory environments.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious instantiation of the KerberosRequestorSecurityToken class. Review process logs associated with this activity to differentiate between legitimate administrative maintenance and malicious credential harvesting. Enable command-line logging (EID 4688) with full command-line auditing to ensure the class name is captured in logs.
