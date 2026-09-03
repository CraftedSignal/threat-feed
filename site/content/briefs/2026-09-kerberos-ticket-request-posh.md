---
title: Suspicious Kerberos Ticket Request via PowerShell
slug: 2026-09-kerberos-ticket-request-posh
description: Detection logic for PowerShell scripts leveraging the .NET KerberosRequestorSecurityToken class to illicitly request Kerberos tickets, a common step in Kerberoasting.
date: "2026-09-03T13:41:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - powershell
  - active-directory
  - kerberos
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    evidence: This behavior is typically seen during a Kerberos or silver ticket attack.
    confidence_band: high
rules:
  - title: Detect Suspicious Kerberos Ticket Request via PowerShell
    description: Detects the use of System.IdentityModel.Tokens.KerberosRequestorSecurityToken in PowerShell scripts, which is indicative of Kerberoasting attempts.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1558.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for Kerberos ticket requests.
      owner: Detection Engineering
      due: 48h
  mitigation_plan:
    - priority: short_term
      action: Enable PowerShell Script Block logging.
      owner: IT Operations
      addresses: T1558.003
---

This threat brief focuses on the exploitation of native .NET classes within PowerShell to perform unauthorized Kerberos ticket requests. Attackers frequently leverage the 'System.IdentityModel.Tokens.KerberosRequestorSecurityToken' class to interface with the Windows authentication stack and request service tickets for specific Service Principal Names (SPNs). This technique is a core component of 'Kerberoasting', where the resulting ticket can be exported and cracked offline to recover service account passwords. Detection depends on the visibility of PowerShell Script Block logging to capture the execution of these specific .NET method calls.

## Attack Chain

1. Attacker establishes an initial foothold on a domain-joined host.
2. Attacker enumerates available services or user accounts via Active Directory queries.
3. Attacker identifies targets with Service Principal Names (SPNs) registered.
4. Attacker crafts a PowerShell script using 'System.IdentityModel.Tokens.KerberosRequestorSecurityToken'.
5. Attacker executes the script in the context of the current session to initiate a ticket request.
6. The .NET assembly interacts with the Kerberos Key Distribution Center (KDC).
7. The KDC issues the service ticket, which is stored in the memory of the current process.
8. Attacker extracts the service ticket for offline decryption (Kerberoasting).

## Impact

Successful execution of this technique facilitates credential theft of high-privileged service accounts. Offline brute-forcing of these tickets allows attackers to obtain cleartext credentials, potentially leading to full domain compromise and lateral movement within the network.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for the abuse of Kerberos request classes. Ensure PowerShell Script Block logging (Event ID 4104) is enabled globally across the enterprise, as this is the primary telemetry source for detecting this behavior.

- Deploy the Sigma rule below to detect unauthorized usage of the 'KerberosRequestorSecurityToken' class.
- Enable 'Log PowerShell Script Blocks' via Group Policy to ensure visibility into the specific .NET classes instantiated by scripts.
- Audit accounts with SPNs, specifically focusing on those with excessive privileges or service account permissions.
