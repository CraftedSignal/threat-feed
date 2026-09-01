---
title: Detection of DSInternals Get-ADReplAccount Usage
slug: 2026-09-dsinternals-usage
description: Detection of the Get-ADReplAccount cmdlet from the DSInternals toolkit, which is frequently used by adversaries for unauthorized Active Directory credential dumping.
date: "2026-09-01T11:05:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The DSInternals PowerShell Module exposes several internal features of Active Directory... including... password hash calculation.
    confidence_band: high
references:
  - https://www.powershellgallery.com/packages/DSInternals
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.006/T1003.006.md#atomic-test-2---run-dsinternals-get-adreplaccount
rules:
  - title: Detect Suspicious Get-ADReplAccount Execution
    description: Detects the use of the DSInternals Get-ADReplAccount cmdlet, which is used to extract Active Directory secrets
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1003.006
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 48h
      evidence: Required to capture PowerShell script content as per rule definition.
  hunt_leads:
    - lead: Search historical Event ID 4104 logs for Get-ADReplAccount command strings
      technique_id: T1003.006
      data_needed:
        - Event ID 4104
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule definition suggests this cmdlet is indicative of credential access.
---

The DSInternals PowerShell module is a powerful toolkit designed for Active Directory and Azure Active Directory auditing. While it serves legitimate administrative and security research purposes, it is also highly valued by attackers for its ability to extract credentials, manipulate offline NTDS.dit files, and perform password hash calculations. Specifically, the Get-ADReplAccount cmdlet is often utilized to retrieve account objects and their associated secrets directly from a domain controller. Detection is critical as the use of this cmdlet in a production environment by unauthorized users or non-standard administrative accounts is a strong indicator of credential access activities, particularly during the post-exploitation phase when an actor attempts to harvest domain secrets.

## Impact

Successful use of this tool allows an adversary to obtain sensitive account information and password hashes. If exploited, this leads to complete domain compromise, allowing the attacker to perform pass-the-hash attacks, escalate privileges, or maintain persistent access to the enterprise identity infrastructure.

## Recommendation

Detection engineering teams should implement PowerShell Script Block Logging (Event ID 4104) and deploy the provided detection rule to identify the execution of the Get-ADReplAccount command. Because the tool can be used for authorized auditing, alerts should be tuned against known administrative workstations and service accounts performing scheduled domain audits.

- Enable PowerShell Script Block Logging (Event ID 4104) across all Domain Controllers and high-value internal workstations to capture script execution details.
- Deploy the Sigma rule provided below to SIEM to identify suspicious credential access attempts.
- Correlate alerts with account authorization logs to determine if the activity is performed by sanctioned administrative staff.
