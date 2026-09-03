---
title: AS-REP Roasting Enumeration via Get-ADUser
slug: 2026-09-get-aduser-enumeration
description: Detection of PowerShell activity used to enumerate Active Directory accounts with the DONT_REQ_PREAUTH flag, a precursor to AS-REP roasting attacks.
date: "2026-09-03T13:37:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - active-directory
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: Get-ADUser enumeration is used to discover user account properties within the domain.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_as_rep_roasting.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.002/T1069.002.md#atomic-test-11---get-aduser-enumeration-using-useraccountcontrol-flags-as-rep-roasting
rules:
  - title: Detect Get-ADUser Enumeration for AS-REP Roasting Targets
    description: Detects PowerShell execution of Get-ADUser filtering for accounts where the DONT_REQ_PREAUTH flag (4194304) is enabled, indicating potential AS-REP roasting enumeration.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) and deploy detection rule
      owner: Detection Engineering
      due: 48h
      evidence: Source requirement for Script Block Logging
  hunt_leads:
    - lead: Search for historical Event ID 4104 logs containing the string '4194304' to identify past discovery attempts
      technique_id: T1033
      data_needed:
        - PowerShell Operational Logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The identified query pattern is a known technique for AS-REP roasting discovery
---

Attackers often perform reconnaissance within Active Directory to identify accounts that do not require Kerberos pre-authentication. By targeting these accounts, attackers can request the TGT (Ticket Granting Ticket) for the user without needing the user's password, subsequently offline cracking the encrypted hash to recover cleartext credentials. This technique, known as AS-REP roasting, relies on the `DONT_REQ_PREAUTH` flag being set on an account's `UserAccountControl` attribute. Security teams can detect this reconnaissance phase by monitoring PowerShell Script Block logs for specific queries using the `Get-ADUser` cmdlet that utilize bitwise operations (`-band`) to filter for the value `4194304`, which corresponds to the pre-authentication requirement flag.

## Impact

Successful enumeration allows an attacker to identify high-value targets or service accounts misconfigured for weaker authentication, leading to account takeover and potential lateral movement within the enterprise network.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious PowerShell command patterns related to AD account enumeration. Enable Windows PowerShell Script Block Logging (Event ID 4104) across all domain-joined endpoints to ensure visibility into the script content.
