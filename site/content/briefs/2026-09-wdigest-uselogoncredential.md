---
title: Modification of WDigest UseLogonCredential Registry Key
slug: 2026-09-wdigest-uselogoncredential
description: Adversaries modify the WDigest UseLogonCredential registry key to downgrade credential protection and enable the storage of clear-text passwords in memory for exfiltration via LSASS.
date: "2026-09-01T12:14:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-theft
  - persistence
  - defense-impairment
  - windows-registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Adversaries exploit the HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest registry key to re-enable the 'UseLogonCredential' setting.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The registry modification allows for ongoing credential theft opportunities by forcing clear-text storage.
    confidence_band: high
rules:
  - title: Detect WDigest UseLogonCredential Modification
    description: Detects the modification of the UseLogonCredential registry value to enable clear-text credential storage.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect WDigest registry changes
      owner: Detection Engineering
      due: 24h
      evidence: Registry key modification is a high-fidelity indicator of credential harvesting.
  hunt_leads:
    - lead: Search for historical changes to HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
      technique_id: T1112
      data_needed:
        - Registry modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry changes to this specific path are rarely benign in modern Windows environments.
---

The WDigest authentication protocol is a legacy Windows mechanism that historically stored credentials in clear-text within memory. To mitigate the risk of credential theft, Microsoft released updates to disable this behavior by default. Adversaries exploit the HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest registry key to re-enable the 'UseLogonCredential' setting. By setting this DWORD value to 1, attackers force the system to store user credentials in clear-text, which can subsequently be dumped from the Local Security Authority Subsystem Service (LSASS) process. This technique is frequently observed in post-exploitation scenarios where actors seek to escalate privileges or move laterally within a domain environment. Defenders should monitor registry modifications targeting this specific path as a high-fidelity signal of credential harvesting preparations.

## Attack Chain

1. Attacker gains administrative access to the target endpoint.
2. Attacker identifies the target registry path HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.
3. Attacker uses reg.exe or PowerShell Set-ItemProperty to create or modify the 'UseLogonCredential' DWORD value to 1.
4. The operating system configuration is updated to allow clear-text credential storage.
5. The attacker waits for a legitimate user or administrative account to perform a new logon session.
6. The attacker uses credential dumping tools like Mimikatz or procdump to extract clear-text credentials from the lsass.exe process memory.
7. The attacker uses the recovered clear-text credentials to authenticate to other services or systems within the network.

## Impact

Successful exploitation results in the exposure of clear-text user credentials, significantly increasing the risk of lateral movement and privilege escalation. This technique facilitates the compromise of domain-wide administrative accounts, potentially leading to total directory service takeover if the credentials belong to highly privileged users.

## Recommendation

Prioritize the deployment of the provided Sigma rule to detect unauthorized modifications to the WDigest registry key. Investigate all alerts originating from administrative accounts or processes not associated with known system configuration management tools. Ensure that LSASS memory dumping is simultaneously restricted via EDR policies to prevent the final extraction of the credentials enabled by this registry change.
