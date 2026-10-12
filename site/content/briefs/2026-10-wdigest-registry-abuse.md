---
title: Detection of WDigest Credential Dumping Configuration
slug: 2026-10-wdigest-registry-abuse
description: Detection of the UseLogonCredential registry modification used to enable plaintext credential storage in Windows memory for post-exploitation credential dumping.
date: "2026-10-12T17:43:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - defense-evasion
  - windows
  - registry
  - credential-dumping
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: This activity is significant because it is commonly used by malware and tools like Mimikatz to dump plain text credentials.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects a suspicious registry modification that enables the plain text credential feature in Windows.
    confidence_band: high
rules:
  - title: Detect UseLogonCredential Registry Modification
    description: Detects the modification of the UseLogonCredential registry value, which enables plaintext credential storage in memory.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
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
    - action: Deploy detection rule for UseLogonCredential modification.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic.
  hunt_leads:
    - lead: Search historical registry modification logs for the UseLogonCredential value being set to 1.
      technique_id: T1112
      data_needed:
        - Registry modification telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This is a high-signal indicator of credential dumping preparation.
  mitigation_plan:
    - priority: medium
      action: Remove the UseLogonCredential registry value if found set to 1.
      owner: IT Operations
      addresses: WDigest misconfiguration
      evidence: Setting this value is unnecessary in modern environments.
---

This brief addresses the abuse of the Windows WDigest authentication protocol configuration. By setting the 'UseLogonCredential' registry value to 1, attackers force the Local Security Authority Subsystem Service (LSASS) to cache plaintext credentials in memory. This configuration change is a classic post-exploitation technique used by frameworks like Mimikatz to facilitate credential dumping. Once plaintext credentials are extracted from LSASS memory, actors can conduct lateral movement, privilege escalation, and persistence across a Windows environment. This activity is typically performed after initial access has been established, requiring administrative privileges on the target host.

## Attack Chain

1. Attacker gains administrative access to the target host.
2. Attacker interacts with the Windows Registry via reg.exe, PowerShell, or malicious scripts.
3. Attacker modifies the HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\ registry key.
4. Attacker sets the 'UseLogonCredential' value to 1.
5. Attacker forces a user re-authentication or waits for a new logon event to trigger credential caching.
6. Attacker executes a credential dumping tool (e.g., Mimikatz) to read the LSASS process memory.
7. Attacker extracts plaintext credentials from the dumped memory.
8. Attacker uses extracted credentials to move laterally or elevate privileges within the network.

## Impact

Successful exploitation leads to the compromise of user and service account credentials. This provides attackers with the ability to move laterally across the domain, escalate privileges, and maintain long-term access, potentially impacting the confidentiality and integrity of all systems accessible by the compromised credentials.

## Recommendation

* Deploy the provided Sigma rule to monitor for registry modifications within the WDigest configuration path.
* Audit administrative access to registry keys governing security providers.
* Enforce LSASS protection (e.g., LSA Protection/RunAsPPL) to hinder unauthorized memory dumping tools.
* Monitor for the execution of credential dumping utilities in environments where the WDigest configuration change is observed.
