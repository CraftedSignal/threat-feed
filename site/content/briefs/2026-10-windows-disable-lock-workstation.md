---
title: Windows Registry Abuse to Disable Lock Workstation Feature
slug: 2026-10-windows-disable-lock-workstation
description: Threat actors and ransomware operators modify the Windows Registry to disable the workstation lock feature, ensuring persistent access and preventing user interference during malicious operations.
date: "2026-10-12T18:03:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows-registry
  - ransomware
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects a suspicious registry modification that disables the Lock Computer feature in Windows.
    confidence_band: high
rules:
  - title: Detect Windows Disable Lock Workstation Registry Modification
    description: Detects unauthorized modification of the DisableLockWorkstation registry key, which disables the ability to lock the screen.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
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
    - action: Deploy the Sigma detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation identifies this as a defense evasion tactic.
  hunt_leads:
    - lead: Search for historical occurrences of this registry modification in logs.
      technique_id: T1112
      data_needed:
        - Registry modification logs (Sysmon EID 13 or EDR telemetry).
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Registry modification is a high-fidelity indicator of potential malware activity.
---

Attackers, including ransomware groups, utilize registry modifications to disable the native Windows Lock Workstation feature. By setting the 'DisableLockWorkstation' registry value to '0x00000001' within the 'Policies\System' hive, adversaries prevent legitimate users from locking their sessions. This tactic serves as a defense evasion mechanism, allowing attackers to maintain active sessions, bypass user-interaction hurdles during malicious activity, and ensure their presence remains uninterrupted on the compromised system. This behavior has been documented in association with various malware strains, including ransomware variants and remote access trojans (RATs) such as FatalRAT, which leverage this configuration change to sustain control over target environments.

## Attack Chain

1. Attacker gains initial access to the Windows endpoint via phishing, exploit, or credential theft.
2. Attacker executes malicious binary or script with elevated privileges required to modify system-wide policies.
3. Attacker identifies the target registry path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\.
4. Attacker writes the key 'DisableLockWorkstation' with a DWORD value of 1 to the identified registry path.
5. The modification takes effect, causing the 'Lock' option to be removed or disabled for the active user session.
6. Attacker continues malicious operations, such as data exfiltration or ransomware encryption, without the risk of the system locking due to inactivity.

## Impact

The primary impact of this modification is the subversion of local security controls and the maintenance of an unlocked session. This ensures that attackers can execute further malicious actions without user interruption. While not resulting in direct data theft by itself, it is a precursor to more severe impact activities like ransomware deployment, where persistent access is required to complete encryption cycles across a network.

## Recommendation

1. Deploy the provided Sigma rule to monitor for registry modifications targeting the 'DisableLockWorkstation' key.
2. Use endpoint protection platforms to restrict registry modification permissions for non-administrative processes or users.
3. Monitor Sysmon Event ID 13 (Registry Event) for value changes to the specified path and correlate with suspicious parent processes.
