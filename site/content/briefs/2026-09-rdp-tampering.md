---
title: Tampering of RDP Terminal Services Registry Settings
slug: 2026-09-rdp-tampering
description: Adversaries, including the DarkGate malware operators, modify sensitive registry keys associated with Terminal Services to facilitate session hijacking, unauthorized remote access, and defense impairment.
date: "2026-09-01T13:09:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rdp
  - registry
  - persistence
  - defense-impairment
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Adversaries modify registry keys under HKLM to enable persistence or disable security settings.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The rule detects tampering of RDP settings, such as disabling security settings, to impair defense mechanisms.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_terminal_server_tampering.yml
  - https://blog.sekoia.io/darkgate-internals/
  - https://web.archive.org/web/20200929062532/https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
rules:
  - title: Detect Tampering of RDP Terminal Server Registry Keys
    description: Detects modifications to sensitive RDP and Terminal Services registry keys used for session shadowing, hijacking, or weakening security settings.
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
    - action: Deploy the Sigma detection rule to the SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: Sigma rule provided in the brief.
  hunt_leads:
    - lead: Search for existing registry modifications within the Terminal Services paths.
      technique_id: T1112
      data_needed:
        - Registry modification logs (Sysmon Event 13)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry tampering is a known persistence and evasion technique.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict Group Policy controls over RDP configuration to prevent unauthorized registry modification.
      owner: IT Operations
      addresses: T1112
      evidence: Registry modifications can be restricted through policy-based hardening.
---

Adversaries frequently target the Windows registry keys associated with Terminal Services and Remote Desktop Protocol (RDP) to gain persistent access, intercept user sessions, or impair security controls. By modifying specific configuration values under HKLM\SOFTWARE\Microsoft\Windows NT\Terminal Services or HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, attackers can enable unauthorized shadowing, disable security layer requirements, or execute arbitrary programs upon user login. Notable threats, such as the DarkGate malware, have been observed modifying 'DisableRemoteDesktopAntiAlias' and 'DisableSecuritySettings' to facilitate their operations. Defenders must monitor these registry paths, as unauthorized modifications often indicate an attempt to bypass existing RDP security configurations or establish persistent, stealthy access to the target host.

## Attack Chain

1. Attacker gains elevated administrative privileges on the target Windows system.
2. Attacker locates the sensitive registry keys under HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server or HKLM\SOFTWARE\Microsoft\Windows NT\Terminal Services.
3. Attacker modifies the 'ServiceDll' value to perform RDP hijacking by specifying a malicious custom DLL.
4. Attacker adjusts 'DisableSecuritySettings' or 'DisableRemoteDesktopAntiAlias' to weaken RDP connection requirements.
5. Attacker enables RDP 'Shadow' keys to view or control active user sessions without authorization.
6. Attacker configures the 'InitialProgram' key to execute a malicious payload automatically upon the next remote session login.
7. Attacker initiates an RDP connection to the compromised host using the newly established persistent or stealthy access configuration.

## Impact

Successful manipulation of RDP registry settings enables adversaries to maintain persistence, conduct credential harvesting via session monitoring, move laterally within an environment, and disable security layers that protect remote access, potentially leading to full system compromise and data exfiltration.

## Recommendation

* Deploy the Sigma rule below to detect unauthorized modifications to sensitive Terminal Services registry keys.
* Enable Sysmon registry-set logging (Event ID 13) to capture changes to the defined registry paths.
* Investigate any alerts originating from legitimate administrative activity to distinguish between authorized group policy updates and potential malicious tampering.
* Establish a baseline for RDP configuration and alert on deviations, particularly for keys related to 'Shadow' and 'ServiceDll'.
