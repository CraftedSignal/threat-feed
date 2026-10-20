---
brief_id: brief-2024-01-02-rdp-registry-enabled
event_id: brief-2024-01-02-rdp-registry-enabled
revision: 2
activity_at: "2024-01-02T15:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:4dafe0589cf7ff64671d3339620713c623505adb2faf731a9af7167dee6acf23
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: RDP Enabled via Registry Modification
slug: 2024-01-02-rdp-registry-enabled
description: Adversaries may enable Remote Desktop Protocol (RDP) access by modifying the `fDenyTSConnections` registry key, potentially indicating lateral movement preparation and subsequent malicious activity within the compromised environment.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - lateral-movement
  - defense-evasion
  - rdp
  - registry-modification
  - windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/001/
  - https://attack.mitre.org/techniques/T1112/
rules:
  - title: RDP Enabled via Registry Modification
    description: Detects registry modifications to enable Remote Desktop Protocol (RDP) access by setting fDenyTSConnections to 0.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021
      - T1021.001
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying RDP Registry Key
    description: Detects processes not commonly associated with RDP configuration modifying the fDenyTSConnections registry key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021
      - T1021.001
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers can enable Remote Desktop Protocol (RDP) access on Windows systems by modifying the `fDenyTSConnections` registry key. This technique is often employed as part of lateral movement and defense evasion strategies. By enabling RDP, adversaries can gain interactive access to compromised systems, facilitating further malicious activities such as data exfiltration, malware deployment, or privilege escalation. The modification of this registry key can be achieved through various means, including remote registry access tools like PsExec. This activity is particularly concerning because it allows attackers to blend in with legitimate remote access activities, making detection more challenging. Defenders should monitor for unauthorized or unexpected modifications to the `fDenyTSConnections` registry key to identify potential lateral movement attempts.

## Attack Chain

1. Initial access is gained through an exploit or compromised credentials (not detailed in source).
2. The attacker leverages a tool like PsExec to execute commands remotely.
3. The attacker targets the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`.
4. The attacker modifies the `fDenyTSConnections` value from `1` to `0`, enabling RDP.
5. The attacker uses RDP to connect to the compromised system, establishing an interactive session.
6. The attacker performs reconnaissance, gathering information about the network and systems.
7. The attacker moves laterally to other systems using the newly enabled RDP access.
8. The attacker achieves their final objective, which could include data theft or ransomware deployment.

## Impact

Successful exploitation can lead to unauthorized remote access to critical systems, allowing attackers to perform lateral movement, data exfiltration, or deploy ransomware. The lack of proper RDP security measures can significantly increase the attack surface, potentially impacting a large number of systems within the network. The modification of the `fDenyTSConnections` registry key can expose sensitive resources and facilitate further malicious activities, resulting in significant financial losses and reputational damage.

## Recommendation

*   Deploy the Sigma rule "RDP Enabled via Registry Modification" to your SIEM to detect unauthorized changes to the `fDenyTSConnections` registry key, as described in the rule definition.
*   Enable Sysmon registry event logging to capture registry modifications for analysis and detection using the provided Sigma rule.
*   Review the exclusion list in the Sigma rule "RDP Enabled via Registry Modification" and customize it for your environment to reduce false positives.
*   Restrict RDP access through firewall rules, allowing only trusted hosts to connect to reduce the attack surface.
*   Monitor network events for incoming RDP connection attempts following a registry modification as described in this brief.
