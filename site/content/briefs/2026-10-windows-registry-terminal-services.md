---
title: Detection of Registry Modifications Weakening Terminal Services Security
slug: 2026-10-windows-registry-terminal-services
description: This detection identifies modifications to the Windows registry key 'DisableSecuritySettings' which lowers Remote Desktop security posture, a technique frequently used by the DarkGate malware to enable persistent unauthorized remote access.
date: "2026-10-12T18:11:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - windows
  - rdp
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
    evidence: The analytic detects modifications to the Windows registry that disable security settings for Terminal Services.
    confidence_band: high
rules:
  - title: Detect Windows Registry Modification to Disable Terminal Services Security
    description: Detects modifications to the Windows registry 'DisableSecuritySettings' value, which weakens RDP security configurations often used by malware for persistence.
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
    - action: Deploy registry monitoring for 'DisableSecuritySettings' via Sysmon Event ID 13
      owner: Detection Engineering
      due: 48h
      evidence: Source defines this as a key TTP for the DarkGate malware.
  hunt_leads:
    - lead: Search for historical registry set events where 'DisableSecuritySettings' was set to 0x1
      technique_id: T1112
      data_needed:
        - Registry modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This registry key manipulation is a known persistence indicator.
---

This alert focuses on unauthorized modifications to the Windows registry path responsible for Terminal Services security configurations. Specifically, it monitors for the creation or modification of the 'DisableSecuritySettings' registry value set to 0x00000001. This configuration weakens the Remote Desktop Protocol (RDP) security posture, effectively lowering the barrier for remote access. This technique is documented as being utilized by the DarkGate malware family to ensure persistent, stealthy, and unauthorized remote control of compromised systems. By tampering with these settings, attackers can bypass default security controls, facilitating further post-exploitation activities such as lateral movement, payload delivery, and sensitive data exfiltration. Detection engineering teams should prioritize this monitoring to identify attempts to establish persistent, insecure remote access channels within the Windows environment.

## Attack Chain

1. Initial access is established via phishing or malicious download (e.g., DarkGate payload execution).
2. The malware executes with high or administrative privileges to gain registry modification access.
3. The malicious process locates the target registry path: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\DisableSecuritySettings.
4. The process modifies or creates the 'DisableSecuritySettings' value, setting it to 0x00000001.
5. The change effectively disables authentication or encryption requirements for RDP sessions.
6. The attacker initiates an RDP connection to the compromised system using the downgraded security configuration.
7. Successful authentication (or lack thereof) provides the attacker with a persistent interactive desktop session.
8. Post-exploitation activities, including credential dumping and data staging, commence.

## Impact

Successful exploitation of this registry modification allows attackers to maintain persistent, unauthorized remote access to the targeted Windows system. This weakens the RDP security boundary, potentially exposing the host to further exploitation. This technique has been observed in campaigns involving the DarkGate malware, which targets corporate environments to facilitate data theft and ransomware deployment. Failure to detect this change may result in prolonged attacker presence and undetected unauthorized access within the enterprise network.

## Recommendation

- Deploy the provided Sigma rule to monitor for registry modifications targeting Terminal Services security settings.
- Enable Sysmon Event ID 13 (Registry Event) across all Windows endpoints to capture Registry Set operations.
- Audit high-privilege accounts and ensure they are not used for routine administrative tasks to prevent unauthorized registry modification.
- Investigate any occurrences of this registry modification that do not align with authorized change management activities.
