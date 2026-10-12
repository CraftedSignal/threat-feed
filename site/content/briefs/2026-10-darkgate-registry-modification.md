---
title: DarkGate Malware Registry Modification for Authentication Override
slug: 2026-10-darkgate-registry-modification
description: DarkGate malware modifies the 'AuthenticationLevelOverride' registry key to weaken remote connection security, enabling unauthorized access and persistent remote control.
date: "2026-10-12T18:10:39Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - DarkGate
tags:
  - darkgate
  - persistence
  - registry
  - defense-evasion
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
    evidence: The analytic detects modifications to the Windows registry key AuthenticationLevelOverride within the Terminal Server Client settings.
    confidence_band: high
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.darkgate
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml#L1061
rules:
  - title: Detect Registry AuthenticationLevelOverride Modification
    description: Detects modifications to the Terminal Server Client AuthenticationLevelOverride registry key to weaken remote authentication.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
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
    - action: Deploy the Sigma rule to monitor Registry modifications for AuthenticationLevelOverride.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific path and value for DarkGate.
  hunt_leads:
    - lead: Search historic logs for registry modifications where TargetObject matches AuthenticationLevelOverride and Details is 0.
      technique_id: T1112
      data_needed:
        - Registry modification telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Malware uses this registry modification for persistence.
  mitigation_plan:
    - priority: short_term
      action: Enforce RDP authentication levels via GPO to overwrite malicious local registry changes.
      owner: IT Operations
      addresses: Registry tampering
      evidence: Standard defensive practice for RDP hardening.
---

DarkGate malware, a sophisticated threat known for its modular design and information-stealing capabilities, utilizes specific registry modifications to facilitate its operations. The malware targets the Windows registry key located at 'HKCU\Software\Microsoft\Terminal Server Client\AuthenticationLevelOverride', setting the value to 0x00000000. This modification intentionally weakens authentication requirements for Terminal Server client connections, allowing attackers to downgrade security protocols or bypass standard authentication checks when establishing remote access to the compromised system. By manipulating these settings, DarkGate actors can maintain more reliable remote control, execute subsequent stages of their attack, or exfiltrate sensitive data without being blocked by hardened remote connection policies. This technique is typically employed during the post-compromise phase to ensure persistence and ease of lateral movement or remote administration.

## Attack Chain

1. Initial access is established, often via social engineering or malicious attachments.
2. The primary payload executes and gains execution privileges on the victim host.
3. The malware performs system enumeration to identify the presence of Remote Desktop/Terminal Server services.
4. The malware modifies the 'AuthenticationLevelOverride' registry value to 0x00000000 via direct API calls or command-line registry utilities.
5. The weakened authentication state is validated by the malware's C2 communication loop.
6. The attacker leverages the modified authentication state to initiate or maintain unauthorized remote sessions.
7. Final objective (data exfiltration, credential harvesting, or ransomware deployment) is executed.

## Impact

Successful exploitation of this registry setting allows attackers to gain unauthorized remote access to a system. This bypasses security configurations intended to prevent weak or unauthenticated remote connections, facilitating data exfiltration, lateral movement, or the deployment of additional malicious tools. The threat primarily impacts enterprise environments where remote administrative access is common.

## Recommendation

1. Deploy the provided Sigma rule to identify registry modifications targeting the 'AuthenticationLevelOverride' key.
2. Configure endpoint monitoring (e.g., Sysmon Event ID 13) to log all changes to the 'Terminal Server Client' registry subkey.
3. Investigate any process modifying this registry path, specifically looking for unsigned binaries or processes running from non-standard user profile directories.
4. Establish a GPO policy to prevent unauthorized modifications to Terminal Server Client registry keys and monitor for policy drift.
