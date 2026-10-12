---
title: Windows EnableLinkedConnections Registry Modification
slug: 2026-10-windows-enablelinkedconnections-registry
description: Detection of unauthorized modifications to the EnableLinkedConnections registry key, a technique used by BlackByte ransomware to enable cross-privilege network share access.
date: "2026-10-12T18:12:28Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - BlackByte
tags:
  - defense-evasion
  - registry
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
    evidence: The following analytic detects a suspicious modification to the Windows registry setting for EnableLinkedConnections.
    confidence_band: high
rules:
  - title: Detect Windows EnableLinkedConnections Registry Modification
    description: Detects modifications to the EnableLinkedConnections registry key which enables network shares across different user privilege levels.
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
    - action: Deploy Sigma rule to monitor for EnableLinkedConnections registry changes.
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation of TTP usage by BlackByte.
  hunt_leads:
    - lead: Search endpoint registry logs for EnableLinkedConnections value 0x00000001.
      technique_id: T1112
      data_needed:
        - Registry modification telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry key modification is a high-signal indicator of unauthorized configuration changes.
  mitigation_plan:
    - priority: short_term
      action: Review group policy objects to ensure EnableLinkedConnections is disabled by default.
      owner: IT Operations
      addresses: T1112
      evidence: Best practice to mitigate unauthorized cross-privilege network access.
---

The EnableLinkedConnections registry setting controls whether Windows allows network connections to be shared across different logon sessions. By modifying this key (typically located at HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) and setting it to 1, attackers can enable access to mapped network drives across both standard and administrator-level access tokens. This technique is frequently abused by post-exploitation actors, notably during BlackByte ransomware intrusions, to facilitate lateral movement and access restricted network resources that would otherwise be protected by User Account Control (UAC) filtering. Defenders should monitor for registry modifications targeting this specific path, as the setting change is rarely required for routine end-user operations.

## Attack Chain

1. Initial access is established through phishing or exploitation of internet-facing services.
2. The attacker gains initial code execution, typically as a standard user.
3. The attacker identifies the need to access network shares mapped in a different security context.
4. A registry modification is performed on 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections' using reg.exe or API calls.
5. The value is set to '0x00000001' to enable linked connections.
6. The attacker leverages the now-shared network connection to access sensitive shares or sensitive data.
7. Final objective such as data exfiltration or encryption (ransomware) is executed.

## Impact

Modification of this registry key significantly expands the attack surface by bypassing UAC restrictions on network shares. Successful exploitation allows an attacker to escalate their capability to interact with network resources without further authentication, often resulting in mass file encryption, data theft, or complete domain compromise within the targeted sector.

## Recommendation

1. Deploy the provided Sigma rule to detect unauthorized modifications to the EnableLinkedConnections registry key.
2. Enable Sysmon Event ID 13 logging to capture registry modifications across all endpoints.
3. Investigate any process modifying the registry key outside of approved system administration toolsets or deployment software.
4. Perform a retroactive hunt for '0x00000001' values written to the EnableLinkedConnections path in registry logs.
