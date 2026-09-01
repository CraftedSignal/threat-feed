---
title: Detection of Malicious RDP Configuration Tampering
slug: 2026-09-rdp-registry-tampering
description: This brief documents registry-based techniques used to impair RDP security by disabling authentication or enabling unauthorized remote access.
date: "2026-09-01T12:28:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-impairment
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The rule detects tampering of RDP Terminal Service/Server sensitive settings.
    confidence_band: high
rules:
  - title: Detect Suspicious RDP Configuration Registry Changes
    description: Detects tampering of RDP Terminal Server settings, specifically the disabling of authentication or enabling of remote connections by setting registry values to zero.
    platform: sigma
    severity: medium
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
    - action: Deploy Sigma rule a2863fbc-d5cb-48d5-83fb-d976d4b1743b to monitor RDP registry modification.
      owner: Detection Engineering
      due: 48h
      evidence: Source material defines these registry modifications as suspicious.
  mitigation_plan:
    - priority: immediate
      action: Enforce RDP security settings through rigid Group Policy Objects (GPO) to prevent local tampering.
      owner: IT Operations
      addresses: RDP configuration security
      evidence: Registry modifications identified as a common TTP.
---

Attackers frequently modify Windows Registry keys related to Terminal Services to maintain persistence, bypass security controls, or gain unauthorized remote access to a compromised system. By altering specific DWORD values within the HKLM hive, an attacker can downgrade RDP security posture without triggering standard administrative alerts. Key targets include disabling Network Level Authentication (NLA), enabling RDP connections when they are otherwise restricted, and allowing multiple concurrent sessions per user. These modifications allow attackers to circumvent security policies and facilitate lateral movement. Defenders should monitor for unexpected registry modifications that change these critical RDP configuration values to zero, as this is a common precursor to session hijacking and remote control activity.

## Attack Chain

1. Attacker achieves initial execution on the target Windows system via a malicious dropper or script.
2. Attacker checks current RDP configuration settings using registry queries or standard administrative tools.
3. Attacker modifies the 'fDenyTSConnections' registry key to 0 to enable Remote Desktop services.
4. Attacker modifies the 'UserAuthentication' registry key to 0 to disable mandatory Network Level Authentication (NLA).
5. Attacker modifies 'fSingleSessionPerUser' to 0 to permit multiple simultaneous remote sessions.
6. Attacker initiates an RDP connection to the target system, potentially using compromised credentials.
7. Attacker performs credential dumping or sensitive data exfiltration from the newly established session.

## Impact

Successful manipulation of these RDP settings allows unauthorized remote access to internal workstations and servers. Impact includes complete system compromise, potential for credential theft, and the ability for attackers to remain persistent while bypassing security features such as NLA, which is designed to prevent pre-authentication exploitation.

## Recommendation

- Deploy the provided Sigma rule to monitor for registry modifications targeting RDP-related keys.
- Investigate any non-standard modification of these keys, especially when performed by processes other than standard Group Policy Object (GPO) update tasks.
- Enable Sysmon event ID 13 (RegistryEvent) to capture 'registry_set' activity effectively.
- Audit RDP configuration via Group Policy to ensure these security settings are enforced and cannot be overridden by local user-level changes.
