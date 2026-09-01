---
title: Detection of DisableRestrictedAdmin Registry Value Tampering
slug: 2026-09-restricted-admin-tampering
description: Adversaries manipulate the DisableRestrictedAdmin registry key to weaken Remote Desktop security, facilitating credential harvesting through the capture of reusable credentials during remote sessions.
date: "2026-09-01T12:08:42Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Detects changes to the DisableRestrictedAdmin registry value in order to disable or enable RestrictedAdmin mode.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system.
    confidence_band: high
rules:
  - title: Detect RestrictedAdminMode Registry Value Tampering via Process Creation
    description: Detects the use of command-line tools to modify the DisableRestrictedAdmin registry value, which lowers RDP security and facilitates credential harvesting.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - persistence
    techniques:
      - T1112
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify historical modifications to the LSA registry path over the last 30 days.
      technique_id: T1112
      priority: medium
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Enable GPO to enforce RestrictedAdmin mode.
      owner: IT Operations
      addresses: RDP Security configuration
---

Adversaries modify the Windows registry key DisableRestrictedAdmin to lower the security posture of Remote Desktop (RDP) connections. When this registry value is set to 0, it enables RestrictedAdmin mode, which prevents the transmission of plaintext or cached credentials to the remote target. By tampering with this configuration (typically via registry modification commands like reg.exe or PowerShell), attackers aim to disable this protection. This allows them to harvest reusable credentials when a user initiates an RDP connection to a compromised host, potentially leading to lateral movement and privilege escalation within the network. This technique is often observed as part of post-exploitation activity where attackers attempt to maintain access or expand their footprint across an environment. Monitoring for modifications to this specific Local Security Authority (LSA) registry path is a critical detective control for identifying credential harvesting attempts.

## Impact

Successful tampering with the DisableRestrictedAdmin registry key compromises the integrity of RDP sessions, directly exposing user credentials to harvest on remote systems. If achieved, this enables attackers to capture high-value administrative credentials, significantly increasing the risk of domain-wide compromise and persistent unauthorized access across the Windows environment.

## Recommendation

Detection engineering teams should monitor for unauthorized modifications to the LSA registry hive related to Remote Desktop security configurations. 

- Deploy the provided Sigma rule to detect command-line processes targeting the LSA registry path for DisableRestrictedAdmin.
- Audit existing Group Policy Objects (GPOs) to ensure RestrictedAdmin mode is enforced globally and that registry modifications are restricted via Endpoint Detection and Response (EDR) or AppLocker policies.
- Review historical logs for process execution of 'reg.exe' or 'powershell.exe' containing the path 'System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin'.
