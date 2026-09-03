---
title: PowerShell GPO Configuration Modification
slug: 2026-09-modify-gpo
description: Adversaries may modify Group Policy settings via PowerShell to impair defensive capabilities or maintain persistence within a Windows environment.
date: "2026-09-03T13:40:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - privilege-escalation
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Policy Modification
    evidence: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain Policy Modification
    evidence: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_modify_group_policy_settings.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1484.001/T1484.001.md
rules:
  - title: Detect GPO Configuration Modification via PowerShell
    description: Detects PowerShell script blocks attempting to modify registry keys associated with Group Policy settings.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - privilege-escalation
    techniques:
      - T1484.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 48h
      evidence: Required telemetry for the detection rule
  hunt_leads:
    - lead: Search for script block logs containing targeted GPO registry paths
      technique_id: T1484.001
      data_needed:
        - Event ID 4104
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sigma detection logic targets specific registry paths in script blocks
  mitigation_plan:
    - priority: medium_term
      action: Restrict write access to sensitive HKLM registry paths to authorized system accounts only
      owner: IT Operations
      addresses: T1484.001
      evidence: Adversaries modify these keys to alter security posture
---

Adversaries often attempt to modify Group Policy Objects (GPO) to change system configurations, disable security controls, or establish persistence. By leveraging PowerShell to interact with the Windows Registry or specific GPO configuration paths, attackers can bypass security defaults or disable features such as Windows SmartScreen. This technique falls under the umbrella of defense impairment and privilege escalation, as successful modifications typically require administrative or SYSTEM level privileges. Monitoring for PowerShell script blocks that reference critical GPO-related registry keys provides visibility into unauthorized configuration changes that could impact the security posture of the endpoint or the wider domain environment.

## Impact

Successful modification of GPO settings can lead to the widespread disablement of security features, unauthorized persistence, and the potential for privilege escalation across the enterprise. Unauthorized changes to policy refresh times or SmartScreen settings can reduce the effectiveness of endpoint protection platforms and increase the likelihood of subsequent malicious actions going undetected.

## Recommendation

Detection engineering teams should implement monitoring for PowerShell script blocks referencing GPO registry paths.

* Deploy the provided Sigma rule to capture script block logging events (Event ID 4104) that target GPO registry keys.
* Ensure PowerShell Script Block Logging is enabled across the environment to provide the necessary telemetry.
* Correlate detections with GPO backup logs and Active Directory audit logs to verify if changes were authorized via standard management tools.
