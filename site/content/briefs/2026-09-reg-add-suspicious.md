---
title: Detection of Suspicious Registry Key Modifications via Reg.exe
slug: 2026-09-reg-add-suspicious
description: This brief documents detection logic for identifying potentially malicious registry modifications using the native Windows reg.exe utility to target sensitive system and persistence-related paths.
date: "2026-09-01T12:08:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - defense-impairment
  - windows
  - reg
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Adversaries use reg.exe to modify registry keys to maintain persistence.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: Modifying Windows Defender registry keys is a common method for defense impairment.
    confidence_band: high
rules:
  - title: Detect Suspicious Registry Modifications via Reg.exe
    description: Detects when the reg.exe utility is used to modify sensitive registry keys associated with persistence, security providers, or defense impairment.
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
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to monitor for registry modification via reg.exe.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search historical logs for reg.exe command lines containing the specified sensitive paths.
      technique_id: T1112
      priority: medium
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: medium_term
      action: Restrict access to reg.exe for standard user accounts.
      owner: IT Operations
---

Adversaries frequently leverage the native Windows registry utility, reg.exe, to achieve persistence, impair security controls, or elevate privileges. By modifying specific registry keys and subkeys, attackers can disable security features, execute arbitrary code at startup, or exfiltrate configuration data. This detection engineering brief focuses on monitoring reg.exe command-line activity targeting high-risk registry paths, such as Windows Defender settings, Winlogon configurations, and OOBE policy keys. These paths are commonly associated with both persistence mechanisms and defense impairment tactics, making them critical observation points for security operations teams seeking to identify unauthorized system modifications.

## Impact

Successful exploitation of registry-based persistence or defense impairment can lead to long-term system compromise, unmonitored lateral movement, or the suppression of security alerts, ultimately hindering incident response and forensic analysis capabilities.

## Recommendation

Deploy the provided Sigma rule to detect the execution of reg.exe attempting to modify sensitive registry keys. Prioritize investigation of alerts originating from non-administrative service accounts or unauthorized administrative workstations.

* Deploy the Sigma rule below to SIEM platforms to alert on suspicious reg.exe command arguments.
* Review administrative scripts that may legitimately interact with the identified paths and add them to an allowlist if necessary to reduce noise.
