---
title: Tampering with DisableRestrictedAdmin Registry Value
slug: 2026-09-restricted-admin-tampering
description: Attackers may modify the DisableRestrictedAdmin registry value to impair credential protection mechanisms by disabling Restricted Admin mode for Remote Desktop Services.
date: "2026-09-01T12:12:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - defense-impairment
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The rule monitors registry modifications to alter security settings.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Disabling security features via registry modification.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_lsa_disablerestrictedadmin.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/a8e3cf63e97b973a25903d3df9fd55da6252e564/atomics/T1112/T1112.md
rules:
  - title: Detect RestrictedAdminMode Registry Value Tampering
    description: Detects unauthorized changes to the DisableRestrictedAdmin registry value which governs RDP credential protection.
    platform: sigma
    severity: high
    tactics:
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor DisableRestrictedAdmin changes
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry path for monitoring
  mitigation_plan:
    - priority: medium_term
      action: Enforce Restricted Admin mode via Group Policy
      owner: IT Operations
      addresses: Defense impairment
      evidence: Technet documentation on RDP security
---

Restricted Admin mode is a security feature in Windows that prevents the transmission of reusable credentials to remote systems when using Remote Desktop (RDP). By disabling this mode via the "DisableRestrictedAdmin" registry key, an attacker can ensure that plaintext or NTLM hash credentials are sent to a compromised host, facilitating credential harvesting and lateral movement. Defenders should monitor for unauthorized modifications to this registry path, as it is a common indicator of an attacker attempting to lower the security posture of the RDP service to extract credentials from administrative sessions.

## Impact

Successful modification of this setting compromises the integrity of remote administrative connections. By disabling Restricted Admin mode, attackers significantly increase the likelihood of successful credential theft via memory dumping tools like Mimikatz on a remote host, potentially leading to domain-wide account compromise and privilege escalation.

## Recommendation

Deploy the provided Sigma rule to detect modifications to the LSA Restricted Admin registry configuration. Enable Registry auditing via Group Policy for the "Set Value" operation on the target key. Alert on any unauthorized changes performed by non-administrative service accounts or automated provisioning scripts.
