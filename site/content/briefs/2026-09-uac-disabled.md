---
title: Modification of UAC EnableLUA Registry Key
slug: 2026-09-uac-disabled
description: Detection of attackers attempting to disable Windows User Account Control (UAC) via registry manipulation to bypass privilege escalation protections.
date: "2026-09-01T12:14:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Detects when an attacker tries to disable User Account Control (UAC) by setting the registry value EnableLUA to 0.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md
rules:
  - title: Detect UAC Disable Registry Modification
    description: Detects when an attacker attempts to disable User Account Control (UAC) by setting the registry value EnableLUA to 0
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
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
    - action: Deploy Sigma detection rule to monitor for EnableLUA registry modifications
      owner: Detection Engineering
      due: 24h
      evidence: Source provides explicit Sigma logic for this TTP
  hunt_leads:
    - lead: Registry modifications to System policies
      technique_id: T1548.002
      data_needed:
        - Sysmon Event ID 12/13
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Registry key EnableLUA is a standard indicator for UAC bypass attempts
---

Disabling User Account Control (UAC) is a common post-exploitation technique used by attackers to weaken the security posture of a Windows host. By setting the EnableLUA registry key to 0, an attacker can prevent the system from prompting for administrative consent, effectively allowing malicious processes to run with elevated privileges without standard user interaction. This configuration change requires administrative access initially, meaning it is typically performed as a persistence or privilege escalation maintenance step rather than an initial entry vector. Detection of this activity is critical, as it serves as a high-fidelity indicator of an adversary attempting to modify host security settings to facilitate further malicious actions.

## Impact

Successful modification of the EnableLUA registry key results in the complete deactivation of UAC prompts for administrative tasks. This increases the susceptibility of the endpoint to privilege escalation, as malware can execute elevated commands silently. If the attacker maintains administrative persistence, this change ensures that subsequent malicious activities encounter no further user-interface hurdles, significantly increasing the probability of full system compromise and credential harvesting.

## Recommendation

Deploy the provided Sigma rule to monitor for registry modifications targeting the EnableLUA system policy. Analysts should investigate any unauthorized process initiating a write request to this registry hive, particularly if the process is not a recognized system management or group policy update utility.

- Enable registry auditing on the path `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` to capture successful set operations.
- Integrate the Sigma rule below into the SIEM to alert on immediate changes to the EnableLUA value.
- Review administrative privileges on affected endpoints to ensure that only authorized accounts can modify system policy registry keys.
