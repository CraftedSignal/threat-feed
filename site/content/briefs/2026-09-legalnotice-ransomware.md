---
title: Suspicious Modification of Windows Legal Notice Registry Keys
slug: 2026-09-legalnotice-ransomware
description: Adversaries modify Windows LegalNotice registry values to display custom ransom messages during the login process as part of an extortion campaign.
date: "2026-09-01T11:07:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - registry
  - windows
  - impact
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: Adversaries modify Windows LegalNotice registry values to display custom ransom messages during the login process.
    confidence_band: high
rules:
  - title: Detect Suspicious LegalNotice Registry Modification
    description: Detect changes to the LegalNoticeCaption or LegalNoticeText registry values containing keywords indicative of extortion or ransomware activity.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1491.001
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
    - action: Deploy the Sigma rule to monitor for LegalNotice modifications.
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief.
  hunt_leads:
    - lead: Search for historical changes to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
      technique_id: T1491.001
      data_needed:
        - Registry set events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Registry keys are persistent and can be audited post-compromise.
---

Adversaries often target the Windows Registry to influence system behavior at login. By modifying the LegalNoticeCaption and LegalNoticeText registry keys located in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, an attacker can force the operating system to display a message box to the user before they can log in. In the context of ransomware or extortion operations, threat actors use this capability to present victims with instructions for data recovery, contact information for extortion negotiations, or proof-of-compromise declarations. This technique provides a persistent, highly visible method of communication that survives system reboots and forces interaction from any user attempting to access the workstation. Detecting unauthorized modifications to these specific registry keys is a high-fidelity indicator of potential system tampering for the purpose of coercion.

## Attack Chain

1. Attacker gains administrative access to the target endpoint.
2. Attacker identifies the target registry hive (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).
3. Attacker uses command-line utilities like reg.exe or PowerShell to modify registry values.
4. Attacker updates the LegalNoticeCaption value to a warning header.
5. Attacker updates the LegalNoticeText value to contain specific ransom-related keywords.
6. The system configuration is updated to enforce the display of these strings on the next login attempt.
7. The user is presented with the adversary's message upon the next login process.
8. Final objective of extortion or psychological pressure on the victim is achieved.

## Impact

Successful exploitation of this technique results in the immediate, high-visibility notification of compromised systems to end users and administrators. While the modification itself is not destructive, it is an indicator of an adversary with administrative privileges on the endpoint who is engaged in extortion activity. Failure to detect this can delay incident response during a broader ransomware or data exfiltration event, as the adversary controls the primary interface for system interaction.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious modifications to LegalNotice registry keys. Filter for legitimate administrative activity (e.g., corporate policy banners) to reduce noise. Investigate any process modifying these keys that is not associated with authorized configuration management software.
