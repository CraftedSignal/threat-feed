---
title: Detection of Malicious Security Center AV Registry Tampering
slug: 2026-10-defendnot-security-center
description: This detection targets unauthorized modifications to Windows Security Center registry keys used by threat actors to spoof or disable antivirus product reporting.
date: "2026-10-19T09:50:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - windows
  - registry
  - security-center
affected_os:
  - Windows
rules:
  - title: Detect Security Center AV Registry Modification
    description: Detects unauthorized modification of Windows Security Center AV registry keys, which may indicate an attempt to spoof or tamper with security product information.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
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
    - action: Deploy Sigma rule to monitor HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av\*
      owner: Detection Engineering
      due: 48h
      evidence: Rule definition provided in brief
  hunt_leads:
    - lead: Identify processes other than svchost.exe modifying WSC registry keys
      technique_id: T1685
      data_needed:
        - Registry Event ID 12/13
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes registry modification as a bypass technique
---

Adversaries often attempt to impair security defenses by manipulating the Windows Security Center (WSC) to mask their presence or facilitate the deployment of malicious tools. By modifying registry keys located under 'HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av\', attackers can register fake or misleading antivirus product information, such as the 'DisplayName', 'ProductEXE', or 'ReportingExe' values. This technique, often referred to as "Defendnot," aims to trick the operating system and monitoring tools into believing a legitimate security product is active, effectively bypassing security software detection or silencing alerts. This behavior is typically observed in the context of post-exploitation toolkits seeking to maintain persistence and evade endpoint detection and response (EDR) agents.

## Impact

Successful manipulation of Security Center registry keys can lead to the successful deployment of secondary payloads, prolonged dwell time, and the potential for complete system compromise due to the blinding of security telemetry and defensive controls.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to monitor for unauthorized writes to WSC registry keys.
* Baseline the 'Details' field in your environment to identify legitimate antivirus installers that may not be included in the default filter list.
* Investigate any process other than 'svchost.exe' attempting to modify these specific registry keys.
