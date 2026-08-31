---
title: Detection of System User Discovery via whoami.exe
slug: 2026-08-system-user-discovery
description: Adversaries frequently utilize the native whoami.exe utility for reconnaissance to identify the current logged-in user context, a common precursor to privilege escalation and lateral movement.
date: "2026-08-31T11:52:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: The following analytic detects the execution of whoami.exe without any arguments, which is used by Red Teams and adversaries to identify the current logged-in user.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/system_user_discovery_with_whoami.yml
rules:
  - title: Detect System User Discovery via whoami.exe
    description: Detects the execution of whoami.exe which is frequently used by adversaries for system user discovery and situational awareness.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for whoami.exe process execution monitoring
      owner: Detection Engineering
      due: 72h
      evidence: Source provides analytic logic for detection of T1033
  mitigation_plan:
    - priority: medium_term
      action: Review and baseline administrative use of system discovery tools
      owner: SOC
      addresses: T1033
      evidence: Source identifies administrative troubleshooting as a common false positive
---

The execution of 'whoami.exe' is a standard technique utilized by various threat actors, including those behind Rhysida Ransomware, Qakbot, and the Winter Vivern campaign, to gain situational awareness on a compromised host. By querying the system for the current user identity, attackers establish context necessary for subsequent phases of the attack lifecycle, such as determining the success of initial access or identifying accounts suitable for privilege escalation and lateral movement. Defenders should note that while this activity is often observed in malicious contexts, it is also frequently performed by administrators and power users for routine system troubleshooting, necessitating careful tuning of detection logic to minimize noise.

## Impact

Successful reconnaissance via system user discovery provides attackers with the environmental knowledge required to navigate Active Directory, identify high-value targets, and select appropriate post-exploitation tools. If this activity goes undetected, it facilitates the progression of unauthorized access toward final objectives such as data exfiltration or the deployment of ransomware.

## Recommendation

Deploy the provided Sigma rule to monitor for process execution of 'whoami.exe' in your SIEM. Enable process-creation logging (Sysmon Event ID 1 or Windows Security Event ID 4688) across all endpoints. Baseline the typical frequency of 'whoami' execution by administrative accounts in your environment to distinguish between benign troubleshooting and unauthorized discovery behavior.
