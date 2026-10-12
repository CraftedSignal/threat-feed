---
title: Windows System User Discovery via Quser
slug: 2026-10-quser-discovery
description: Adversaries leverage the native Windows utility quser.exe to enumerate active RDP user sessions, a common reconnaissance technique observed in post-exploitation frameworks like winPEAS and ransomware campaigns.
date: "2026-10-12T18:25:13Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - post-exploitation
  - windows
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: The following analytic detects the execution of the Windows OS tool quser.exe, commonly used to gather information about user sessions on a Remote Desktop Session Host server.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/quser
  - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
  - https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/
rules:
  - title: Detect Windows System User Discovery via Quser
    description: Detects the execution of quser.exe, a utility used to enumerate active user sessions.
    platform: sigma
    severity: low
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
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule for quser.exe execution.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides analytic guidance.
  hunt_leads:
    - lead: Search for quser.exe usage by non-admin service accounts.
      technique_id: T1033
      data_needed:
        - Process creation logs with user context
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: quser.exe is often abused by post-exploitation tools.
---

The Windows utility `quser.exe` is frequently abused by attackers during the post-exploitation phase to gather information about active user sessions on a system or Remote Desktop Session Host. This technique is categorized under system user discovery and is commonly implemented by automated privilege escalation and post-exploitation tools, such as winPEAS. By enumerating active sessions, attackers identify high-value accounts or existing administrative sessions to facilitate further compromise, privilege escalation, or lateral movement. This behavior has been observed in various attack campaigns, including the deployment of Prestige ransomware. Defenders should monitor for the execution of this utility, particularly when initiated by suspicious parent processes or in environments where the tool is not required for daily administration.

## Impact

Successful user discovery allows attackers to map the environment, identify target accounts for credential harvesting, and determine the reach of current session access. This reconnaissance is a critical prerequisite for lateral movement and the subsequent deployment of ransomware or other destructive payloads.

## Recommendation

* Deploy the provided Sigma rule to monitor for execution of `quser.exe` via endpoint process creation logs.
* Establish a baseline of legitimate `quser.exe` usage by network and systems administrators to reduce false positives.
* Correlate `quser.exe` execution with other post-exploitation indicators, such as the use of `winPEAS` or unexpected network connections.
