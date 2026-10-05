---
title: Detection of Unauthorized Remote Access Software Persistence
slug: 2026-10-remote-access-persistence
description: This detection monitors for the configuration of known remote access utilities within Windows registry persistence locations to identify potential adversary activity aimed at maintaining long-term control.
date: "2026-10-05T12:11:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - command-and-control
  - remote-access-software
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries use these utilities to retain remote access capabilities to the environment.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1219/
  - https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
  - https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
rules:
  - title: Detect Remote Access Software Persistence via Registry
    description: Detects when known remote access software is configured to persist by adding an entry to Windows Run keys or creating/modifying system services.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1219
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
    - action: Deploy registry-monitoring detection rule.
      owner: Detection Engineering
      due: 72h
      evidence: Source analytic metadata.
  mitigation_plan:
    - priority: medium_term
      action: Establish and maintain a centralized allowlist for remote administrative tools.
      owner: IT Operations
      evidence: Best practice for managing dual-use software.
---

Adversaries and unauthorized users frequently leverage legitimate remote access software (RAS) to maintain persistent, remote control over compromised systems within an enterprise environment. By modifying Windows registry keys associated with automatic startup, such as "Run" keys or Service "ImagePath" values, actors ensure these utilities execute upon system reboot or user login. 

This analytic identifies the unauthorized configuration of such software - including tools like AnyDesk, GoToMyPC, LogMeIn, and TeamViewer - by monitoring Sysmon Event ID 13 registry modifications. Defenders should maintain a robust allowlist of approved enterprise remote administration tools, as these utilities are dual-use and commonly employed by both IT administrators and malicious actors for persistence (MITRE ATT&CK T1219). This approach allows SOC teams to filter out expected administrative behavior while focusing investigations on unauthorized or unexpected remote access software deployments.

## Impact

Successful deployment of unauthorized remote access software allows attackers to bypass traditional network perimeter defenses, exfiltrate sensitive data, and execute further stages of an attack chain. This technique is frequently associated with ransomware operators and secondary infection chains, such as those observed in Gozi, Emotet, and Bumblebee campaigns. Failure to monitor for these persistence mechanisms increases the risk of long-term undetected access and eventual catastrophic business impact from ransomware or data theft.

## Recommendation

* Enable Sysmon Event ID 13 logging to capture registry modification events across all endpoints.
* Implement the suggested registry-monitoring Sigma rule to trigger alerts when remote access utilities are added to Windows startup paths.
* Utilize the "remote_access_software_usage_exceptions" lookup mechanism to maintain an enterprise-wide allowlist of authorized administrative tools, reducing noise for the security operations center.
* Prioritize investigations where a remote access utility is detected on high-value targets (e.g., domain controllers, build servers, or sensitive workstations) as these often represent deliberate persistence efforts by an adversary.
