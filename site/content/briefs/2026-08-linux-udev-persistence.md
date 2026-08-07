---
title: Abuse of Linux UDEV Rules for Persistence and Privilege Escalation
slug: 2026-08-linux-udev-persistence
description: Adversaries leverage the creation of malicious udev rules in system directories to achieve persistent, elevated code execution triggered by device events.
date: "2026-08-07T15:18:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries abuse udev rules to achieve persistent code execution by embedding RUN+= directives that trigger arbitrary commands whenever a matching device event occurs.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
    evidence: Because udev rules execute in the context of the udev daemon with elevated privileges, this technique can provide both persistence and privilege escalation.
    confidence_band: high
rules:
  - title: Detect Linux UDEV Rule Creation
    description: Detects the creation of files within udev rules directories which can be used for persistence or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1037
      - T1547
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Linux UDEV rule creation Sigma rule.
      owner: Detection Engineering
      due: 72h
      evidence: Source material defines udev abuse as a persistence technique observable via filesystem events.
  hunt_leads:
    - lead: Audit existing /etc/udev/rules.d/ files for suspicious RUN+= directives.
      technique_id: T1547
      data_needed:
        - File content scan of existing rules.
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Persistence is achieved via embedding RUN+= directives.
  mitigation_plan:
    - priority: short_term
      action: Restrict write access to /etc/udev/rules.d/ and /usr/lib/udev/rules.d/ to authorized accounts only.
      owner: IT Operations
      addresses: T1547
      evidence: Persistence requires file modification in system directories.
---

Adversaries are increasingly abusing Linux udev rules, a mechanism for managing device events, to achieve persistence and privilege escalation on compromised systems. By creating or modifying rule files within monitored directories such as /etc/udev/rules.d/ or /usr/lib/udev/rules.d/, attackers can embed malicious 'RUN+=' directives. These directives force the udev daemon, which runs with root privileges, to execute arbitrary commands whenever a specific device event occurs, such as a USB device insertion or a network interface state change.

This technique is particularly effective on headless servers and is a documented capability within post-exploitation frameworks like PANIX. Because the payload is triggered by hardware-related events rather than standard user interaction, this persistence mechanism is difficult to detect without monitoring file system modifications in sensitive system paths. Defenders should focus on tracking any unauthorized file creation or modification events within the defined udev rule directories.

## Attack Chain

1. Attacker gains initial access to the Linux system through a separate vulnerability or misconfiguration.
2. Attacker performs local reconnaissance to identify existing udev rules or system hardware configurations.
3. Attacker identifies writable access to /etc/udev/rules.d/ or /usr/lib/udev/rules.d/ directories.
4. Attacker crafts a new .rules file containing a 'RUN+=' directive pointing to a malicious payload or script.
5. Attacker triggers a corresponding device event (e.g., physically connecting a USB device or spoofing an interface signal).
6. The udev daemon processes the new rule, executing the malicious command with root privileges.
7. Attacker successfully gains persistent backdoor access or elevates privileges on the host.

## Impact

Successful exploitation results in reliable persistence that survives system reboots and provides the attacker with elevated, root-level execution every time a specific hardware event occurs. This technique is especially potent for maintaining access on headless infrastructure, potentially leading to full system compromise, data exfiltration, and further lateral movement within the network.

## Recommendation

Deploy detection for file creation events targeting the /etc/udev/rules.d/ and /usr/lib/udev/rules.d/ directories.
Monitor for any process spawning from the udevd process or udev-related tasks that were not initiated by authorized system administration activity.
Review logs from Sysmon for Linux EventID 11 to identify anomalous file creations in protected system directories.
Integrate the provided Sigma rule into your SIEM to alert on unauthorized modifications to udev configuration files.
