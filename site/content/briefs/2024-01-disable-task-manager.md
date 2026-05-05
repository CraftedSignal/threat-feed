---
title: Windows Registry Modification to Disable Task Manager
slug: 2024-01-disable-task-manager
description: Attackers modify the Windows registry to disable Task Manager, preventing users from terminating malicious processes and allowing persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - privilege-escalation
  - registry-modification
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows
references:
  - https://any.run/report/ea4ea08407d4ee72e009103a3b77e5a09412b722fdef67315ea63f22011152af/a866d7b1-c236-4f26-a391-5ae32213dfc4#registry
  - https://blog.talosintelligence.com/2020/05/threat-roundup-0424-0501.html
rules:
  - title: Registry Modification to Disable Task Manager
    description: Detects modifications to the Windows registry that disable Task Manager.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying DisableTaskMgr Registry Key
    description: Detects a process modifying the DisableTaskMgr registry key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers modify the Windows Registry to disable the Task Manager on compromised systems. This is a common tactic employed by malware, including Remote Access Trojans (RATs), Trojans, and worms, to prevent users from identifying and terminating malicious processes. Disabling the Task Manager can hinder incident response efforts and allow malware to maintain persistence and control over the infected system. The registry key targeted is typically `*\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` with a value of `0x00000001`.

## Attack Chain

1. Initial access is achieved through various means, such as phishing or exploiting vulnerabilities in applications or the operating system.
2. The attacker gains elevated privileges to modify the Windows Registry.
3. The attacker modifies the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` or `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`.
4. The registry value `DisableTaskMgr` is set to `0x00000001`, effectively disabling the Task Manager.
5. The user attempts to open Task Manager but is blocked.
6. The attacker continues to perform malicious activities, such as data exfiltration or lateral movement.
7. The attacker maintains persistence on the compromised system without the user being able to easily terminate malicious processes.

## Impact

Disabling the Task Manager hinders the ability of users and security personnel to identify and terminate malicious processes running on the compromised system. This allows attackers to maintain persistence, escalate privileges, and conduct further malicious activities, potentially leading to data theft, system compromise, and disruption of services.

## Recommendation

*   Deploy the Sigma rule `Registry Modification to Disable Task Manager` to your SIEM and tune for your environment.
*   Monitor registry modifications to `*\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` with a value of `0x00000001` using Sysmon Event ID 13.
*   Investigate any alerts triggered by the Sigma rule and analyze the associated processes and user accounts.
*   Educate users about the risks of opening suspicious attachments or clicking on links from untrusted sources.
*   Ensure that systems are patched with the latest security updates to prevent exploitation of vulnerabilities.
