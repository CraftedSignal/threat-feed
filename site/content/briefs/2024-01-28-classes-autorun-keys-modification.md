---
title: Windows Registry Classes Autorun Keys Modification for Persistence
slug: 2024-01-28-classes-autorun-keys-modification
description: Adversaries modify Windows Registry Classes keys to establish persistence by executing malicious code when specific file types are opened or actions are performed, potentially leading to privilege escalation and persistent access.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.t1547.001
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
  - https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
  - https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_classes.yml
rules:
  - title: Suspicious Modification of .exe Association
    description: Detects suspicious modification of the .exe file association in the registry, often used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Modification of ShellEx DragDropHandlers
    description: Detects modifications to ShellEx DragDropHandlers, which is often abused by malware for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious CLSID Instance Modification
    description: Detects modification of CLSID Instance registry keys associated with media codecs, a common persistence location
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Attackers can manipulate Windows Registry Classes keys, an autostart extensibility point (ASEP), to achieve persistence. This involves modifying registry entries that control how the operating system handles specific file types or shell actions. By modifying these keys, adversaries can ensure their malicious code executes whenever a user interacts with a specific file type (e.g., opening an .exe) or performs a specific action within the shell. This technique, which has been observed since at least 2019, allows malicious actors to maintain a persistent foothold on compromised systems. While legitimate software also utilizes these registry keys, careful filtering and monitoring are crucial for distinguishing malicious modifications from benign software installations. Detection can be noisy due to the legitimate use of these keys, so tuning and review is critical.

## Attack Chain

1.  Initial Access: The attacker gains initial access through a separate vector (e.g., phishing, exploit). This stage is not covered by this detection, which focuses on post-exploitation activity.
2.  Privilege Escalation (if needed): The attacker may need elevated privileges to modify certain registry keys. This can involve exploiting vulnerabilities or leveraging existing administrative rights.
3.  Registry Key Modification: The attacker modifies specific keys under `\Software\Classes` in the Windows Registry. Common targets include `\Folder\ShellEx\ExtShellFolderViews`, `\.exe`, and `\Directory\Shellex\DragDropHandlers`.
4.  Payload植入：攻击者修改注册表项指向一个恶意可执行文件或脚本。这可能涉及替换默认命令或添加新的处理程序。
5.  Execution Trigger: The malicious code is configured to execute when a user interacts with the associated file type or shell action (e.g., opening a .exe file, right-clicking a folder).
6.  Malicious Payload Execution: When the configured trigger occurs, the malicious payload executes, giving the attacker control over the system.
7.  Persistence Maintained: The modified registry keys ensure that the malicious payload will continue to execute whenever the trigger occurs, maintaining persistence across reboots or user logons.
8.  Objective Achieved: The attacker leverages persistent access to achieve their objectives, such as data exfiltration, lateral movement, or deploying ransomware.

## Impact

Successful exploitation allows attackers to maintain persistent access to compromised systems, bypassing traditional security measures. This can lead to significant data breaches, financial losses, and reputational damage. The number of potential victims is broad, as any Windows system is potentially vulnerable. The types of damage possible range from credential theft to ransomware deployment, depending on the attacker's objectives.

## Recommendation

*   Enable Windows Registry auditing and monitor `registry_set` events for modifications to keys under `\Software\Classes` to identify suspicious activity.
*   Deploy the Sigma rule "Classes Autorun Keys Modification" to your SIEM and tune the filters (filter_main_*, filter_optional_*) for your specific environment to reduce false positives.
*   Investigate any registry modifications detected by the Sigma rule, focusing on unusual executables or scripts being launched from these locations.
*   Regularly review and update the filters in the Sigma rule to account for legitimate software changes in your environment.
