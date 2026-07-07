---
title: Threat Actors Abuse Microsoft ClickOnce for Stealthy Persistence and Malware Delivery
slug: 2026-07-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce deployment technology to bypass traditional defenses, gain stealthy persistence on victim systems without elevated privileges, and update malware payloads through its legitimate update mechanism.
date: "2026-07-07T18:30:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - execution
  - defense-evasion
  - windows
  - malware-delivery
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The malicious ClickOnce application is delivered to the victim, typically via social engineering tactics like phishing emails containing a direct link or an .application file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The victim is convinced to click the provided link or execute the .application file, initiating the ClickOnce deployment process.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: Legitimate Microsoft processes, such as rundll32.exe or dfsvc.exe, are launched by the ClickOnce framework to install and execute the initial malicious payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: To ensure persistent access, the attacker establishes an auto-run mechanism by creating a shortcut (.appref-ms file) in the user's Startup folder
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payloads execute within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: leveraging its built-in update mechanism to fetch new malicious components from the attacker-controlled server.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folder
    description: Detects the creation of .appref-ms files in the Windows Startup folder, a known technique for adversaries to establish persistence using abused ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1036
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

CrowdStrike has identified new abuses of Microsoft's ClickOnce technology, a legitimate application deployment framework, by threat actors for malicious purposes. Beginning around June 2026, adversaries are weaponizing ClickOnce due to its user-friendly deployment, minimal user interaction requirements, and general lack of awareness among users and security tools. This method allows threat actors to execute malware, establish persistence, and maintain remote access without requiring administrative privileges, often bypassing traditional defenses that scrutinize `.exe` files but overlook `.application` files. Attackers can push malicious updates to an already "approved" ClickOnce application, ensuring persistent compromise and dynamic malware delivery. The malicious payloads execute within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`, further increasing stealth and making detection challenging for defenders.

## Attack Chain

1.  Attacker crafts a malicious ClickOnce application, often disguised as a legitimate tool or document, to serve as an initial dropper.
2.  The malicious ClickOnce application is delivered to the victim, typically via social engineering tactics like phishing emails containing a direct link or an `.application` file.
3.  The victim is convinced to click the provided link or execute the `.application` file, initiating the ClickOnce deployment process.
4.  Legitimate Microsoft processes, such as `rundll32.exe` or `dfsvc.exe`, are launched by the ClickOnce framework to install and execute the initial malicious payload without requiring administrative privileges.
5.  To ensure persistent access, the attacker establishes an auto-run mechanism by creating a shortcut (`.appref-ms` file) in the user's `Startup` folder (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or by configuring a scheduled task to regularly execute the application.
6.  Upon subsequent system reboots or scheduled executions, the `.appref-ms` file triggers the ClickOnce application, leveraging its built-in update mechanism to fetch new malicious components from the attacker-controlled server.
7.  The continuously updated malware performs adversarial actions, such as maintaining remote access, facilitating lateral movement within the network, or exfiltrating sensitive data, while blending in with legitimate ClickOnce process activity.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access and deliver evolving malware with minimal user interaction and without requiring elevated privileges. This significantly lowers the barrier to entry for attacks, as standard user accounts can be compromised. Organizations face increased risk of data exfiltration, system compromise, and network-wide infection due to the stealthy nature of this technique, which bypasses traditional defenses and operates within legitimate Microsoft process trees. The built-in update mechanism further complicates remediation, as malware can be updated dynamically to evade detection or change C2 infrastructure.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically monitoring for `file_event` logs related to `.appref-ms` files in `Startup` directories.
*   Implement strong application control policies (e.g., Windows Defender Application Control - WDAC) to restrict or audit the execution of unsigned ClickOnce applications or those from untrusted sources.
*   Educate users about the risks associated with clicking on unfamiliar links or executing `.application` files, even if they appear to originate from trusted sources.
*   Monitor process creation logs for unusual child processes or network connections originating from `rundll32.exe` or `dfsvc.exe` that are not part of expected ClickOnce operations.
