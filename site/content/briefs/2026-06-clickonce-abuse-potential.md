---
title: Potential Abuse of Microsoft ClickOnce Technology for Malware Delivery
slug: 2026-06-clickonce-abuse-potential
description: Threat actors can abuse Microsoft's ClickOnce technology, which allows for simplified application distribution and installation with minimal user interaction and no administrative privileges, to easily spread malware and bypass traditional security controls through a 'click once' deployment.
date: "2026-06-19T04:55:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - windows
  - application-deployment
  - abuse-t1204.002
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Deployment Service Execution (dfsvc.exe)
    description: Detects the execution of dfsvc.exe, the Windows Deployment Foundation Services, which is central to ClickOnce application deployment. This can indicate legitimate activity or potential abuse.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Network Connections by ClickOnce Deployment Service
    description: Detects outbound network connections initiated by dfsvc.exe, which downloads ClickOnce application components. Monitoring these connections can help identify untrusted or malicious deployment sources.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect File Creation in ClickOnce Application Cache Directory
    description: Monitors for file creation events within the ClickOnce application cache, typically located in a user's AppData directory. While legitimate, new or unusual activity here might indicate a new ClickOnce application deployment, potentially malicious.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CrowdStrike has highlighted the potential for abuse of Microsoft's ClickOnce technology, a deployment mechanism designed to simplify application distribution and installation on Windows systems. While ClickOnce offers developers an easy way to package and deliver software, requiring minimal user interaction and no administrative privileges, these very features can be weaponized by threat actors. This initial analysis focuses on the underlying mechanics of ClickOnce deployment, setting the stage for understanding how malicious actors could leverage it to bypass traditional security measures. The user-friendly "click once" installation process means that unsuspecting victims could inadvertently deploy malware, making it a powerful vehicle for initial access and execution. This vulnerability is significant for defenders as it represents a novel or under-documented method for adversaries to achieve their objectives without relying on more commonly detected techniques.

## Attack Chain

1.  **Preparation**: Attacker crafts a malicious application and publishes it using ClickOnce technology, generating a deployment file (e.g., a `.application` file).
2.  **Delivery**: The attacker hosts the malicious ClickOnce deployment file on a controlled website or delivers it via a malicious link in a phishing email or message.
3.  **User Execution**: A victim is lured into clicking the malicious link or opening the deployment file, which triggers its download and initiates the ClickOnce deployment process.
4.  **Security Prompt**: The operating system displays a security warning or confirmation dialog to the user, particularly if the application publisher's signature is untrusted or unknown.
5.  **Deployment Service Invocation**: Upon user confirmation, the Windows Deployment Foundation Services (`dfsvc.exe`) process is invoked to handle the download and installation/execution of the ClickOnce application.
6.  **Application Cache Write**: The malicious ClickOnce application's files are downloaded and written to the user's ClickOnce application cache, typically located in `%LOCALAPPDATA%\Apps\2.0\`.
7.  **Malware Execution**: The malicious ClickOnce application is launched, executing its payload which could include installing additional malware, establishing persistence, or performing data exfiltration.

## Impact

If successfully abused, the ClickOnce technology can lead to widespread malware infections, enabling attackers to establish a foothold on victim systems without requiring elevated privileges. Organizations could face data breaches, ransomware attacks, or system compromise as malicious applications bypass conventional security controls. The user-friendly nature of ClickOnce deployment lowers the barrier for successful social engineering, increasing the likelihood of successful attacks across various sectors. While specific victim counts are not available for this abuse method in this part of the research, the potential impact is broad, affecting any Windows environment where users might encounter and execute ClickOnce applications.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically focusing on `process_creation` and `network_connection` logs related to ClickOnce.
*   Enable comprehensive `process_creation` logging to capture executions of `dfsvc.exe` and any processes launched from the ClickOnce application cache (`%LOCALAPPDATA%\Apps\2.0\`).
*   Monitor `network_connection` logs for outbound connections initiated by `dfsvc.exe` or other ClickOnce-related processes to suspicious or untrusted domains.
*   Educate users about the risks of executing applications from untrusted sources, even those presented through what appears to be a legitimate Windows installation wizard, as this relates to the Attack Chain step of "Security Prompt".
