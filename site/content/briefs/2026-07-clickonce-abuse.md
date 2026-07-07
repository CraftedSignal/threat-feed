---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings of ClickOnce Application Deployment'
slug: 2026-07-clickonce-abuse
description: Threat actors are leveraging Microsoft's ClickOnce technology, a legitimate Windows application deployment mechanism allowing non-administrative installations and automatic updates, to distribute malware, simplify payload delivery, and achieve initial access and persistence on user endpoints.
date: "2026-07-05T11:16:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - application-deployment
  - windows
  - abuse
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By packaging malicious applications using ClickOnce, attackers can simplify the delivery and execution of their payloads on user endpoints, potentially achieving initial access and persistence on compromised systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: By packaging malicious applications using ClickOnce, attackers can simplify the delivery and execution of their payloads on user endpoints, potentially achieving initial access and persistence on compromised systems.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: By packaging malicious applications using ClickOnce, attackers can simplify the delivery and execution of their payloads on user endpoints, potentially achieving initial access and persistence on compromised systems.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a potential new abuse vector involving Microsoft's ClickOnce technology, a legitimate deployment mechanism for Windows applications. Published on July 5, 2026, this first part of a two-part series details the inner workings of ClickOnce, explaining its design to simplify software distribution and installation without requiring administrative privileges or extensive user interaction. While intended for legitimate developers to easily publish and update applications, its user-friendly nature makes it an attractive channel for threat actors to spread malware. This brief focuses on how ClickOnce functions, from publishing an application in Visual Studio to its deployment and optional installation on a user's system, laying the groundwork for understanding how adversaries can weaponize this feature for initial access and persistence, as further detailed in Part 2 of the research.

## Attack Chain

1.  **Crafting Malicious Application**: A threat actor develops or repackages a malicious payload into a ClickOnce application using tools like Visual Studio, generating `.application` and `.manifest` files.
2.  **Hosting Deployment Files**: The malicious ClickOnce deployment files are hosted on an attacker-controlled web server or network share, masquerading as legitimate software.
3.  **Social Engineering**: The victim is lured, often through phishing emails, instant messages, or compromised websites, to click a link pointing to the malicious `.application` file.
4.  **User Execution & Trust Prompt**: The user's system downloads the `.application` file, and the ClickOnce runtime initiates the deployment. If the application is unsigned or from an unknown publisher, a trust prompt is displayed.
5.  **Malicious Deployment**: Upon user confirmation, the malicious ClickOnce application executes, leveraging its non-administrative deployment capabilities to install malware components (e.g., executables, scripts) into the user's profile.
6.  **Payload Execution & Persistence**: The installed malicious application executes its payload, which could include establishing persistence mechanisms (e.g., modifying registry `Run` keys, creating scheduled tasks) and initiating command-and-control communication.
7.  **Objective Achievement**: The attacker achieves their objective, such as initial access to the system, data exfiltration, or further lateral movement within the network.

## Impact

While this brief focuses on the technical mechanics, the abuse of ClickOnce applications provides adversaries with a simplified and potentially stealthy method for malware distribution. If exploited, attackers can bypass traditional installation barriers, delivering malicious payloads directly to user endpoints without requiring elevated privileges. The inherent trust users might have in Microsoft technologies or what appears to be a standard application installation wizard increases the likelihood of successful deployment, leading to initial compromise, persistence, and potential data exfiltration or further system compromise as a result of the deployed malware.

## Recommendation

*   Enable comprehensive process creation logging (e.g., via Sysmon) to monitor for ClickOnce application launches, typically initiated by `dfsvc.exe` or directly from `.application` files.
*   Collect file event logs (e.g., Sysmon Event ID 11 or 23) to track the creation of ClickOnce related files, specifically `.application` and `.manifest` files, in user profile directories or temporary folders.
*   Monitor network connection logs for outbound connections from `dfsvc.exe` or ClickOnce deployed applications to unusual or untrusted domains.
