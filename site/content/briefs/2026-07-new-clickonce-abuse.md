---
title: Threat Actors Abuse ClickOnce Technology for Malware Delivery
slug: 2026-07-new-clickonce-abuse
description: Threat actors are exploiting Microsoft's ClickOnce deployment technology to distribute malware, leveraging its ability to simplify application installation and updates on Windows systems without requiring administrative privileges, thereby bypassing traditional security controls and facilitating initial access and execution of malicious applications on user endpoints.
date: "2026-07-07T07:12:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - initial-access
  - execution
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker hosts a crafted ClickOnce application on a compromised website or distributes a malicious `.application` file via phishing.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1072
    technique_name: Software Deployment Tools
    evidence: ClickOnce is a 'deployment technology' that enables developers to package and distribute applications that users can run, install, and automatically update with minimal interaction and without requiring administrative privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Recent analysis by CrowdStrike highlights a new method of abusing Microsoft's ClickOnce deployment technology for malware distribution. ClickOnce, a legitimate feature designed to streamline application deployment, allows users to install and update applications with minimal interaction and often without administrative privileges. This user-friendly design, however, presents a significant vector for threat actors to deliver malicious payloads. By packaging malware as ClickOnce applications, attackers can circumvent security mechanisms that typically flag executables requiring elevated permissions, enabling easier initial access and execution on target Windows systems. This technique allows adversaries to bypass traditional defenses, making it crucial for defenders to understand the inner workings of ClickOnce to identify and mitigate such threats.

## Attack Chain

1.  **Malicious Delivery**: An attacker hosts a crafted ClickOnce application on a compromised website or distributes a malicious `.application` file via phishing.
2.  **User Initiates Deployment**: A user is lured into clicking an "Install" button on a webpage or directly opening the `.application` file.
3.  **Manifest Download**: The user's system downloads the ClickOnce deployment manifest (`.application` file), an XML-based file pointing to the actual application components.
4.  **User Confirmation**: The operating system prompts the user for confirmation to install the application, especially if the publisher's signature cannot be verified.
5.  **Application Deployment**: Upon user confirmation, the ClickOnce framework automatically downloads and executes the application components specified in the manifest.
6.  **Malware Execution**: The malicious application (e.g., a custom backdoor, infostealer, or ransomware loader) runs on the victim's machine without requiring administrative privileges for installation.
7.  **Persistence/Update**: The malicious ClickOnce application leverages its self-updating functionality to maintain persistence or fetch additional malicious modules from a C2 server.
8.  **Objective Achieved**: The attacker achieves their final objective, which could be data exfiltration, system compromise, or ransomware deployment.

## Impact

The abuse of ClickOnce technology significantly lowers the bar for attackers to achieve initial access and execution on Windows endpoints. Organizations could face widespread malware infections, data breaches, and system compromise, as the benign nature of ClickOnce applications (no admin rights needed for installation) can bypass traditional security defenses and user scrutiny. The ability of these applications to self-update also provides a built-in persistence mechanism, allowing attackers to refresh payloads or deploy new tools covertly. While no specific victim counts are detailed in this Part 1 brief, the ease of deployment suggests potential for broad targeting across various sectors.

## Recommendation

*   Enable comprehensive logging for process creation, file events, and network connections on Windows endpoints to monitor for suspicious ClickOnce activity.
*   Educate users about the risks of installing software from untrusted sources, even if it appears to be a simple "click-to-install" process, and the importance of verifying publisher signatures.
*   Monitor for the creation and execution of `.application` files and associated processes (e.g., `dfsvc.exe`, `rundll32.exe` with specific ClickOnce arguments) on Windows systems.
*   Deploy endpoint detection and response (EDR) solutions capable of inspecting ClickOnce deployment processes and detecting anomalies.
