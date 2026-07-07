---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings of ClickOnce Application Deployment'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are actively exploiting Microsoft's ClickOnce deployment technology to spread malware, leveraging its user-friendly installation process that requires minimal user interaction and no administrative privileges to deploy malicious applications.
date: "2026-07-06T07:16:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware
  - initial-access
  - windows
  - microsoft
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: tricking users into a 'click once' installation
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: user would only have to 'click once' to deploy the application
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Threat actors are increasingly leveraging Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to distribute malware. First documented by CrowdStrike on June 18, 2026, this abuse capitalizes on ClickOnce's design which enables user-friendly application installation and updates with minimal interaction and without requiring elevated administrative privileges. While designed to streamline software distribution for developers, this ease of deployment presents a significant security risk by providing an accessible channel for malicious application dissemination. Attackers can package malicious payloads as ClickOnce applications, tricking users into a "click once" installation that bypasses traditional security hurdles, making it a potent vector for initial access and execution in targeted environments. This initial brief details the internal workings of ClickOnce and its inherent vulnerabilities, setting the stage for understanding how attackers exploit it.

## Attack Chain

1.  **Publish Malicious Application**: An attacker utilizes Microsoft Visual Studio to publish a malicious application, configuring it for ClickOnce deployment, potentially opting for offline availability and update mechanisms.
2.  **Host Deployment Files**: The attacker hosts the generated ClickOnce deployment files (primarily the `.application` manifest file) on a controlled website or network share.
3.  **Lure User to Installation Link**: The attacker socially engineers a victim, often through phishing, to click an "Install" button or a direct link to the malicious ClickOnce `.application` file on a compromised or attacker-controlled website.
4.  **Initiate Download**: The user's browser or operating system initiates the download of the ClickOnce deployment manifest (`.application` file).
5.  **User Confirmation Prompt**: The Windows operating system prompts the user for confirmation to deploy the application, especially if the publisher's signature cannot be verified.
6.  **Application Deployment/Installation**: Upon the user's confirmation, the malicious ClickOnce application is deployed and potentially installed onto the system without requiring administrative privileges, initiating the attacker's payload.
7.  **Execution of Malicious Code**: The deployed application executes its malicious payload, which could range from establishing persistence to exfiltrating data or deploying further stages of an attack.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common security controls that rely on administrative privileges for software installation. This significantly lowers the barrier for attackers to gain initial access and execute code on victim systems. The user-friendly "click once" installation process, combined with potential social engineering, makes it highly effective for malware distribution across various sectors. If successful, this can lead to system compromise, data exfiltration, deployment of ransomware, or establishment of persistent access within the target environment, impacting the integrity, confidentiality, and availability of sensitive data and systems.

## Recommendation

*   Educate users about the risks associated with installing software from untrusted sources, particularly when prompted by the operating system during a `ClickOnce deployment`.
*   Implement application whitelisting policies to prevent the execution of unauthorized `ClickOnce applications` (and other executable types) on endpoints.
*   Enable comprehensive logging for `ClickOnce` related activities and application deployments to facilitate detection strategies, as will be detailed in Part 2 of the CrowdStrike research.
*   Deploy endpoint detection and response (EDR) solutions to monitor for suspicious `process_creation` and `network_connection` activities initiated by newly deployed applications.
