---
title: New Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly abusing Microsoft's ClickOnce deployment technology, designed for simplified application distribution, to easily deploy and execute malicious applications on Windows endpoints without requiring administrative privileges, enabling broader malware distribution and bypassing traditional security controls.
date: "2026-07-07T06:48:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - deployment
  - malware-delivery
  - windows
  - execution
  - initial-access
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an “Install” button.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1072
    technique_name: Software Deployment Tools
    evidence: ClickOnce is a deployment technology that enables developers to package and distribute applications that users can run, install, and automatically update with minimal interaction and without requiring administrative privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: No elevated privileges required to perform the deployment
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Self-updating functionality allowing applications to automatically fetch and install updates from the deployment server
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Microsoft's ClickOnce is a legitimate deployment technology that streamlines the process of distributing and updating applications, allowing users to install and run software with minimal interaction and typically without elevated privileges. While beneficial for legitimate developers, this user-friendly design presents a significant opportunity for threat actors to facilitate malware delivery. This brief, based on CrowdStrike's analysis, outlines the inner workings of ClickOnce, detailing how applications are published and deployed. Attackers are leveraging these mechanisms to package and distribute malicious payloads, exploiting the trust associated with application deployment processes and the system's inherent design to bypass traditional installation hurdles. The simplicity of execution—often a single click—makes it an attractive vector for initial access and execution, posing a growing threat to Windows users.

## Attack Chain

1.  **Application Publishing**: A developer (or threat actor) uses tools like Visual Studio to "publish" a ClickOnce application, configuring deployment parameters such as update locations and offline availability.
2.  **Resource Generation**: The publishing process generates ClickOnce-specific resources, including the `.application` deployment manifest (an XML file) and other related manifests and application files.
3.  **Hosting Deployment Files**: The generated ClickOnce deployment files (e.g., the `.application` file) are hosted on a web server or network file share, making them accessible for distribution.
4.  **User Initiates Deployment**: A user is tricked into clicking an "Install" button on a webpage or directly executing a `.application` file, initiating the ClickOnce deployment process.
5.  **OS Security Prompt**: If the application's publisher cannot be verified (e.g., it's unsigned or from an untrusted source), the operating system displays a security prompt to the user seeking confirmation for deployment.
6.  **Deployment Wizard Execution**: Upon user confirmation, a standardized ClickOnce deployment wizard guides the user through the installation process, informing them of each step.
7.  **Application Execution/Installation**: The ClickOnce application is executed and/or installed onto the system. Crucially, this often happens without requiring administrative privileges, bypassing UAC prompts.
8.  **Self-Updating Functionality**: The deployed application gains self-updating capabilities, allowing it to fetch and install new versions or additional malicious components from the deployment server without further user interaction.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier for adversaries to distribute and execute malware. If successful, this can lead to widespread compromise across targeted organizations and individual users, as the simplified installation process bypasses common security controls and user privilege requirements. While this brief (Part 1) focuses on the mechanism rather than specific campaigns, the implied impact is broad malware dissemination, data exfiltration, system compromise, and the establishment of persistent access. The ease with which applications can be deployed through a single click increases the likelihood of successful social engineering attacks.

## Recommendation

*   Enable `process_creation` logging (e.g., via Sysmon) on all Windows endpoints to monitor for executions originating from ClickOnce deployment paths or unusual ClickOnce application activities.
*   Monitor `file_event` logs for `.application` files or related ClickOnce manifests being downloaded and executed outside of expected and trusted enterprise software distribution channels.
*   Educate users about the risks associated with installing software from unverified sources, even when prompted by legitimate-looking system dialogs, especially concerning ClickOnce applications.
