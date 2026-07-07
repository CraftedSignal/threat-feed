---
title: New Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse
description: CrowdStrike details how threat actors can abuse Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to distribute and execute malware on Windows systems with minimal user interaction and without requiring administrative privileges, presenting a significant new vector for initial access and execution.
date: "2026-07-07T13:04:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - malware-distribution
  - initial-access
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
    evidence: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor's website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file...
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment... uses a standardized procedure to deploy the app alongside a dedicated wizard to keep the user informed of every step.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has published an analysis highlighting the potential for abuse of Microsoft's ClickOnce technology by threat actors. ClickOnce, designed to simplify application distribution and updates for developers and users, allows applications to be deployed and run with a "single click" and without requiring administrative privileges. This user-friendly deployment process, while beneficial for legitimate software, creates an attractive vector for threat actors to spread malware. The brief, published on June 18, 2026, focuses on the inner workings of ClickOnce, detailing how applications are published and deployed, and how threat actors can leverage these mechanisms for malicious purposes, setting the stage for more in-depth discussion on weaponization and detection in a subsequent report. This represents a critical concern for defenders as it enables easy execution of malicious payloads, bypassing traditional privilege escalation requirements.

## Attack Chain

1.  **Attacker Publishes Malicious ClickOnce Application**: A threat actor leverages the Visual Studio publishing wizard to package their malware payload as a ClickOnce application, configuring deployment parameters such as update locations and installation behavior.
2.  **Attacker Hosts Deployment Files**: The compiled ClickOnce deployment files, including the `.application` manifest, are hosted on an attacker-controlled web server or network share.
3.  **Attacker Lures Victim**: The threat actor employs social engineering techniques (e.g., phishing emails, malicious advertisements, compromised websites) to entice a user into clicking a link or button associated with the malicious ClickOnce application.
4.  **Victim Initiates Deployment**: The victim clicks the malicious link or button, which triggers the download of the `.application` deployment file, initiating the ClickOnce deployment process.
5.  **User Confirmation Prompt**: The operating system presents a security prompt, asking the user for confirmation to deploy the application, particularly if the publisher's signature cannot be verified.
6.  **Malicious ClickOnce Application Execution**: Upon user confirmation, the ClickOnce application is deployed and executed on the victim's Windows system without requiring elevated administrative privileges.
7.  **Malware Payload Execution**: The malicious ClickOnce application executes its embedded payload, which can perform actions such as establishing persistence, exfiltrating data, or downloading and installing additional malware.

## Impact

The abuse of ClickOnce technology allows threat actors to easily distribute and execute malware on Windows systems, bypassing common security barriers such as administrative privilege requirements for installation. If successful, this can lead to initial compromise of endpoints, subsequent network lateral movement, data exfiltration, or the deployment of ransomware. While this specific brief (Part 1) does not detail observed campaigns or victim numbers, it highlights a significant "easy way of spreading malware" that poses a high risk across all sectors, as it leverages a legitimate, built-in Windows deployment mechanism.

## Recommendation

*   Educate users about the risks of deploying applications from untrusted sources, particularly when prompted to confirm publisher details during ClickOnce installations.
*   Implement application control solutions to restrict execution of unsigned ClickOnce applications or those from unauthorized publishers.
*   Monitor process creation events for `rundll32.exe` calls to `dfshim.dll,ShOpenVerbApplication` from unusual parent processes or with suspicious command-line arguments.
*   Enable comprehensive logging for ClickOnce deployment activities, including application installation and update events, to identify potentially malicious activity.
