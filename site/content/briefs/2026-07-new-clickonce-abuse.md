---
title: 'New Abuse of ClickOnce Technology: Part 1 Analysis'
slug: 2026-07-new-clickonce-abuse
description: CrowdStrike details how threat actors can abuse Microsoft's ClickOnce technology, a user-friendly deployment mechanism, to distribute malware and bypass traditional installation hurdles without requiring administrative privileges, posing a significant risk to user endpoints.
date: "2026-07-07T08:36:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - application-deployment
  - windows
  - malware-delivery
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
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
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

CrowdStrike recently published "New Abuse of the ClickOnce Technology, Part 1", detailing how Microsoft's ClickOnce application deployment technology, designed for user-friendly software distribution without administrative privileges, presents a "double-edged sword" that can be abused by threat actors. Published on 2026-07-07, this first part of a two-part series explains the internal workings of ClickOnce, from application publication to user installation. While Part 1 focuses on the technology itself rather than specific campaigns or actors, it highlights the inherent risk that ClickOnce's minimal user interaction and lack of privilege requirement can simplify malware spread. For defenders, understanding these mechanics is crucial to anticipate and counter future weaponization methods, which will be detailed in Part 2.

## Attack Chain

1.  **Preparation**: A threat actor packages their malicious application using ClickOnce technology, likely via Visual Studio, configuring it for deployment via a website or network share. This process generates ClickOnce deployment files, including the `.application` manifest.
2.  **Delivery**: The actor shares a link to the malicious ClickOnce deployment file with a victim, potentially through a phishing email, compromised legitimate website, or social engineering.
3.  **User Execution**: The victim clicks the provided link, which initiates the download of the `.application` deployment manifest onto their system.
4.  **Deployment Wizard**: The operating system or .NET runtime presents a ClickOnce deployment wizard to the user, typically asking for confirmation, especially if the publisher's signature cannot be verified.
5.  **Application Execution/Installation**: Upon user confirmation, the malicious ClickOnce application is deployed and optionally installed onto the system. This process occurs without requiring administrative privileges.
6.  **Malicious Payload Execution**: The deployed ClickOnce application executes its harmful payload, which could include data exfiltration, ransomware deployment, or further download and execution of additional malware.
7.  **Persistence/Updates**: If configured, the malicious ClickOnce application establishes persistence, and can automatically fetch and install updates from an attacker-controlled deployment server, maintaining its presence and evolving its capabilities.

## Impact

While Part 1 does not detail specific victim counts or observed attacks, it emphasizes that the user-friendly nature of ClickOnce, requiring minimal interaction and no elevated privileges, makes it an attractive vector for threat actors. If abused, the technology could facilitate widespread malware distribution across various sectors, leading to compromised systems, data exfiltration, and potentially system-wide damage, similar to other user-executed malware. The ease of deployment means even non-technical users could inadvertently install sophisticated threats, making organizations vulnerable to rapid and silent infiltration.

## Recommendation

1.  Implement endpoint detection and response (EDR) solutions to monitor for the creation and execution of `ClickOnce deployment files` (e.g., `.application` manifests) originating from untrusted or unexpected sources.
2.  Educate users on the risks associated with `ClickOnce technology` and advise vigilance against unsolicited prompts to install applications, especially those from unverified publishers.
3.  For critical systems, consider policy enforcement or application whitelisting to control the execution of applications delivered via `ClickOnce technology`.
