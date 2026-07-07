---
title: Abuse of Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-07-abuse-clickonce-tech
description: Microsoft's ClickOnce technology, designed for simplified application deployment, presents an attractive vector for threat actors to distribute malware due to its minimal user interaction and lack of administrative privilege requirements, according to new research by CrowdStrike.
date: "2026-07-04T08:38:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - microsoft
  - deployment-technology
  - malware-delivery
  - potential-abuse
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce Technology
  - Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Microsoft's ClickOnce technology, a deployment mechanism intended to simplify application distribution and updates for developers and users, is identified as a potential vector for malware delivery by threat actors. This research, published by CrowdStrike on July 4, 2026, focuses on the inner workings of ClickOnce, detailing how applications are published and installed. While beneficial for legitimate software deployment, ClickOnce's design allows applications to be run and installed with minimal user interaction and without requiring administrative privileges, making it an appealing target for adversaries seeking an easy way to spread malicious software. The brief explains the technology's mechanics, setting the stage for subsequent analysis of its weaponization by threat actors and potential detection strategies.

## Attack Chain

1.  Attacker creates a malicious application and packages it using Microsoft's ClickOnce technology.
2.  The malicious ClickOnce application package, including the `.application` manifest file, is hosted on an attacker-controlled web server.
3.  The attacker socially engineers a user (e.g., via phishing) to visit a malicious webpage or click a link that points to the hosted ClickOnce deployment file.
4.  Upon clicking an "Install" button or link, the user's system downloads the `.application` deployment manifest.
5.  The user executes the downloaded `.application` file, initiating the ClickOnce deployment process.
6.  The operating system displays a user confirmation prompt, which may lack publisher verification, leading the user to proceed with the installation.
7.  Upon user confirmation, the malicious ClickOnce application is deployed and executed on the system without requiring elevated administrative privileges.
8.  The malicious application proceeds to establish persistence, exfiltrate data, or perform other objectives defined by the attacker.

## Impact

If successfully abused, ClickOnce's ability to deploy applications with minimal user interaction and without administrative privileges can lead to widespread malware infections, credential theft, data exfiltration, or further system compromise across targeted organizations. Its self-updating feature also means a persistently compromised application could serve as a continuous backdoor for attackers, allowing for long-term access and control. This part of the research does not detail specific victim counts or industry targets but highlights a significant attack surface for any organization utilizing Windows environments, as ClickOnce is a built-in Microsoft deployment technology.

## Recommendation

*   Enable comprehensive logging for process creation events on all Windows endpoints, focusing on processes related to application deployment and execution.
*   Review Microsoft's documentation and security best practices for ClickOnce deployments to understand legitimate application behavior and artifacts.
*   Ensure endpoint detection and response (EDR) solutions are configured to monitor execution of applications launched via deployment technologies like ClickOnce (e.g., those executed by `dfsvc.exe` or directly from `.application` files).
*   Monitor network connections initiated by newly deployed or unfamiliar applications for suspicious outbound communication to detect potential C2 activity.
