---
title: Threat Actors Abusing Microsoft's ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse
description: Threat actors are exploiting the legitimate functionality of Microsoft's ClickOnce deployment technology to simplify malware distribution, enabling the execution and optional installation of malicious applications on user endpoints with minimal interaction and often without requiring administrative privileges.
date: "2026-07-06T06:40:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - deployment
  - malware-distribution
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: ClickOnce enables developers to package and distribute applications that users can run, install, and automatically update with minimal interaction... it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an ''Install'' button.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The 'deployment' refers to the execution of a ClickOnce application and its potential installation onto the system afterward
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has documented a new abuse vector leveraging Microsoft's ClickOnce technology, a deployment framework designed to simplify the distribution and updating of applications. While intended for legitimate developers, its features — such as minimal user interaction for installation and the ability to operate without administrative privileges — present a significant opportunity for threat actors. This initial analysis, published in June 2026, details the inner workings of ClickOnce application deployment, setting the stage for understanding its weaponization. By packaging malware as a ClickOnce application, adversaries can bypass traditional installation hurdles, leveraging a trusted platform to gain initial access and establish execution on victim systems, making it a critical concern for defenders as it transforms a legitimate software delivery mechanism into a potent malware vector.

## Attack Chain

1.  A developer (or threat actor) uses Visual Studio to "publish" a ClickOnce application, configuring deployment parameters like the distribution medium and update location.
2.  The publishing process generates key ClickOnce resources, including the `.application` file (the ClickOnce deployment manifest) and associated application files.
3.  These generated deployment files are then hosted on a distribution medium, such as a website or network file share, making them accessible to users.
4.  A user interacts with the deployment by clicking an "Install" button on a webpage or directly executing the `.application` file.
5.  The operating system prompts the user for confirmation if the publisher's digital signature cannot be verified, indicating a potential trust issue.
6.  Upon user confirmation, the ClickOnce deployment initiates, executing the application and, depending on configuration, optionally installing it onto the system.
7.  The application runs on the user's system, often without requiring elevated administrative privileges due to ClickOnce's design.
8.  In an abuse scenario, this successfully deployed application can then perform malicious activities, achieving execution or persistence for malware.

## Impact

The abuse of ClickOnce technology allows threat actors to distribute malware with reduced friction, potentially leading to widespread infections across targeted sectors. Its design, which enables installation without elevated privileges and simplifies updates, means that successful deployment can establish persistent access or quickly spread updated malware versions. Organizations in any sector that rely on Windows environments and where users may encounter external application installation prompts are at risk. If an attack succeeds, it can result in data exfiltration, system compromise, ransomware deployment, or further network lateral movement, leveraging a seemingly legitimate channel.

## Recommendation

*   Enable comprehensive process creation logging (e.g., via Sysmon) to monitor for suspicious processes originating from ClickOnce installation directories.
*   Monitor for process execution of `dfsvc.exe` and `rundll32.exe` associated with ClickOnce deployments, specifically looking for unusual parent processes or command-line arguments.
*   Implement application whitelisting policies to restrict the execution of unsigned or untrusted ClickOnce applications, specifically those not originating from approved sources.
*   Educate users about the risks of installing applications from untrusted sources, even those appearing to use common Windows deployment mechanisms like ClickOnce.
