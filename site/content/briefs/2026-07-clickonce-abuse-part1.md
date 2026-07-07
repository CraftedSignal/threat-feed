---
title: 'New Abuse of ClickOnce Technology: Understanding the Attack Surface'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology, a legitimate Windows application deployment mechanism, to distribute malware by leveraging its streamlined installation process, which requires minimal user interaction and no elevated privileges, posing a significant defense evasion and initial access risk.
date: "2026-07-07T07:20:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - application-deployment
  - windows
  - microsoft
  - defense-evasion
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
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1072
    technique_name: Application Deployment Software
    evidence: The 'deployment' refers to the execution of a ClickOnce application and its potential installation onto the system afterward.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Self-updating functionality allowing applications to automatically fetch and install updates from the deployment server.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1072
    technique_name: Application Deployment Software
    evidence: No elevated privileges required to perform the deployment.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike recently detailed the inner workings and potential abuse of Microsoft's ClickOnce technology, a legitimate application deployment solution designed to simplify software distribution and updates on Windows. While intended for developers to publish applications with minimal user interaction and without requiring administrative privileges, threat actors are increasingly weaponizing ClickOnce for malware delivery. This two-part series, with the first part published on June 18, 2026, explains how the technology functions, from application publishing via Visual Studio to its installation on the user's endpoint. Its inherent design, which allows for single-click deployment and automatic updates, provides an attractive mechanism for adversaries to bypass traditional security controls and deploy malicious payloads with ease. This detailed exposition serves as a foundational understanding for defenders to anticipate and mitigate future ClickOnce-based attacks, as the second part of the series will focus on specific weaponization methods and detection strategies.

## Attack Chain

1.  An attacker publishes a malicious application using Microsoft Visual Studio's ClickOnce publishing wizard, generating necessary deployment files such as the `.application` manifest.
2.  The attacker hosts the malicious ClickOnce deployment files (e.g., `.application`, `.manifest`, and associated application files) on a controlled web server or network share.
3.  The victim is lured to click a link pointing to the attacker-controlled `.application` file, typically through social engineering tactics like phishing emails or compromised websites.
4.  Upon clicking, the Windows operating system downloads the `.application` deployment manifest and initiates the ClickOnce deployment process.
5.  If the publisher's signature is unverified, the OS presents a user confirmation prompt; if approved, the ClickOnce deployment wizard proceeds to deploy the application.
6.  The malicious ClickOnce application is executed directly or optionally installed onto the victim's system, crucially without requiring administrative privileges for this stage.
7.  The deployed malicious application proceeds to execute its payload, which could involve downloading additional malware, establishing persistence via its self-updating mechanism, or initiating data exfiltration.

## Impact

The abuse of ClickOnce technology allows threat actors to deliver malware with minimal user interaction, bypassing traditional installation methods that often require elevated privileges or multiple consent steps. If successful, this can lead to the widespread deployment of various malicious payloads, including ransomware, information stealers, or backdoors, across targeted organizations. The technology's self-updating feature can also be leveraged for persistent access and continuous malware evolution on compromised systems, making detection and remediation more challenging. While specific victim counts or sectors are not detailed in this part of the analysis, the ease of deployment makes it a versatile vector for broad campaigns.

## Recommendation

*   Enable comprehensive logging for `.application` file downloads and executions to capture artifacts mentioned in the Attack Chain.
*   Implement application whitelisting and software restriction policies to prevent the execution of unsigned or untrusted ClickOnce applications.
*   Educate users on the risks associated with executing applications, particularly `.application` files, from untrusted or unexpected sources, even when prompts appear minimal.
