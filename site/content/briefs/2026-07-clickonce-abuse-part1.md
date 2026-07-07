---
title: Threat Actors Abusing Microsoft ClickOnce Technology for Malware Distribution (Part 1)
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly abusing Microsoft's ClickOnce application deployment technology, which allows for minimal-interaction, non-administrative installation of applications, to easily distribute malware onto user endpoints, leveraging its user-friendly process to bypass traditional security hurdles.
date: "2026-07-07T18:31:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-distribution
  - application-deployment
  - windows
  - living-off-the-land
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
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Minimal user interaction to deploy an application, hence the name “ClickOnce,” highlighting that the deployment can be as simple as clicking a webpage “Install” button in certain deployment scenarios
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike reports on a new trend where threat actors are actively leveraging Microsoft's ClickOnce technology to distribute malware. This deployment mechanism, designed for simplified application installation and updates without requiring administrative privileges, presents a double-edged sword: while beneficial for legitimate developers, it offers an attractive vector for malicious campaigns. This first part of a two-series brief details the inner workings of ClickOnce, from application publishing via Visual Studio to its seamless deployment on user endpoints. Understanding these technical foundations is crucial for defenders to anticipate and build robust detection strategies against the exploitation methods that will be elaborated in subsequent analyses. The user-friendly nature, requiring only a single click for deployment, greatly lowers the bar for threat actors to infect systems.

## Attack Chain

1.  A developer (or adversary posing as one) publishes a C# or Visual Basic application using Visual Studio's built-in "publish" wizard.
2.  The wizard is configured for deployment parameters, such as the hosting medium (website, network share) and update locations.
3.  The publishing process generates a directory of files, including the `.application` file (ClickOnce deployment manifest) and other related resources.
4.  The `.application` file and associated binaries are hosted on a remote server, such as a website controlled by the threat actor.
5.  A user is enticed to interact with an "Install" button or link, triggering the download of the `.application` file onto their system.
6.  The operating system presents a confirmation prompt to the user, particularly if the publisher's signature cannot be verified.
7.  Upon user confirmation, the ClickOnce Deployment Support Service (`dfsvc.exe`) initiates a standardized deployment procedure, executing and optionally installing the application without requiring administrative privileges.
8.  The deployed malicious application can then leverage ClickOnce's self-updating functionality to fetch additional malicious components or maintain persistence.

## Impact

ClickOnce's inherent design for minimal user interaction and non-administrative deployment makes it a highly effective vehicle for malware distribution. If exploited, it allows threat actors to bypass security controls traditionally associated with software installation, enabling rapid and widespread deployment of malicious applications. The ease of use for both legitimate developers and adversaries means that compromised applications can propagate quickly, leading to data theft, system compromise, or ransomware infections across targeted organizations and individual users. This method significantly lowers the barrier for entry for less sophisticated attackers, while also providing a stealthy vector for advanced persistent threats.

## Recommendation

*   Enable comprehensive logging for `process_creation` events, especially for `dfsvc.exe` and its child processes, to monitor ClickOnce application deployments.
*   Configure `file_event` logging to track the creation, modification, and execution of `.application` files downloaded from untrusted sources.
*   Implement `network_connection` logging to identify outbound connections initiated by processes related to ClickOnce (`dfsvc.exe` or deployed applications) to unfamiliar or suspicious domains.
*   Familiarize security operations teams with the legitimate ClickOnce deployment process, as detailed in the "Attack Chain" section of this brief, to better distinguish malicious activity from benign operations.
