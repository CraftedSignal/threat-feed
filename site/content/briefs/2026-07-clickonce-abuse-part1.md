---
title: New Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology, a deployment mechanism designed for easy application distribution, to spread malware by leveraging its user-friendly installation and update features that require minimal interaction and no elevated privileges.
date: "2026-07-04T09:07:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - malware-delivery
  - application-deployment
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - ClickOnce applications
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has highlighted a growing trend of threat actors exploiting Microsoft's ClickOnce technology for malware distribution. ClickOnce, an integral deployment mechanism within the Windows ecosystem, was designed to simplify software installation and updates for users, notably requiring minimal interaction and no administrative privileges. However, its streamlined nature is now being weaponized, providing an effective channel for adversaries to deploy malicious applications. This analysis, the first in a two-part series, delves into the underlying mechanics of ClickOnce, detailing how applications are published and deployed. Understanding these internals is crucial for defenders, as threat actors leverage these legitimate processes to bypass traditional security controls and spread malware efficiently, making it imperative for organizations to anticipate and detect such abuses.

## Attack Chain

1.  **Application Publishing**: A developer (or attacker) uses Visual Studio to publish an application using ClickOnce, defining deployment parameters such as the distribution medium (website, network share), update location, and offline availability.
2.  **Manifest Generation**: The publishing process generates key ClickOnce resources, including `.application` files (ClickOnce deployment manifests) and other manifests that define the application's components and update rules.
3.  **Deployment File Hosting**: The generated ClickOnce deployment files are hosted on a distribution medium, such as a website, where users can access them, often via an "Install" button.
4.  **User Initiated Download**: A user, prompted by a website or other lure, clicks to deploy the application, triggering the download of the ClickOnce deployment file.
5.  **OS Confirmation (Optional)**: If the application's publisher signature cannot be verified, the operating system may present a user confirmation prompt before proceeding with deployment.
6.  **Application Deployment/Installation**: Upon user confirmation, the system uses a standardized procedure to deploy the application. This can involve executing it directly or installing it onto the system, often accompanied by a wizard.
7.  **Automatic Updates**: Once deployed, the ClickOnce application can automatically fetch and install updates from the configured deployment server, potentially allowing attackers to maintain persistence or update malware.

## Impact

The abuse of ClickOnce technology allows threat actors to easily distribute malware, potentially bypassing security measures that rely on traditional installation methods or requiring elevated privileges. Since ClickOnce applications can be deployed with minimal user interaction and without administrator rights, successful attacks can lead to widespread infection within an organization. This means that users could inadvertently install malicious software, leading to data exfiltration, system compromise, or the deployment of ransomware, significantly increasing the attack surface and the risk of successful cyberattacks across various sectors.

## Recommendation

*   Enable comprehensive `process_creation` logging across all Windows endpoints to capture ClickOnce deployment activities.
*   Monitor `file_event` logs for `.application` and manifest file creations or modifications to identify suspicious ClickOnce package deployments.
*   Prepare to deploy detection strategies and specific Sigma rules targeting ClickOnce abuse, which will be detailed in Part 2 of the CrowdStrike series, to your SIEM.
*   Educate users about the risks associated with installing applications from untrusted sources, even those seemingly legitimate via simplified deployment methods.
