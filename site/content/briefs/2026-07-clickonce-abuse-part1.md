---
title: 'New Abuse of ClickOnce Technology: Part 1 - Inner Workings'
slug: 2026-07-clickonce-abuse-part1
description: Microsoft's ClickOnce technology, designed for simplified application deployment and updates with minimal user interaction and no administrative privileges, is susceptible to abuse by threat actors who can leverage its features for malware distribution, execution, and persistence on Windows systems, as detailed in this first part of a series covering its internal mechanisms.
date: "2026-07-07T15:50:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - microsoft
  - application-deployment
  - abuse-of-feature
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
    technique_id: T1204
    technique_name: User Execution
    evidence: Developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has published the first part of a two-part series detailing the internal workings and potential for abuse of Microsoft's ClickOnce technology. Designed to simplify application deployment and updates for developers and users, ClickOnce allows applications to be distributed and installed with minimal user interaction and without requiring administrative privileges. While beneficial for legitimate software distribution, these features — including self-contained packaging and automatic updates — present a significant opportunity for threat actors to easily spread malware, establish execution, and maintain persistence on Windows systems. This initial part of the research, published on June 18, 2026, focuses on describing the legitimate publishing and deployment process, setting the foundation for understanding how adversaries can weaponize this technology.

## Attack Chain

This section outlines the legitimate ClickOnce application deployment process, which threat actors can subvert for malicious purposes.

1.  **Application Publishing:** A developer uses Visual Studio to "publish" their C# or Visual Basic application, configuring deployment parameters like the distribution medium (web, network share) and update location.
2.  **Manifest Generation:** Visual Studio generates a directory containing key files, including the `.application` (ClickOnce deployment manifest) file, which is an XML-based file holding application information.
3.  **Distribution:** The developer hosts the generated ClickOnce deployment files (e.g., the `.application` file) on a distribution medium, such as a website.
4.  **User Interaction:** A user visits the website and clicks an "Install" button or a direct link, which triggers the download of the `.application` file.
5.  **Initiation of Deployment:** The operating system detects the ClickOnce deployment file and initiates its processing.
6.  **User Confirmation:** If the application's publisher signature cannot be verified, the OS presents a dialog box asking the user for confirmation to proceed with the installation.
7.  **Application Deployment:** Upon user confirmation, a standardized procedure deploys the application and presents a dedicated wizard to the user.
8.  **Execution and Optional Installation:** The application runs and can optionally be installed onto the system. If configured, it can automatically fetch and install updates from the deployment server.

## Impact

The abuse of ClickOnce technology can lead to significant compromise. Its design allows for the deployment of applications with minimal user interaction and without requiring elevated privileges, making it an attractive vector for initial access and execution. If exploited maliciously, an attacker could distribute malware disguised as legitimate software, leveraging ClickOnce's self-contained packaging to evade traditional detection methods. Furthermore, the self-updating functionality could be used to maintain persistence and deliver updated malicious payloads, bypassing security controls that monitor for new installations. While this specific brief does not detail observed attacks or victim counts, the inherent capabilities of ClickOnce, when weaponized, pose a severe risk for arbitrary code execution and system compromise across Windows environments.

## Recommendation

*   Enable comprehensive logging for `process_creation` events on Windows endpoints, specifically monitoring for executions related to ClickOnce deployment files (`.application`).
*   Monitor `network_connection` logs for outbound connections initiated by processes associated with ClickOnce applications, especially to untrusted or newly observed domains.
*   Implement strong application whitelisting policies to prevent the execution of unsigned or untrusted ClickOnce applications.
*   Educate users about the risks of installing software from untrusted sources, even if it appears to be a "one-click" installation.
