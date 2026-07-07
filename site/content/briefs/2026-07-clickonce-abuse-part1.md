---
title: Abuse of Microsoft ClickOnce Technology for Application Deployment (Part 1)
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology, a legitimate application deployment mechanism that allows low-privilege, user-friendly installation and updates, to easily distribute malware by leveraging its minimal user interaction and lack of administrative privilege requirements.
date: "2026-07-06T08:05:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - application-deployment
  - malware-delivery
  - execution
  - windows
  - high_confidence_source
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Microsoft's ClickOnce technology, designed for streamlined application deployment, is being increasingly abused by threat actors for malware distribution. This technology allows developers to package and distribute applications that users can run, install, and automatically update with minimal interaction and without requiring administrative privileges. While intended to simplify software deployment, these very features make ClickOnce an attractive vector for malicious actors. CrowdStrike's research, detailed in this first part of a two-part series, examines the fundamental internals of ClickOnce deployment, from application publishing to installation on the user endpoint. Understanding this legitimate deployment journey is critical for defenders to anticipate and counter the weaponization methods that threat actors will leverage, enabling the spread of malicious applications by simply enticing a user to "click once" to deploy. This foundational knowledge is essential before exploring specific abuse cases.

## Attack Chain

This section describes the legitimate ClickOnce deployment journey which is abused by threat actors.

1.  **Application Publishing:** A developer (or threat actor) uses tools like Visual Studio to package an application into ClickOnce-compatible resources, generating key files such as the `.application` deployment manifest.
2.  **Deployment File Hosting:** The generated ClickOnce deployment files (e.g., `.application` files) are hosted on a distribution medium, such as a website or a network file share, making them accessible to users.
3.  **User Deployment Request:** A user is enticed to initiate the deployment, typically by clicking an "Install" button on a webpage or directly accessing the `.application` file.
4.  **ClickOnce File Download:** The user's action triggers the download of the `.application` deployment manifest file to their system.
5.  **Operating System Confirmation:** The operating system intercepts the deployment request and presents a confirmation dialog to the user, particularly if the publisher's signature cannot be verified.
6.  **Application Deployment/Installation:** Upon user confirmation, the ClickOnce application is deployed and optionally installed onto the system, often without requiring elevated privileges.
7.  **Application Execution:** The deployed application is then executed, allowing the legitimate software (or malicious payload in an abuse scenario) to run on the user's machine.

## Impact

The abuse of ClickOnce technology allows threat actors an easy method to distribute and execute malware on user endpoints with minimal friction. The core impact stems from ClickOnce's design to require minimal user interaction and no administrative privileges for installation, significantly lowering the bar for attackers to achieve initial access and execution. If an attack succeeds, malicious applications can be deployed covertly, leading to a wide range of consequences including data exfiltration, system compromise, and further propagation of malware, potentially affecting any Windows user tricked into deploying a malicious ClickOnce application.

## Recommendation

*   Educate users about the risks associated with deploying applications from unverified publishers, emphasizing the confirmation dialog highlighted in the brief.
*   Implement application whitelisting policies to prevent the execution of unsigned or unauthorized `.application` files, addressing the "publisher’s signature cannot be verified" scenario discussed.
*   Enable comprehensive logging for application deployment events within Windows environments, focusing on the execution of `.application` files or related ClickOnce components, to monitor for unusual or unverified deployment sources mentioned in the brief.
